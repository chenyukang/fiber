use std::collections::HashMap;

use ckb_hash::blake2b_256;
use ckb_jsonrpc_types::{Status, TxStatus};
use ckb_types::packed::OutPoint;
use ractor::{
    async_trait as rasync_trait, call_t,
    concurrency::{timeout, Duration},
    Actor, ActorCell, ActorProcessingErr, ActorRef, ActorRuntime,
};
use secp256k1::Message;
use serde::Serialize;
use tentacle::{
    async_trait as tasync_trait,
    builder::MetaBuilder,
    bytes::Bytes,
    context::{ProtocolContext, ProtocolContextMutRef, SessionContext},
    multiaddr::Multiaddr,
    secio::PeerId,
    service::{ProtocolHandle, ProtocolMeta, Service, ServiceAsyncControl},
    traits::ServiceProtocol,
    SessionId,
};
use tokio::sync::oneshot;
use tracing::{debug, error, info, warn};

use crate::{
    ckb::{CkbChainMessage, GetBlockTimestampRequest, TraceTxRequest, TraceTxResponse},
    fiber::{network::DEFAULT_CHAIN_ACTOR_TIMEOUT, types::secp256k1_instance},
    unwrap_or_return, Error,
};

use super::{
    network::{get_chain_hash, GossipMessageWithPeerId, GOSSIP_PROTOCOL_ID},
    types::{
        BroadcastMessage, BroadcastMessageID, BroadcastMessageQuery, BroadcastMessageQueryFlags,
        BroadcastMessageWithTimestamp, BroadcastMessagesFilter, ChannelAnnouncement, ChannelUpdate,
        Cursor, GossipMessage, NodeAnnouncement, Pubkey,
    },
};

pub(crate) trait GossipMessageStore {
    fn get_broadcast_messages(
        &self,
        after_cursor: &Cursor,
        count: Option<u16>,
    ) -> Vec<BroadcastMessageWithTimestamp>;

    fn query_broadcast_messages<I: IntoIterator<Item = BroadcastMessageQuery>>(
        &self,
        queries: I,
    ) -> (Vec<BroadcastMessageWithTimestamp>, Vec<u16>) {
        let mut results = Vec::new();
        let mut missing = Vec::new();
        for (index, query) in queries.into_iter().enumerate() {
            if let Some(message) = self.query_broadcast_message(query) {
                results.push(message);
            } else {
                missing.push(index as u16);
            }
        }
        (results, missing)
    }

    fn query_broadcast_message(
        &self,
        query: BroadcastMessageQuery,
    ) -> Option<BroadcastMessageWithTimestamp> {
        match query.flags {
            BroadcastMessageQueryFlags::ChannelAnnouncement => self
                .get_latest_channel_announcement(&query.channel_outpoint)
                .map(|(timestamp, channel_announcement)| {
                    BroadcastMessageWithTimestamp::ChannelAnnouncement(
                        timestamp,
                        channel_announcement,
                    )
                }),
            BroadcastMessageQueryFlags::ChannelUpdateNode1 => self
                .get_latest_channel_update(&query.channel_outpoint, true)
                .map(|channel_update| BroadcastMessageWithTimestamp::ChannelUpdate(channel_update)),
            BroadcastMessageQueryFlags::ChannelUpdateNode2 => self
                .get_latest_channel_update(&query.channel_outpoint, false)
                .map(|channel_update| BroadcastMessageWithTimestamp::ChannelUpdate(channel_update)),

            BroadcastMessageQueryFlags::NodeAnnouncementNode1
            | BroadcastMessageQueryFlags::NodeAnnouncementNode2 => self
                .get_latest_channel_announcement(&query.channel_outpoint)
                .and_then(|(_, channel_announcement)| {
                    let node = if query.flags == BroadcastMessageQueryFlags::NodeAnnouncementNode1 {
                        &channel_announcement.node1_id
                    } else {
                        &channel_announcement.node2_id
                    };
                    self.get_lastest_node_announcement(node)
                        .map(|m| BroadcastMessageWithTimestamp::NodeAnnouncement(m))
                }),
        }
    }

    fn save_broadcast_message(&self, message: BroadcastMessageWithTimestamp);

    fn get_broadcast_message_with_cursor(
        &self,
        cursor: &Cursor,
    ) -> Option<BroadcastMessageWithTimestamp>;

    fn get_latest_channel_announcement_timestamp(&self, outpoint: &OutPoint) -> Option<u64>;

    fn get_latest_channel_update_timestamp(
        &self,
        outpoint: &OutPoint,
        is_node1: bool,
    ) -> Option<u64>;

    fn get_lastest_node_announcement_timestamp(&self, pk: &Pubkey) -> Option<u64>;

    fn get_latest_channel_announcement(
        &self,
        outpoint: &OutPoint,
    ) -> Option<(u64, ChannelAnnouncement)> {
        self.get_latest_channel_announcement_timestamp(outpoint)
            .and_then(|timestamp| {
                 self.get_broadcast_message_with_cursor(&Cursor::new(
                    timestamp,
                    BroadcastMessageID::ChannelAnnouncement(outpoint.clone()),
                )).and_then(|message| match message {
                    BroadcastMessageWithTimestamp::ChannelAnnouncement(
                        _,
                        channel_announcement,
                    ) => Some((timestamp, channel_announcement)),
                    _ => panic!(
                        "get_latest_channel_announcement returned non-ChannelAnnouncement message from db: channel outpoint {:?}, message {:?}", outpoint, message
                    ),
                })
            })
    }

    fn get_latest_channel_update(
        &self,
        outpoint: &OutPoint,
        is_node1: bool,
    ) -> Option<ChannelUpdate> {
        self.get_latest_channel_update_timestamp(outpoint, is_node1)
            .and_then(|timestamp| {
                 self.get_broadcast_message_with_cursor(&Cursor::new(
                    timestamp,
                    BroadcastMessageID::ChannelUpdate(outpoint.clone()),
                )).and_then(|message| match message {
                    BroadcastMessageWithTimestamp::ChannelUpdate(channel_update) => Some(channel_update),
                    _ => panic!("get_latest_channel_update returned non-ChannelUpdate message from db: channel outpoint {:?}, is_node1 {:?}, message {:?}", outpoint, is_node1, message),
                })
            })
    }

    fn get_lastest_node_announcement(&self, pk: &Pubkey) -> Option<NodeAnnouncement> {
        self.get_lastest_node_announcement_timestamp(pk).and_then(|timestamp| {
            self.get_broadcast_message_with_cursor(&Cursor::new(
                timestamp,
                BroadcastMessageID::NodeAnnouncement(pk.clone()),
            )).and_then(|message|
                    match message {
                    BroadcastMessageWithTimestamp::NodeAnnouncement(node_announcement) => Some(node_announcement),
                    _ => panic!("get_lastest_node_announcement returned non-NodeAnnouncement message from db: pk {:?}, message {:?}", pk, message),
                    }
                )
            }
        )
    }
}

pub(crate) enum GossipActorMessage {
    /// Network events to be processed by this actor.
    PeerConnected(PeerId, Pubkey, SessionContext),
    PeerDisconnected(PeerId, SessionContext),

    // Command to broadcast BroadcastMessage to the network
    BroadcastMessage(BroadcastMessageWithTimestamp),
    // Received GossipMessage from a peer
    GossipMessage(GossipMessageWithPeerId),
}

pub(crate) struct GossipActor<S> {
    _phantom: std::marker::PhantomData<S>,
}

impl<S> GossipActor<S> {
    fn new() -> Self {
        Self {
            _phantom: Default::default(),
        }
    }
}

pub(crate) struct GossipActorState<S> {
    store: S,
    chain_actor: ActorRef<CkbChainMessage>,
    control: ServiceAsyncControl,
    peer_session_map: HashMap<PeerId, SessionId>,
    peer_pubkey_map: HashMap<PeerId, Pubkey>,
    peer_filter_map: HashMap<PeerId, Cursor>,
}

pub(crate) struct GossipProtocolHandle {
    actor: ActorRef<GossipActorMessage>,
    sender: Option<oneshot::Sender<ServiceAsyncControl>>,
}

async fn verify_and_save_broadcast_message<S: GossipMessageStore>(
    message: BroadcastMessage,
    store: &S,
    chain: &ActorRef<CkbChainMessage>,
) {
    let message_id = message.id();
    if let Err(error) = match message {
        BroadcastMessage::ChannelAnnouncement(channel_announcement) => {
            verify_and_save_channel_announcement(channel_announcement, store, chain).await
        }
        BroadcastMessage::ChannelUpdate(channel_update) => {
            verify_and_save_channel_update(channel_update, store)
        }
        BroadcastMessage::NodeAnnouncement(node_announcement) => {
            verify_and_save_node_announcement(node_announcement, store)
        }
    } {
        error!(
            "Failed to process broadcast message with id {:?}: {:?}",
            message_id, error
        );
    };
}

async fn verify_and_save_channel_announcement<S: GossipMessageStore>(
    channel_announcement: ChannelAnnouncement,
    store: &S,
    chain: &ActorRef<CkbChainMessage>,
) -> Result<(), Error> {
    debug!(
        "Received channel announcement message: {:?}",
        &channel_announcement
    );
    let message = channel_announcement.message_to_sign();
    if channel_announcement.node1_id == channel_announcement.node2_id {
        return Err(Error::InvalidParameter(format!(
            "Channel announcement node had a channel with itself: {:?}",
            &channel_announcement
        )));
    }
    let (node1_signature, node2_signature, ckb_signature) = match (
        &channel_announcement.node1_signature,
        &channel_announcement.node2_signature,
        &channel_announcement.ckb_signature,
    ) {
        (Some(node1_signature), Some(node2_signature), Some(ckb_signature)) => {
            (node1_signature, node2_signature, ckb_signature)
        }
        _ => {
            return Err(Error::InvalidParameter(format!(
                "Channel announcement message signature verification failed, some signatures are missing: {:?}",
                &channel_announcement
            )));
        }
    };

    if !node1_signature.verify(&channel_announcement.node1_id, &message) {
        return Err(Error::InvalidParameter(format!(
            "Channel announcement message signature verification failed for node 1: {:?}, message: {:?}, signature: {:?}, pubkey: {:?}",
            &channel_announcement,
            &message,
            &node1_signature,
            &channel_announcement.node1_id
        )));
    }

    if !node2_signature.verify(&channel_announcement.node2_id, &message) {
        return Err(Error::InvalidParameter(format!(
            "Channel announcement message signature verification failed for node 2: {:?}, message: {:?}, signature: {:?}, pubkey: {:?}",
            &channel_announcement,
            &message,
            &node2_signature,
            &channel_announcement.node2_id
        )));
    }

    debug!(
        "Node signatures in channel announcement message verified: {:?}",
        &channel_announcement
    );

    let (tx, block_hash) = match call_t!(
        chain,
        CkbChainMessage::TraceTx,
        DEFAULT_CHAIN_ACTOR_TIMEOUT,
        TraceTxRequest {
            tx_hash: channel_announcement.channel_outpoint.tx_hash(),
            confirmations: 1,
        }
    ) {
        Ok(TraceTxResponse {
            tx: Some(tx),
            status:
                TxStatus {
                    status: Status::Committed,
                    block_hash: Some(block_hash),
                    ..
                },
        }) => (tx, block_hash),
        err => {
            return Err(Error::InvalidParameter(format!(
                "Channel announcement transaction {:?} not found or not confirmed, result is: {:?}",
                &channel_announcement.channel_outpoint.tx_hash(),
                err
            )));
        }
    };

    debug!("Channel announcement transaction found: {:?}", &tx);

    let pubkey = channel_announcement.ckb_key.serialize();
    let pubkey_hash = &blake2b_256(pubkey.as_slice())[0..20];
    match tx.inner.outputs.first() {
        None => {
            return Err(Error::InvalidParameter(format!(
                "On-chain transaction found but no output: {:?}",
                &channel_announcement
            )));
        }
        Some(output) => {
            if output.lock.args.as_bytes() != pubkey_hash {
                return Err(Error::InvalidParameter(format!(
                    "On-chain transaction found but pubkey hash mismatched: on chain hash {:?}, pub key ({:?}) hash {:?}",
                    &output.lock.args.as_bytes(),
                    hex::encode(pubkey),
                    &pubkey_hash
                )));
            }
            let capacity: u128 = u64::from(output.capacity).into();
            if channel_announcement.udt_type_script.is_none()
                && capacity != channel_announcement.capacity
            {
                return Err(Error::InvalidParameter(format!(
                    "On-chain transaction found but capacity mismatched: on chain capacity {:?}, channel capacity {:?}",
                    &output.capacity, &channel_announcement.capacity
                )));
            }
            capacity
        }
    };

    if let Err(err) = secp256k1_instance().verify_schnorr(
        ckb_signature,
        &Message::from_digest(message),
        &channel_announcement.ckb_key,
    ) {
        return Err(Error::InvalidParameter(format!(
            "Channel announcement message signature verification failed for ckb: {:?}, message: {:?}, signature: {:?}, pubkey: {:?}, error: {:?}",
            &channel_announcement,
            &message,
            &ckb_signature,
            &channel_announcement.ckb_key,
            &err
        )));
    }

    debug!(
        "All signatures in channel announcement message verified: {:?}",
        &channel_announcement
    );

    let timestamp: u64 = match call_t!(
        chain,
        CkbChainMessage::GetBlockTimestamp,
        DEFAULT_CHAIN_ACTOR_TIMEOUT,
        GetBlockTimestampRequest::from_block_hash(block_hash.clone())
    ) {
        Ok(Ok(Some(timestamp))) => timestamp,
        Ok(Ok(None)) => {
            return Err(Error::InternalError(anyhow::anyhow!(
                "Unable to find block {:?} for channel outpoint {:?}",
                &block_hash,
                &channel_announcement.channel_outpoint
            )));
        }
        Ok(Err(err)) => {
            return Err(Error::CkbRpcError(err));
        }
        Err(err) => {
            return Err(Error::InternalError(anyhow::Error::new(err).context(
                format!(
                    "Error while trying to obtain block {:?} for channel outpoint {:?}",
                    block_hash, channel_announcement.channel_outpoint
                ),
            )));
        }
    };

    debug!(
        "Saving channel announcement after obtained block timestamp for transaction {:?}: {}",
        &channel_announcement.channel_outpoint, timestamp
    );

    store.save_broadcast_message(BroadcastMessageWithTimestamp::ChannelAnnouncement(
        timestamp,
        channel_announcement,
    ));

    Ok(())
}

fn verify_and_save_channel_update<S: GossipMessageStore>(
    channel_update: ChannelUpdate,
    store: &S,
) -> Result<(), Error> {
    let message = channel_update.message_to_sign();

    let signature = match channel_update.signature {
        Some(ref signature) => signature,
        None => {
            return Err(Error::InvalidParameter(format!(
                "Channel update message signature verification failed (signature not found): {:?}",
                &channel_update
            )));
        }
    };
    match store.get_latest_channel_announcement(&channel_update.channel_outpoint) {
        Some((_, channel_announcement)) => {
            let pubkey = if channel_update.is_update_of_node_1() {
                channel_announcement.node1_id
            } else {
                channel_announcement.node2_id
            };
            debug!(
                "Verifying channel update message signature: {:?}, pubkey: {:?}, message: {:?}",
                &channel_update, &pubkey, &message
            );
            if !signature.verify(&pubkey, &message) {
                return Err(Error::InvalidParameter(format!(
                    "Channel update message signature verification failed (invalid signature): {:?}",
                    &channel_update
                )));
            }
        }
        None => {
            // TODO: It is possible that the channel update message is received before the channel announcement message.
            // In this case, we should store the channel update message and verify it later when the channel announcement message is received.
            return Err(Error::InvalidParameter(format!(
                "Failed to process channel update because channel announcement not found: {:?}",
                &channel_update
            )));
        }
    }
    store.save_broadcast_message(BroadcastMessageWithTimestamp::ChannelUpdate(channel_update));
    Ok(())
}

fn verify_and_save_node_announcement<S: GossipMessageStore>(
    node_announcement: NodeAnnouncement,
    store: &S,
) -> Result<(), Error> {
    let message = node_announcement.message_to_sign();
    match node_announcement.signature {
        Some(ref signature) if signature.verify(&node_announcement.node_id, &message) => {
            debug!(
                "Node announcement message verified: {:?}",
                &node_announcement
            );
        }
        _ => {
            return Err(Error::InvalidParameter(format!(
                "Node announcement message signature verification failed: {:?}",
                &node_announcement
            )));
        }
    }
    store.save_broadcast_message(BroadcastMessageWithTimestamp::NodeAnnouncement(
        node_announcement,
    ));
    Ok(())
}

impl GossipProtocolHandle {
    pub(crate) async fn new<S: GossipMessageStore + Send + Sync + 'static>(
        store: S,
        chain_actor: ActorRef<CkbChainMessage>,
        supervisor: ActorCell,
    ) -> Self {
        let (sender, receiver) = oneshot::channel();

        let (actor, _handle) = ActorRuntime::spawn_linked_instant(
            Some("gossip actor".to_string()),
            GossipActor::new(),
            (receiver, store, chain_actor),
            supervisor,
        )
        .expect("start gossip actor");
        Self {
            actor,
            sender: Some(sender),
        }
    }

    pub(crate) fn actor(&self) -> &ActorRef<GossipActorMessage> {
        &self.actor
    }

    pub(crate) fn create_meta(self) -> ProtocolMeta {
        MetaBuilder::new()
            .id(GOSSIP_PROTOCOL_ID)
            .service_handle(move || {
                let handle = Box::new(self);
                ProtocolHandle::Callback(handle)
            })
            .build()
    }
}

#[rasync_trait]
impl<S> Actor for GossipActor<S>
where
    S: GossipMessageStore + Send + Sync + 'static,
{
    type Msg = GossipActorMessage;
    type State = GossipActorState<S>;
    type Arguments = (
        oneshot::Receiver<ServiceAsyncControl>,
        S,
        ActorRef<CkbChainMessage>,
    );

    async fn pre_start(
        &self,
        myself: ActorRef<Self::Msg>,
        (rx, store, chain_actor): Self::Arguments,
    ) -> Result<Self::State, ActorProcessingErr> {
        let control = timeout(Duration::from_secs(1), rx)
            .await
            .expect("received control timely")
            .expect("receive control");
        debug!("Gossip actor received service control");
        let state = Self::State {
            store,
            chain_actor,
            control,
            peer_pubkey_map: Default::default(),
            peer_session_map: Default::default(),
            peer_filter_map: Default::default(),
        };
        Ok(state)
    }

    async fn handle(
        &self,
        myself: ActorRef<Self::Msg>,
        message: Self::Msg,
        state: &mut Self::State,
    ) -> Result<(), ActorProcessingErr> {
        match message {
            GossipActorMessage::PeerConnected(peer_id, pubkey, session) => {
                if state.peer_session_map.contains_key(&peer_id) {
                    warn!(
                        "Repeated connection from {:?} for gossip protocol",
                        &peer_id
                    );
                    return Ok(());
                }
                state.peer_session_map.insert(peer_id.clone(), session.id);
                state.peer_pubkey_map.insert(peer_id.clone(), pubkey);
            }
            GossipActorMessage::PeerDisconnected(peer_id, session) => {
                debug!(
                    "Peer disconnected: peer {:?}, session {:?}",
                    &peer_id, &session.id
                );
                let _ = state.peer_session_map.remove(&peer_id);
                let _ = state.peer_pubkey_map.remove(&peer_id);
            }
            GossipActorMessage::BroadcastMessage(broadcast_message) => {
                for (peer, session) in &state.peer_session_map {
                    match state.peer_filter_map.get(peer) {
                        Some(cursor) if cursor < &broadcast_message.cursor() => {
                            state
                                .control
                                .send_message_to(
                                    *session,
                                    GOSSIP_PROTOCOL_ID,
                                    GossipMessage::BroadcastMessagesFilterResult(
                                        broadcast_message.create_broadcast_messages_filter_result(),
                                    )
                                    .to_molecule_bytes(),
                                )
                                .await?;
                        }
                        _ => {}
                    }
                }
            }
            GossipActorMessage::GossipMessage(GossipMessageWithPeerId { peer_id, message }) => {
                match message {
                    GossipMessage::BroadcastMessagesFilter(BroadcastMessagesFilter {
                        chain_hash,
                        after_cursor,
                    }) => {
                        if chain_hash != get_chain_hash() {
                            warn!("Received BroadcastMessagesFilter with unknown chain hash {:?} (wants {:?})", chain_hash, get_chain_hash());
                            return Ok(());
                        }
                        state.peer_filter_map.insert(peer_id, after_cursor);
                    }
                    GossipMessage::BroadcastMessagesFilterResult(
                        broadcast_messages_filter_result,
                    ) => {
                        for message in broadcast_messages_filter_result.messages {
                            verify_and_save_broadcast_message(
                                message,
                                &state.store,
                                &state.chain_actor,
                            )
                            .await;
                        }
                    }
                    GossipMessage::GetBroadcastMessages(get_broadcast_messages) => todo!(),
                    GossipMessage::GetBroadcastMessagesResult(get_broadcast_messages_result) => {
                        todo!()
                    }
                    GossipMessage::QueryBroadcastMessages(query_broadcast_messages) => todo!(),
                    GossipMessage::QueryBroadcastMessagesResult(
                        query_broadcast_messages_result,
                    ) => todo!(),
                }
            }
        }

        Ok(())
    }
}

#[tasync_trait]
impl ServiceProtocol for GossipProtocolHandle {
    async fn init(&mut self, context: &mut ProtocolContext) {
        let sender = self
            .sender
            .take()
            .expect("service control sender set and init called once");
        if let Err(_) = sender.send(context.control().clone()) {
            panic!("Failed to send service control");
        }
    }

    async fn connected(&mut self, context: ProtocolContextMutRef<'_>, version: &str) {
        info!(
            "proto id [{}] open on session [{}], address: [{}], type: [{:?}], version: {}",
            context.proto_id,
            context.session.id,
            context.session.address,
            context.session.ty,
            version
        );

        if let Some(remote_pubkey) = context.session.remote_pubkey.clone() {
            let remote_peer_id = PeerId::from_public_key(&remote_pubkey);
            let _ = self.actor.send_message(GossipActorMessage::PeerConnected(
                remote_peer_id,
                remote_pubkey.into(),
                context.session.clone(),
            ));
        } else {
            warn!("Peer connected without remote pubkey {:?}", context.session);
        }
    }

    async fn disconnected(&mut self, context: ProtocolContextMutRef<'_>) {
        info!(
            "proto id [{}] close on session [{}], address: [{}], type: [{:?}]",
            context.proto_id, context.session.id, &context.session.address, &context.session.ty
        );

        match context.session.remote_pubkey.as_ref() {
            Some(remote_pubkey) => {
                let remote_peer_id = PeerId::from_public_key(&remote_pubkey);
                let _ = self
                    .actor
                    .send_message(GossipActorMessage::PeerDisconnected(
                        remote_peer_id,
                        context.session.clone(),
                    ));
            }
            None => {
                unreachable!("Received message without remote pubkey");
            }
        }
    }

    async fn received(&mut self, context: ProtocolContextMutRef<'_>, data: Bytes) {
        let message = unwrap_or_return!(GossipMessage::from_molecule_slice(&data), "parse message");
        match context.session.remote_pubkey.as_ref() {
            Some(pubkey) => {
                let peer_id = PeerId::from_public_key(pubkey);
                let _ = self.actor.send_message(GossipActorMessage::GossipMessage(
                    GossipMessageWithPeerId { peer_id, message },
                ));
            }
            None => {
                unreachable!("Received message without remote pubkey");
            }
        }
    }

    async fn notify(&mut self, _context: &mut ProtocolContext, _token: u64) {}
}

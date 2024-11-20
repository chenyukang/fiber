use std::collections::HashMap;

use ckb_types::packed::OutPoint;
use ractor::{
    async_trait as rasync_trait,
    concurrency::{timeout, Duration},
    Actor, ActorCell, ActorProcessingErr, ActorRef, ActorRuntime,
};
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

use crate::unwrap_or_return;

use super::{
    network::{get_chain_hash, GossipMessageWithPeerId, GOSSIP_PROTOCOL_ID},
    types::{
        BroadcastMessage, BroadcastMessageID, BroadcastMessageQuery, BroadcastMessageQueryFlags, BroadcastMessageWithTimestamp, BroadcastMessagesFilter, ChannelAnnouncement, ChannelUpdate, Cursor, GossipMessage, NodeAnnouncement, Pubkey
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
                .get_latest_channel_announcement(
                    &query.channel_outpoint
                ).map(|(timestamp, channel_announcement)| {
                    BroadcastMessageWithTimestamp::ChannelAnnouncement(timestamp, channel_announcement)
                }),
            BroadcastMessageQueryFlags::ChannelUpdateNode1 => self
                .get_latest_channel_update(&
                    query.channel_outpoint,
                    true,
                ).map(|channel_update| {
                    BroadcastMessageWithTimestamp::ChannelUpdate(channel_update)    
                }),
            BroadcastMessageQueryFlags::ChannelUpdateNode2 => self
            .get_latest_channel_update(&
                query.channel_outpoint,
                false,
            ).map(|channel_update| {
                BroadcastMessageWithTimestamp::ChannelUpdate(channel_update)    
            }),
            
            BroadcastMessageQueryFlags::NodeAnnouncementNode1 | BroadcastMessageQueryFlags::NodeAnnouncementNode2 => {
                self
                .get_latest_channel_announcement(
                    &query.channel_outpoint,
                ).and_then(
                    |(_, channel_announcement)| {
                                let node = if query.flags == BroadcastMessageQueryFlags::NodeAnnouncementNode1 {
                                    &channel_announcement.node1_id
                                } else {
                                    &channel_announcement.node2_id
                                };
                                self.get_lastest_node_announcement(node).map(|m| BroadcastMessageWithTimestamp::NodeAnnouncement(m))
                            }
                )
            },
        }
    }

    fn save_broadcast_message(&self, message: BroadcastMessageWithTimestamp);

    fn get_broadcast_message_with_cursor(
        &self,
        cursor: &Cursor,
    ) -> Option<BroadcastMessageWithTimestamp>;

    fn get_latest_channel_announcement_timestamp(&self, outpoint: &OutPoint) -> Option<u64>;

    fn get_latest_channel_update_timestamp(&self, outpoint: &OutPoint, is_node1: bool) -> Option<u64>;

    fn get_lastest_node_announcement_timestamp(&self, pk: &Pubkey) -> Option<u64>;

    fn get_latest_channel_announcement(&self, outpoint: &OutPoint) -> Option<(u64, ChannelAnnouncement)> {
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

    fn get_latest_channel_update(&self, outpoint: &OutPoint, is_node1: bool) -> Option<ChannelUpdate> {
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
    control: ServiceAsyncControl,
    peer_session_map: HashMap<PeerId, SessionId>,
    peer_pubkey_map: HashMap<PeerId, Pubkey>,
    peer_filter_map: HashMap<PeerId, Cursor>,
}

pub(crate) struct GossipProtocolHandle {
    actor: ActorRef<GossipActorMessage>,
    sender: Option<oneshot::Sender<ServiceAsyncControl>>,
}

impl GossipProtocolHandle {
    pub(crate) async fn new<S: GossipMessageStore + Send + Sync + 'static>(store: S,supervisor: ActorCell) -> Self {
        let (sender, receiver) = oneshot::channel();

        let (actor, _handle) = ActorRuntime::spawn_linked_instant(
            Some("gossip actor".to_string()),
            GossipActor::new(),
            (store, receiver),
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
where S: GossipMessageStore + Send + Sync + 'static {
    type Msg = GossipActorMessage;
    type State = GossipActorState<S>;
    type Arguments = (S, oneshot::Receiver<ServiceAsyncControl>);

    async fn pre_start(
        &self,
        myself: ActorRef<Self::Msg>,
        (store, rx): Self::Arguments,
    ) -> Result<Self::State, ActorProcessingErr> {
        let control = timeout(Duration::from_secs(1), rx)
            .await
            .expect("received control timely")
            .expect("receive control");
        debug!("Gossip actor received service control");
        let state = Self::State {
            store,
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
                    ) => todo!(),
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

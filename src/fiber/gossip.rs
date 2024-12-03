use std::{collections::HashMap, marker::PhantomData, sync::Arc, time::Duration};

use ckb_hash::blake2b_256;
use ckb_jsonrpc_types::{Status, TxStatus};
use ckb_types::packed::OutPoint;
use ractor::{
    async_trait as rasync_trait, call_t,
    concurrency::{timeout, JoinHandle},
    Actor, ActorCell, ActorProcessingErr, ActorRef, ActorRuntime, MessagingErr, OutputPort,
    RpcReplyPort, SupervisionEvent,
};
use secp256k1::Message;
use tentacle::{
    async_trait as tasync_trait,
    builder::MetaBuilder,
    bytes::Bytes,
    context::{ProtocolContext, ProtocolContextMutRef, SessionContext},
    secio::PeerId,
    service::{ProtocolHandle, ProtocolMeta, ServiceAsyncControl},
    traits::ServiceProtocol,
    SessionId,
};
use tokio::sync::oneshot;
use tracing::{debug, error, info, warn};

use crate::{
    ckb::{CkbChainMessage, GetBlockTimestampRequest, TraceTxRequest, TraceTxResponse},
    fiber::{network::DEFAULT_CHAIN_ACTOR_TIMEOUT, types::secp256k1_instance},
    now_timestamp, unwrap_or_return, Error,
};

use super::{
    network::{check_chain_hash, get_chain_hash, GossipMessageWithPeerId, GOSSIP_PROTOCOL_ID},
    types::{
        BroadcastMessage, BroadcastMessageID, BroadcastMessageQuery, BroadcastMessageQueryFlags,
        BroadcastMessageWithTimestamp, BroadcastMessagesFilter, BroadcastMessagesFilterResult,
        ChannelAnnouncement, ChannelUpdate, Cursor, GetBroadcastMessages,
        GetBroadcastMessagesResult, GossipMessage, NodeAnnouncement, Pubkey,
        QueryBroadcastMessages, QueryBroadcastMessagesResult,
    },
};

const MAX_BROADCAST_MESSAGE_TIMESTAMP_DRIFT: Duration = Duration::from_secs(60);
const MAX_BROADCAST_MESSAGE_TIMESTAMP_DRIFT_MILLIS: u64 =
    MAX_BROADCAST_MESSAGE_TIMESTAMP_DRIFT.as_millis() as u64;

const MAX_NUM_OF_BROADCAST_MESSAGES: u16 = 1000;
pub(crate) const DEFAULT_NUM_OF_BROADCAST_MESSAGE: u16 = 100;

const NUM_SIMULTANEOUS_GET_REQUESTS: usize = 1;
const NUM_PEERS_TO_RECEIVE_BROADCASTS: usize = 3;
const GET_REQUEST_TIMEOUT: Duration = Duration::from_secs(20);

pub trait GossipMessageStore {
    /// The implementors should guarantee that the returned messages are sorted by timestamp in the ascending order.
    fn get_broadcast_messages_iter(
        &self,
        after_cursor: &Cursor,
    ) -> impl IntoIterator<Item = BroadcastMessageWithTimestamp>;

    fn get_broadcast_messages(
        &self,
        after_cursor: &Cursor,
        count: Option<u16>,
    ) -> Vec<BroadcastMessageWithTimestamp> {
        self.get_broadcast_messages_iter(after_cursor)
            .into_iter()
            .take(count.unwrap_or(DEFAULT_NUM_OF_BROADCAST_MESSAGE as u16) as usize)
            .collect()
    }

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
                    self.get_latest_node_announcement(node)
                        .map(|m| BroadcastMessageWithTimestamp::NodeAnnouncement(m))
                }),
        }
    }

    fn get_broadcast_message_with_cursor(
        &self,
        cursor: &Cursor,
    ) -> Option<BroadcastMessageWithTimestamp>;

    fn get_latest_broadcast_message_cursor(&self) -> Option<Cursor>;

    fn get_latest_channel_announcement_timestamp(&self, outpoint: &OutPoint) -> Option<u64>;

    fn get_latest_channel_update_timestamp(
        &self,
        outpoint: &OutPoint,
        is_node1: bool,
    ) -> Option<u64>;

    fn get_latest_node_announcement_timestamp(&self, pk: &Pubkey) -> Option<u64>;

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

    fn get_latest_node_announcement(&self, pk: &Pubkey) -> Option<NodeAnnouncement> {
        self.get_latest_node_announcement_timestamp(pk).and_then(|timestamp| {
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

    fn save_channel_announcement(&self, timestamp: u64, channel_announcement: ChannelAnnouncement);

    fn save_channel_update(&self, channel_update: ChannelUpdate);

    fn save_node_announcement(&self, node_announcement: NodeAnnouncement);
}

// A batch of gossip messages has been added to the store since the last time
// we pulled new messages/messages are pushed to us.
#[derive(Clone)]
pub struct GossipMessageUpdates {
    pub messages: Vec<BroadcastMessageWithTimestamp>,
}

// New messages will be added to the store every now and then.
// These messages are not guaranteed to be saved to the store in order.
// This trait provides a way to subscribe to the updates of the gossip message store.
// The subscriber will receive a batch of messages that are added to the store since the last time
// we sent messages to the subscriber.
#[rasync_trait]
trait SubscribableGossipMessageStore {
    // Initialize a subscription for gossip message updates, the receiver will receive a batch of
    // messages that are added to the store since the last time we sent messages to the receiver.
    // These messages are first processed by the converter. When it is unideal to send messages to
    // the receiver the converter should return a None, otherwise it can return some message of type
    // TReceiverMsg, which would then be sent to the receiver actor.
    // The cursor here specifies the starting point of the subscription. If it is None, the subscription
    // will start from the very latest message in the store.
    async fn subscribe_store_updates<
        TReceiverMsg: ractor::Message,
        F: Fn(GossipMessageUpdates) -> Option<TReceiverMsg> + Send + 'static,
    >(
        &self,
        cursor: Option<Cursor>,
        receiver: ActorRef<TReceiverMsg>,
        converter: F,
    ) -> Result<(), Error>;
}

pub(crate) enum GossipActorMessage {
    /// Network events to be processed by this actor.
    PeerConnected(PeerId, Pubkey, SessionContext),
    PeerDisconnected(PeerId, SessionContext),

    // The function of TickNetworkMaintenance is to maintain the network state.
    // Currently it will do the following things:
    // 1. Check if we have sufficient number of peers to receive broadcasts. If not, send more BroadcastMessageFilter.
    // 2. Check if there are any pending broadcast messages. If so, broadcast them to the network.
    TickNetworkMaintenance,

    InitialSyncingFinished,

    // Process BroadcastMessage from the network. This is mostly used for testing.
    // In production, we process GossipMessage from the network.
    ProcessBroadcastMessage(BroadcastMessage),
    // Broadcast a BroadcastMessage created by us to the network.
    BroadcastMessages(Vec<BroadcastMessage>),
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

struct SyncingPeerState {
    failed_times: usize,
}

pub struct GossipSyncerState<S> {
    gossip_actor: ActorRef<GossipActorMessage>,
    chain_actor: ActorRef<CkbChainMessage>,
    store: S,
    peers: HashMap<PeerId, SyncingPeerState>,
    request_id: u64,
    inflight_requests: HashMap<
        u64,
        (
            PeerId,
            JoinHandle<Result<(), MessagingErr<GossipSyncerMessage>>>,
        ),
    >,
}

impl<S> GossipSyncerState<S> {
    fn new(
        gossiper: ActorRef<GossipActorMessage>,
        chain: ActorRef<CkbChainMessage>,
        store: S,
    ) -> Self {
        Self {
            gossip_actor: gossiper,
            store,
            chain_actor: chain,
            peers: Default::default(),
            inflight_requests: Default::default(),
            request_id: 0,
        }
    }

    fn select_a_node(&self) -> Option<&PeerId> {
        self.select_n_nodes(1).into_iter().next()
    }

    fn select_n_nodes(&self, n: usize) -> impl IntoIterator<Item = &PeerId> {
        let mut peers = self.peers.iter().collect::<Vec<_>>();
        peers.sort_by_key(|(_, state)| state.failed_times);
        peers.into_iter().take(n).map(|(peer, _)| peer)
    }

    fn get_and_increment_request_id(&mut self) -> u64 {
        let id = self.request_id;
        self.request_id += 1;
        id
    }
}

pub(crate) struct GossipSyncingActor<S> {
    _phantom: std::marker::PhantomData<S>,
}

impl<S> GossipSyncingActor<S> {
    fn new() -> Self {
        Self {
            _phantom: Default::default(),
        }
    }
}

pub(crate) enum GossipSyncerMessage {
    PeerConnected(PeerId),
    PeerDisconnected(PeerId),
    RequestTimeout(u64),
    ResponseReceived(PeerId, GetBroadcastMessagesResult),
    NewGetRequest(),
}

#[rasync_trait]
impl<S> Actor for GossipSyncingActor<S>
where
    S: GossipMessageStore + Send + Sync + 'static,
{
    type Msg = GossipSyncerMessage;
    type State = GossipSyncerState<S>;
    type Arguments = (ActorRef<GossipActorMessage>, ActorRef<CkbChainMessage>, S);

    async fn pre_start(
        &self,
        _myself: ActorRef<Self::Msg>,
        (gossip_actor, chain_actor, store): Self::Arguments,
    ) -> Result<Self::State, ActorProcessingErr> {
        Ok(GossipSyncerState::new(gossip_actor, chain_actor, store))
    }

    async fn handle(
        &self,
        myself: ActorRef<Self::Msg>,
        message: Self::Msg,
        state: &mut Self::State,
    ) -> Result<(), ActorProcessingErr> {
        match message {
            GossipSyncerMessage::PeerConnected(peer_id) => {
                state
                    .peers
                    .insert(peer_id, SyncingPeerState { failed_times: 0 });
                let _ = myself.send_message(GossipSyncerMessage::NewGetRequest());
            }
            GossipSyncerMessage::PeerDisconnected(peer_id) => {
                let _ = state.peers.remove(&peer_id);
            }
            GossipSyncerMessage::RequestTimeout(request_id) => {
                if let Some((peer_id, _)) = state.inflight_requests.remove(&request_id) {
                    warn!(
                        "GetBoradcastMessages request to peer timeout: peer {:?}, request {}",
                        &peer_id, request_id
                    );
                    if let Some(peer) = state.peers.get_mut(&peer_id) {
                        peer.failed_times += 1;
                    }
                }
                myself
                    .send_message(GossipSyncerMessage::NewGetRequest())
                    .expect("gossip syncing actor alive");
            }
            GossipSyncerMessage::ResponseReceived(peer_id, result) => {
                if let Some((peer, handle)) = state.inflight_requests.remove(&result.id) {
                    if &peer != &peer_id {
                        warn!(
                            "Received GetBroadcastMessages response from unexpected peer (possible malicious peer): expected {:?}, got {:?}",
                            peer, peer_id
                        );
                        state.inflight_requests.insert(result.id, (peer, handle));
                        return Ok(());
                    }
                    handle.abort();
                    let messages = result.messages;
                    // If we are receiving an empty response, then the syncing process is finished.
                    // TODO: a malicious peer may send an empty response to stop the syncing process.
                    // Maybe we should check a few more peers to see if they have the same response.
                    if messages.is_empty() {
                        state
                            .gossip_actor
                            .send_message(GossipActorMessage::InitialSyncingFinished)
                            .expect("gossip actor alive");
                    }

                    for message in messages {
                        match verify_broadcast_message(message, &state.store, &state.chain_actor)
                            .await
                        {
                            Ok(verified_message) => {
                                // To simplify things, we don't query missing messages related to this message.
                                // We just save the verified messages to the store.
                                save_broadcast_message(&state.store, verified_message.clone());
                            }
                            Err(error) => {
                                error!("Failed to verify and save broadcast message: {:?}", error);
                                continue;
                            }
                        }
                    }
                    myself
                        .send_message(GossipSyncerMessage::NewGetRequest())
                        .expect("gossip syncing actor alive");
                }
            }
            GossipSyncerMessage::NewGetRequest() => {
                let latest_cursor = state
                    .store
                    .get_latest_broadcast_message_cursor()
                    .unwrap_or_default();
                let request_id = state.get_and_increment_request_id();
                let request = GossipMessage::GetBroadcastMessages(GetBroadcastMessages {
                    id: request_id,
                    chain_hash: get_chain_hash(),
                    after_cursor: latest_cursor,
                    count: DEFAULT_NUM_OF_BROADCAST_MESSAGE,
                });
                // Send a new GetBroadcastMessages request to the newly-connected peer.
                // If we have less than NUM_SIMULTANEOUS_GET_REQUESTS requests inflight.
                if state.inflight_requests.len() < NUM_SIMULTANEOUS_GET_REQUESTS {
                    debug!("Not sending new GetBroadcastMessages request because there are already {} requests inflight (max {})", state.inflight_requests.len(), NUM_SIMULTANEOUS_GET_REQUESTS);
                    return Ok(());
                }
                match state.select_a_node() {
                    Some(peer) => {
                        state
                            .gossip_actor
                            .send_message(GossipActorMessage::GossipMessage(
                                GossipMessageWithPeerId {
                                    peer_id: peer.clone(),
                                    message: request,
                                },
                            ))
                            .expect("gossip actor alive");
                        let peer_id = peer.clone();
                        // Send a timeout message to myself after 20 seconds, which will resend the request to other peers.
                        let handle = myself.send_after(GET_REQUEST_TIMEOUT, move || {
                            // Send a timeout notification to myself after 20 seconds.
                            // If the request with the same request_id is completed before the timeout,
                            // we will cancel the timeout notification.
                            GossipSyncerMessage::RequestTimeout(request_id)
                        });
                        state
                            .inflight_requests
                            .insert(request_id, (peer_id, handle));
                    }
                    None => {
                        debug!("No suitable peer to send GetBroadcastMessages");
                    }
                }
            }
        }
        Ok(())
    }
}

#[derive(Default)]
struct PeerState {
    session: SessionId,
    // The filter is a cursor that the peer sent to us. We will only send messages to the peer
    // that are newer than the cursor. If the peer has not sent us a filter, we will not actively
    // send messages to the peer. If the peer sends us a new filter, we will update this field,
    // and send all the messages after the cursor to the peer immediately.
    filter: Option<Cursor>,
    // We will search for messages after this cursor in the store and send them to the
    // peer. This cursor is updated whenever we look for messages to send to the peer.
    // This cursor must be greater than the cursor in the filter.
    after_cursor: Cursor,
}

impl PeerState {
    fn new(session: SessionId) -> Self {
        Self {
            session,
            filter: Default::default(),
            after_cursor: Default::default(),
        }
    }

    fn is_syncing_with_us(&self) -> bool {
        self.filter.is_some()
    }

    fn update_for_messages(&mut self, messages: &[BroadcastMessageWithTimestamp]) {
        for message in messages {
            let cursor = message.cursor();
            if &cursor > &self.after_cursor {
                self.after_cursor = cursor;
            }
        }
    }
}

// This ExtendedGossipMessageStore is used to store the gossip messages and their dependencies.
// It enhances the GossipMessageStore trait with the ability to check the dependencies of the messages,
// and occasionally send out messages that are saved out of order (a message with smaller timestamp
// was saved before a message with larger timestamp).
pub struct ExtendedGossipMessageStore<S> {
    store: S,
    actor: ActorRef<ExtendedGossipMessageStoreMessage>,
}

impl<S> ExtendedGossipMessageStore<S>
where
    S: GossipMessageStore + Send + Sync + Clone + 'static,
{
    async fn new(store: S) -> Self {
        let (actor, _) = Actor::spawn(
            Some("gossip message store actor".to_string()),
            ExtendedGossipMessageStoreActor::new(),
            store.clone(),
        )
        .await
        .expect("start gossip message actor store");

        Self { store, actor }
    }
}

#[rasync_trait]
impl<S: GossipMessageStore + Sync> SubscribableGossipMessageStore
    for ExtendedGossipMessageStore<S>
{
    async fn subscribe_store_updates<
        TReceiverMsg: ractor::Message,
        F: Fn(GossipMessageUpdates) -> Option<TReceiverMsg> + Send + 'static,
    >(
        &self,
        cursor: Option<Cursor>,
        receiver: ActorRef<TReceiverMsg>,
        converter: F,
    ) -> Result<(), Error> {
        const DEFAULT_TIMEOUT: u64 = Duration::from_secs(5).as_millis() as u64;
        match call_t!(
            &self.actor,
            ExtendedGossipMessageStoreMessage::NewSubscription,
            DEFAULT_TIMEOUT,
            cursor
        ) {
            Ok(output_port) => {
                output_port.subscribe(receiver, converter);
                Ok(())
            }
            Err(e) => Err(Error::InternalError(anyhow::anyhow!(e.to_string()))),
        }
    }
}

impl<S: GossipMessageStore> GossipMessageStore for ExtendedGossipMessageStore<S> {
    fn get_broadcast_messages_iter(
        &self,
        after_cursor: &Cursor,
    ) -> impl IntoIterator<Item = BroadcastMessageWithTimestamp> {
        self.store.get_broadcast_messages_iter(after_cursor)
    }

    fn get_broadcast_message_with_cursor(
        &self,
        cursor: &Cursor,
    ) -> Option<BroadcastMessageWithTimestamp> {
        self.store.get_broadcast_message_with_cursor(cursor)
    }

    fn get_latest_broadcast_message_cursor(&self) -> Option<Cursor> {
        self.store.get_latest_broadcast_message_cursor()
    }

    fn get_latest_channel_announcement_timestamp(&self, outpoint: &OutPoint) -> Option<u64> {
        self.store
            .get_latest_channel_announcement_timestamp(outpoint)
    }

    fn get_latest_channel_update_timestamp(
        &self,
        outpoint: &OutPoint,
        is_node1: bool,
    ) -> Option<u64> {
        self.store
            .get_latest_channel_update_timestamp(outpoint, is_node1)
    }

    fn get_latest_node_announcement_timestamp(&self, pk: &Pubkey) -> Option<u64> {
        self.store.get_latest_node_announcement_timestamp(pk)
    }

    fn save_channel_announcement(&self, timestamp: u64, channel_announcement: ChannelAnnouncement) {
        let _ = self
            .actor
            .send_message(ExtendedGossipMessageStoreMessage::SaveMessage(
                BroadcastMessageWithTimestamp::ChannelAnnouncement(timestamp, channel_announcement),
            ));
    }

    fn save_channel_update(&self, channel_update: ChannelUpdate) {
        let _ = self
            .actor
            .send_message(ExtendedGossipMessageStoreMessage::SaveMessage(
                BroadcastMessageWithTimestamp::ChannelUpdate(channel_update),
            ));
    }

    fn save_node_announcement(&self, node_announcement: NodeAnnouncement) {
        let _ = self
            .actor
            .send_message(ExtendedGossipMessageStoreMessage::SaveMessage(
                BroadcastMessageWithTimestamp::NodeAnnouncement(node_announcement),
            ));
    }
}

struct BroadcastMessageOutput {
    // A subscriber may send a very small filter cursor to us. That filter cursor may be much smaller than
    // our last_cursor. In this case, we need to load all the messages from the store that are newer than
    // the filter cursor. Only after we have loaded all "historical" messages, we can start sending messages
    // in the normal procedure, i.e. sending only messages in lagged_messages and messages that are newer than last_cursor.
    is_loading_initially: bool,
    // The filter that a subscriber has set. We will only send messages that are newer than this filter.
    // This is normally a cursor that the subscriber is confident that it has received all the messages
    // before this cursor.
    filter: Option<Cursor>,
    // A port that from which the subscriber will receive messages and from which we will send messages to the subscriber.
    output_port: Arc<OutputPort<GossipMessageUpdates>>,
}

impl BroadcastMessageOutput {
    fn new(
        is_syncing: bool,
        filter: Option<Cursor>,
        output_port: Arc<OutputPort<GossipMessageUpdates>>,
    ) -> Self {
        Self {
            is_loading_initially: is_syncing,
            filter,
            output_port,
        }
    }
}

pub struct ExtendedGossipMessageStoreState<S> {
    store: S,
    next_id: u64,
    output_ports: HashMap<u64, BroadcastMessageOutput>,
    last_cursor: Cursor,
    lagged_messages: HashMap<BroadcastMessageID, BroadcastMessageWithTimestamp>,
    messages_to_be_saved: HashMap<BroadcastMessageID, BroadcastMessageWithTimestamp>,
}

impl<S: GossipMessageStore> ExtendedGossipMessageStoreState<S> {
    fn new(store: S) -> Self {
        Self {
            store,
            next_id: Default::default(),
            output_ports: Default::default(),
            last_cursor: Default::default(),
            lagged_messages: Default::default(),
            messages_to_be_saved: Default::default(),
        }
    }

    fn has_node_announcement(&self, node_id: &Pubkey) -> bool {
        self.store
            .get_latest_node_announcement_timestamp(node_id)
            .is_some()
            || self
                .messages_to_be_saved
                .contains_key(&BroadcastMessageID::NodeAnnouncement(node_id.clone()))
            || self
                .lagged_messages
                .contains_key(&BroadcastMessageID::NodeAnnouncement(node_id.clone()))
    }

    fn has_channel_announcement(&self, outpoint: &OutPoint) -> bool {
        self.get_channel_annnouncement(outpoint).is_some()
    }

    fn get_channel_annnouncement(&self, outpoint: &OutPoint) -> Option<ChannelAnnouncement> {
        self.store
            .get_latest_channel_announcement(outpoint)
            .map(|(_, channel_announcement)| channel_announcement)
            .or(self
                .messages_to_be_saved
                .get(&BroadcastMessageID::ChannelAnnouncement(outpoint.clone()))
                .and_then(|message| match message {
                    BroadcastMessageWithTimestamp::ChannelAnnouncement(_, channel_announcement) => {
                        Some(channel_announcement.clone())
                    }
                    _ => None,
                }))
            .or(self
                .lagged_messages
                .get(&BroadcastMessageID::ChannelAnnouncement(outpoint.clone()))
                .and_then(|message| match message {
                    BroadcastMessageWithTimestamp::ChannelAnnouncement(_, channel_announcement) => {
                        Some(channel_announcement.clone())
                    }
                    _ => None,
                }))
    }

    fn has_transitive_dependencies(&self, message: &BroadcastMessageWithTimestamp) -> bool {
        match message {
            BroadcastMessageWithTimestamp::ChannelAnnouncement(_, channel_announcement) => {
                let node1 = &channel_announcement.node1_id;
                let node2 = &channel_announcement.node2_id;
                self.has_node_announcement(node1) && self.has_node_announcement(node2)
            }
            BroadcastMessageWithTimestamp::ChannelUpdate(channel_update) => {
                match self.get_channel_annnouncement(&channel_update.channel_outpoint) {
                    Some(channel_announcement) => {
                        let node1 = &channel_announcement.node1_id;
                        let node2 = &channel_announcement.node2_id;
                        self.has_node_announcement(node1) && self.has_node_announcement(node2)
                    }
                    None => false,
                }
            }
            BroadcastMessageWithTimestamp::NodeAnnouncement(_) => true,
        }
    }
}

struct ExtendedGossipMessageStoreActor<S> {
    phantom: PhantomData<S>,
}

impl<S: GossipMessageStore> ExtendedGossipMessageStoreActor<S> {
    fn new() -> Self {
        Self {
            phantom: Default::default(),
        }
    }
}

#[rasync_trait]
impl<S: GossipMessageStore + Send + Sync + 'static> Actor for ExtendedGossipMessageStoreActor<S> {
    type Msg = ExtendedGossipMessageStoreMessage;
    type State = ExtendedGossipMessageStoreState<S>;
    type Arguments = S;

    async fn pre_start(
        &self,
        myself: ActorRef<Self::Msg>,
        store: Self::Arguments,
    ) -> Result<Self::State, ActorProcessingErr> {
        // TODO: make this interval configurable.
        myself.send_interval(Duration::from_millis(500), || {
            ExtendedGossipMessageStoreMessage::Tick
        });
        Ok(ExtendedGossipMessageStoreState::new(store))
    }

    async fn handle(
        &self,
        myself: ActorRef<Self::Msg>,
        message: Self::Msg,
        state: &mut Self::State,
    ) -> Result<(), ActorProcessingErr> {
        match message {
            ExtendedGossipMessageStoreMessage::NewSubscription(cursor, reply) => {
                let id = state.next_id;
                state.next_id += 1;
                let output_port = Arc::new(OutputPort::default());
                let _ = reply.send(Arc::clone(&output_port));
                let is_syncing = match &cursor {
                    // We are going to take all the messages that are older than last_cursor but newer than filter.
                    // After this we need only to look for messages after last_cursor and messages in lagged_messages
                    // that satisfy the filter.
                    Some(filter) if filter < &state.last_cursor => {
                        myself.send_message(
                            ExtendedGossipMessageStoreMessage::SendMessagesFromStore(
                                id,
                                filter.clone(),
                            ),
                        )?;
                        true
                    }
                    _ => false,
                };
                state.output_ports.insert(
                    id,
                    BroadcastMessageOutput::new(is_syncing, cursor, Arc::clone(&output_port)),
                );
            }

            ExtendedGossipMessageStoreMessage::SendMessagesFromStore(id, cursor) => {
                let output = match state.output_ports.get_mut(&id) {
                    Some(output) => output,
                    // Subscriber has already unsubscribed, early return.
                    None => return Ok(()),
                };
                let messages = state
                    .store
                    .get_broadcast_messages(&cursor, Some(MAX_NUM_OF_BROADCAST_MESSAGES))
                    .into_iter()
                    .filter(|m| m.cursor() < state.last_cursor)
                    .collect::<Vec<_>>();
                match messages.last() {
                    Some(m) => {
                        myself.send_message(
                            ExtendedGossipMessageStoreMessage::SendMessagesFromStore(
                                id,
                                m.cursor(),
                            ),
                        )?;
                        output.output_port.send(GossipMessageUpdates { messages });
                    }
                    // All the messages that are newer than the given cursor are now also newer than our global last_cursor.
                    // This means that we can use the global last_cursor as a starting point to send messages to the subscriber.
                    None => {
                        output.is_loading_initially = false;
                        return Ok(());
                    }
                }
            }

            ExtendedGossipMessageStoreMessage::SaveMessage(message) => {
                let message_cursor = message.cursor();
                let message_id = message.message_id();
                // Check if the message is lagged. If it is, then save it also to lagged_messages.
                if message_cursor < state.last_cursor {
                    state
                        .lagged_messages
                        .insert(message_id.clone(), message.clone());
                }
                // Check if the message has any dependencies that are not saved yet.
                // If it has, then stash it to messages_to_be_saved, otherwise, save it to the store.
                if get_dependent_message_queries(&message, &state.store).is_empty() {
                    save_broadcast_message(&state.store, message.clone());
                } else {
                    state
                        .messages_to_be_saved
                        .insert(message_id.clone(), message.clone());
                }
            }

            ExtendedGossipMessageStoreMessage::Tick => {
                // These subscriptions are the subscriptions that are not loading "historic" messages from the store.
                let effective_subscriptions = state
                    .output_ports
                    .values()
                    .filter(|output| !output.is_loading_initially)
                    .collect::<Vec<_>>();

                // Messages that have their dependencies saved are complete messages.
                // We need to save them to the store.
                let complete_messages_to_be_saved = state
                    .messages_to_be_saved
                    .values()
                    .filter(|m| state.has_transitive_dependencies(m))
                    .cloned()
                    .collect::<Vec<_>>();
                state
                    .messages_to_be_saved
                    .retain(|_, v| !complete_messages_to_be_saved.contains(v));

                // We also need to check if there are any lagged messages that are now complete.
                let lagged_complete_messages = state
                    .lagged_messages
                    .values()
                    .filter(|m| state.has_transitive_dependencies(m))
                    .cloned()
                    .collect::<Vec<_>>();
                state
                    .lagged_messages
                    .retain(|_, v| !lagged_complete_messages.contains(v));

                // We need to send the lagged complete messages to the subscribers. After doing this,
                // we may remove the messages from the lagged_messages.
                for subscription in &effective_subscriptions {
                    let messages_to_send = match subscription.filter {
                        Some(ref filter) => lagged_complete_messages
                            .iter()
                            .filter(|m| &m.cursor() > filter)
                            .cloned()
                            .collect::<Vec<_>>(),
                        None => lagged_complete_messages.clone(),
                    };
                    for chunk in messages_to_send.chunks(MAX_NUM_OF_BROADCAST_MESSAGES as usize) {
                        if chunk.is_empty() {
                            break;
                        }
                        subscription.output_port.send(GossipMessageUpdates {
                            messages: chunk.to_vec(),
                        });
                    }
                }

                // Saving all the messages that are complete and have also their dependencies saved.
                for message in lagged_complete_messages
                    .into_iter()
                    .chain(complete_messages_to_be_saved)
                {
                    // TODO: we may need to order all the messages by their dependencies, because
                    // the saving of broadcast messages is not an atomic operation. The node may fail any time
                    // while saving the messages. If the node failed, some messages in the store may not have their
                    // dependencies saved yet.
                    save_broadcast_message(&state.store, message);
                }

                // We now have some messages later than last_cursor saved to the store, we can take them
                // out and save them to the subscribers. Here we need to take messages directly from the
                // store because some messages with complete dependencies are previously saved directly
                // to the store.
                for subscription in effective_subscriptions {
                    let filter = subscription.filter.clone().unwrap_or_default();
                    // We still need to check if the messages returned are newer than the filter,
                    // because a subscriber may set filter so large that our last_cursor is still smaller
                    // than this filter cursor.
                    let mut starting_cursor_in_the_loop = if state.last_cursor > filter {
                        state.last_cursor.clone()
                    } else {
                        filter
                    };
                    loop {
                        let messages = state.store.get_broadcast_messages(
                            &starting_cursor_in_the_loop,
                            Some(MAX_NUM_OF_BROADCAST_MESSAGES),
                        );
                        match messages.last() {
                            Some(m) => {
                                starting_cursor_in_the_loop = m.cursor();
                                state.last_cursor = m.cursor();
                                subscription
                                    .output_port
                                    .send(GossipMessageUpdates { messages });
                            }
                            None => {
                                break;
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

pub enum ExtendedGossipMessageStoreMessage {
    // A new subscription for gossip message updates. We will send a batch of messages to the subscriber
    // via the returned output port.
    NewSubscription(
        Option<Cursor>,
        RpcReplyPort<Arc<OutputPort<GossipMessageUpdates>>>,
    ),
    // Save a new broadcast message to the store. We will check if the message has any dependencies that are not
    // saved yet. If it has, we will save it to messages_to_be_saved, otherwise we will save it to the store.
    // We may also save the message to lagged_messages if the message is lagged.
    SaveMessage(BroadcastMessageWithTimestamp),
    // Send broadcast messages after the cursor to the subscriber specified in the u64 id.
    // This is normally called immediately after a new subscription is created. This is the time when
    // we need to send existing messages to the subscriber.
    SendMessagesFromStore(u64, Cursor),
    // A tick message that is sent periodically to check if there are any messages that are saved out of order.
    // If there are, we will send them to the subscribers.
    // This tick will also advance the last_cursor upon finishing.
    Tick,
}

pub(crate) struct GossipActorState<S> {
    store: S,
    chain_actor: ActorRef<CkbChainMessage>,
    control: ServiceAsyncControl,
    next_request_id: u64,
    // The actor that is responsible for syncing the gossip messages.
    // On startup, we will create a GossipSyncerActor to sync the messages.
    // But when the initial syncing is finished, we will stop the actor.
    // And send BroadcastMessagesFilter to peers to receive the latest messages.
    gossip_sync_actor: Option<ActorRef<GossipSyncerMessage>>,
    // There are some messages missing from our store, and we need to query them from peers.
    // These messages include channel updates and node announcements related to channel announcements,
    // and channel announcements related to channel updates.
    pending_queries: Vec<BroadcastMessageQuery>,
    peer_states: HashMap<PeerId, PeerState>,
    // The last BroadcastMessagesFilter we sent to a peer. We will maintain
    // a number of filters for each peer, so that we can receive the latest
    // messages from the peer.
    my_filter_map: HashMap<PeerId, Cursor>,
}

impl<S> GossipActorState<S>
where
    S: GossipMessageStore + Send + Sync + 'static,
{
    fn is_syncing(&self) -> bool {
        self.gossip_sync_actor.is_some()
    }

    fn is_peer_connected(&self, peer_id: &PeerId) -> bool {
        self.peer_states.contains_key(peer_id)
    }

    fn get_peer_session(&self, peer_id: &PeerId) -> Option<SessionId> {
        self.peer_states.get(peer_id).map(|s| s.session)
    }

    fn get_latest_cursor(&self) -> Cursor {
        self.store
            .get_latest_broadcast_message_cursor()
            .unwrap_or_default()
    }

    async fn verify_and_save_broadcast_message(
        &mut self,
        message: BroadcastMessage,
    ) -> Result<BroadcastMessageWithTimestamp, Error> {
        let message_id = message.id();
        let verified_message = verify_broadcast_message(message, &self.store, &self.chain_actor)
            .await
            .map_err(|error| {
                error!(
                    "Failed to process broadcast message with id {:?}: {:?}",
                    message_id, &error
                );
                error
            })?;

        if verified_message.timestamp()
            > now_timestamp() + MAX_BROADCAST_MESSAGE_TIMESTAMP_DRIFT_MILLIS
        {
            return Err(Error::InvalidParameter(format!(
                "Broadcast message timestamp is too far in the future: {:?}",
                verified_message
            )));
        }
        save_broadcast_message(&self.store, verified_message.clone());

        // If there is any messages related to this message that we haven't obtained yet, we will
        // add them to pending_queries, which would be processed later.
        let queries = get_dependent_message_queries(&verified_message, &self.store);
        self.pending_queries.extend(queries);

        Ok(verified_message)
    }

    async fn send_message_to_session(
        &self,
        session_id: SessionId,
        message: GossipMessage,
    ) -> crate::Result<()> {
        send_message_to_session(&self.control, session_id, message).await?;
        Ok(())
    }

    async fn send_message_to_peer(
        &self,
        peer_id: &PeerId,
        message: GossipMessage,
    ) -> crate::Result<()> {
        match self.get_peer_session(peer_id) {
            Some(session_id) => self.send_message_to_session(session_id, message).await,
            None => Err(Error::PeerNotFound(peer_id.clone())),
        }
    }

    fn get_and_increment_request_id(&mut self) -> u64 {
        let id = self.next_request_id;
        self.next_request_id += 1;
        id
    }

    async fn send_broadcast_message_filter(&mut self, peer_id: &PeerId) {
        let cursor = self.get_latest_cursor();
        let message = GossipMessage::BroadcastMessagesFilter(BroadcastMessagesFilter {
            chain_hash: get_chain_hash(),
            after_cursor: cursor.clone(),
        });
        debug!(
            "Sending BroadcastMessagesFilter to peer {:?}: {:?}",
            &peer_id, &message
        );
        if let Err(error) = self.send_message_to_peer(peer_id, message).await {
            error!(
                "Failed to send BroadcastMessagesFilter to peer {:?}: {:?}",
                &peer_id, error
            );
        }
        self.my_filter_map.insert(peer_id.clone(), cursor);
    }
}

async fn send_message_to_session(
    control: &ServiceAsyncControl,
    session_id: SessionId,
    message: GossipMessage,
) -> crate::Result<()> {
    control
        .send_message_to(session_id, GOSSIP_PROTOCOL_ID, message.to_molecule_bytes())
        .await?;
    Ok(())
}

// Check if we have already stored messages related to this broadcast message.
// This function is called when we want to broadcast a message to the network.
// This message is already verified and saved to the store. But we don't know if
// we have stored messages related to this message. If we don't have related messages,
// we should not broadcast this message to the network because other peers may
// query the related messages from us if they don't have those messages.
fn have_related_messages_in_store<S: GossipMessageStore>(
    store: &S,
    message: &BroadcastMessage,
) -> bool {
    match message {
        BroadcastMessage::ChannelAnnouncement(channel_announcement) => {
            // There are two deadlocks here.
            // 1). Channel updates depend on channel announcements, and channel announcements depend on channel updates.
            // For our own channel announcements and channel updates, we can save them to the store first.
            // But it is difficult to to avoid the following situation.
            // 2). The channel announcement of one node depends on other node's announcements and channel updates.
            // We must send our channel announcement to the peer even if we don't have the other node's announcements and channel updates.
            // This is the reason why we shouldn't use this function to determine if we should broadcast our own messages to the network.
            store
                .get_latest_channel_update(&channel_announcement.channel_outpoint, true)
                .is_some()
                && store
                    .get_latest_channel_update(&channel_announcement.channel_outpoint, false)
                    .is_some()
                && store
                    .get_latest_node_announcement(&channel_announcement.node1_id)
                    .is_some()
                && store
                    .get_latest_node_announcement(&channel_announcement.node2_id)
                    .is_some()
        }
        BroadcastMessage::ChannelUpdate(channel_update) => {
            // Channel updates are independent, we shouldn't rely on channel update in the other direction to
            // broadcast channel update in this direction.
            store
                .get_latest_channel_announcement(&channel_update.channel_outpoint)
                .is_some()
        }
        BroadcastMessage::NodeAnnouncement(_node_announcement) => {
            // Node announcements can work independently (although it's not very useful (or even harmful) to
            // broadcast a node without any channel).
            true
        }
    }
}

pub(crate) struct GossipProtocolHandle {
    actor: ActorRef<GossipActorMessage>,
    sender: Option<oneshot::Sender<ServiceAsyncControl>>,
}

fn save_broadcast_message<S: GossipMessageStore>(
    store: &S,
    message: BroadcastMessageWithTimestamp,
) {
    match message {
        BroadcastMessageWithTimestamp::ChannelAnnouncement(timestamp, channel_announcement) => {
            store.save_channel_announcement(timestamp, channel_announcement)
        }
        BroadcastMessageWithTimestamp::ChannelUpdate(channel_update) => {
            store.save_channel_update(channel_update)
        }
        BroadcastMessageWithTimestamp::NodeAnnouncement(node_announcement) => {
            store.save_node_announcement(node_announcement)
        }
    }
}

fn get_dependent_message_queries<S: GossipMessageStore>(
    message: &BroadcastMessageWithTimestamp,
    store: &S,
) -> Vec<BroadcastMessageQuery> {
    let mut queries = Vec::new();
    match message {
        BroadcastMessageWithTimestamp::ChannelAnnouncement(_timestamp, channel_announcement) => {
            let outpoint = &channel_announcement.channel_outpoint;
            if store
                .get_latest_node_announcement_timestamp(&channel_announcement.node1_id)
                .is_none()
            {
                queries.push(BroadcastMessageQuery {
                    flags: BroadcastMessageQueryFlags::NodeAnnouncementNode1,
                    channel_outpoint: outpoint.clone(),
                });
            }
            if store
                .get_latest_node_announcement_timestamp(&channel_announcement.node2_id)
                .is_none()
            {
                queries.push(BroadcastMessageQuery {
                    flags: BroadcastMessageQueryFlags::NodeAnnouncementNode2,
                    channel_outpoint: outpoint.clone(),
                });
            }
        }
        BroadcastMessageWithTimestamp::ChannelUpdate(channel_update) => {
            // Check if we need to obtain related channel announcement message.
            let outpoint = &channel_update.channel_outpoint;
            if store
                .get_latest_channel_announcement_timestamp(outpoint)
                .is_none()
            {
                queries.push(BroadcastMessageQuery {
                    flags: BroadcastMessageQueryFlags::ChannelAnnouncement,
                    channel_outpoint: outpoint.clone(),
                });
            }
        }
        BroadcastMessageWithTimestamp::NodeAnnouncement(_node_announcement) => {}
    }
    queries
}

async fn verify_broadcast_message<S: GossipMessageStore>(
    message: BroadcastMessage,
    store: &S,
    chain: &ActorRef<CkbChainMessage>,
) -> Result<BroadcastMessageWithTimestamp, Error> {
    match message {
        BroadcastMessage::ChannelAnnouncement(channel_announcement) => {
            let timestamp =
                verify_channel_announcement(&channel_announcement, store, chain).await?;
            Ok(BroadcastMessageWithTimestamp::ChannelAnnouncement(
                timestamp,
                channel_announcement,
            ))
        }
        BroadcastMessage::ChannelUpdate(channel_update) => {
            verify_channel_update(&channel_update, store)?;
            Ok(BroadcastMessageWithTimestamp::ChannelUpdate(channel_update))
        }
        BroadcastMessage::NodeAnnouncement(node_announcement) => {
            verify_node_announcement(&node_announcement, store)?;
            Ok(BroadcastMessageWithTimestamp::NodeAnnouncement(
                node_announcement,
            ))
        }
    }
}

async fn verify_channel_announcement<S: GossipMessageStore>(
    channel_announcement: &ChannelAnnouncement,
    store: &S,
    chain: &ActorRef<CkbChainMessage>,
) -> Result<u64, Error> {
    debug!(
        "Verifying channel announcement message: {:?}",
        &channel_announcement
    );
    if let Some((timestamp, announcement)) =
        store.get_latest_channel_announcement(&channel_announcement.channel_outpoint)
    {
        if announcement == *channel_announcement {
            return Ok(timestamp);
        } else {
            return Err(Error::InvalidParameter(format!(
                "Channel announcement message already exists but mismatched: {:?}, existing: {:?}",
                &channel_announcement, &announcement
            )));
        }
    }
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

    Ok(timestamp)
}

fn verify_channel_update<S: GossipMessageStore>(
    channel_update: &ChannelUpdate,
    store: &S,
) -> Result<(), Error> {
    if let Some(BroadcastMessageWithTimestamp::ChannelUpdate(existing)) =
        store.get_broadcast_message_with_cursor(&channel_update.cursor())
    {
        if existing == *channel_update {
            return Ok(());
        } else {
            return Err(Error::InvalidParameter(format!(
                "Channel update message already exists but mismatched: {:?}, existing: {:?}",
                &channel_update, &existing
            )));
        }
    }
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
    Ok(())
}

fn verify_node_announcement<S: GossipMessageStore>(
    node_announcement: &NodeAnnouncement,
    store: &S,
) -> Result<(), Error> {
    if let Some(BroadcastMessageWithTimestamp::NodeAnnouncement(announcement)) =
        store.get_broadcast_message_with_cursor(&node_announcement.cursor())
    {
        if announcement == *node_announcement {
            return Ok(());
        } else {
            return Err(Error::InvalidParameter(format!(
                "Node announcement message already exists but mismatched: {:?}, existing: {:?}",
                &node_announcement, &announcement
            )));
        }
    }
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
    Ok(())
}

impl GossipProtocolHandle {
    pub(crate) async fn new<S: GossipMessageStore + Clone + Send + Sync + 'static>(
        name: Option<String>,
        gossip_network_maintenance_interval: Duration,
        store: S,
        chain_actor: ActorRef<CkbChainMessage>,
        supervisor: ActorCell,
    ) -> Self {
        let (sender, receiver) = oneshot::channel();

        let (actor, _handle) = ActorRuntime::spawn_linked_instant(
            name,
            GossipActor::new(),
            (
                receiver,
                gossip_network_maintenance_interval,
                store,
                chain_actor,
            ),
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
    S: GossipMessageStore + Clone + Send + Sync + 'static,
{
    type Msg = GossipActorMessage;
    type State = GossipActorState<S>;
    type Arguments = (
        oneshot::Receiver<ServiceAsyncControl>,
        Duration,
        S,
        ActorRef<CkbChainMessage>,
    );

    async fn pre_start(
        &self,
        myself: ActorRef<Self::Msg>,
        (rx, network_maintenance_interval, store, chain_actor): Self::Arguments,
    ) -> Result<Self::State, ActorProcessingErr> {
        let control = timeout(Duration::from_secs(1), rx)
            .await
            .expect("received control timely")
            .expect("receive control");
        debug!("Gossip actor received service control");

        let _ = myself.send_after(Duration::from_millis(500), || {
            GossipActorMessage::TickNetworkMaintenance
        });
        let _ = myself.send_interval(network_maintenance_interval, || {
            GossipActorMessage::TickNetworkMaintenance
        });
        let (syncing_actor, _) = Actor::spawn_linked(
            None,
            GossipSyncingActor::new(),
            (myself.clone(), chain_actor.clone(), store.clone()),
            myself.get_cell().clone(),
        )
        .await
        .expect("spawning gossip syncing actor");
        let state = Self::State {
            store,
            chain_actor,
            control,
            next_request_id: 0,
            gossip_sync_actor: Some(syncing_actor),
            pending_queries: Default::default(),
            peer_states: Default::default(),
            my_filter_map: Default::default(),
        };
        Ok(state)
    }

    async fn handle_supervisor_evt(
        &self,
        _myself: ActorRef<Self::Msg>,
        message: SupervisionEvent,
        _state: &mut Self::State,
    ) -> Result<(), ActorProcessingErr> {
        match message {
            SupervisionEvent::ActorTerminated(who, _, _) => {
                debug!("{:?} terminated", who);
            }
            SupervisionEvent::ActorPanicked(who, _) => {
                error!("{:?} panicked", who);
            }
            _ => {}
        }
        Ok(())
    }

    async fn handle(
        &self,
        _myself: ActorRef<Self::Msg>,
        message: Self::Msg,
        state: &mut Self::State,
    ) -> Result<(), ActorProcessingErr> {
        match message {
            GossipActorMessage::PeerConnected(peer_id, pubkey, session) => {
                if state.is_peer_connected(&peer_id) {
                    warn!(
                        "Repeated connection from {:?} for gossip protocol",
                        &peer_id
                    );
                    return Ok(());
                }
                debug!(
                    "Saving gossip peer pubkey and session: peer {:?}, pubkey {:?}, session {:?}",
                    &peer_id, &pubkey, &session.id
                );
                state
                    .peer_states
                    .insert(peer_id.clone(), PeerState::new(session.id));
                if let Some(sync_actor) = &state.gossip_sync_actor {
                    sync_actor
                        .send_message(GossipSyncerMessage::PeerConnected(peer_id.clone()))
                        .expect("gossip sync actor alive");
                }
            }
            GossipActorMessage::PeerDisconnected(peer_id, session) => {
                debug!(
                    "Peer disconnected: peer {:?}, session {:?}",
                    &peer_id, &session.id
                );
                let _ = state.peer_states.remove(&peer_id);
                if let Some(sync_actor) = &state.gossip_sync_actor {
                    sync_actor
                        .send_message(GossipSyncerMessage::PeerDisconnected(peer_id.clone()))
                        .expect("gossip sync actor alive");
                }
            }
            GossipActorMessage::ProcessBroadcastMessage(message) => {
                if let Err(error) = state
                    .verify_and_save_broadcast_message(message.clone())
                    .await
                {
                    error!(
                        "Failed to process broadcast message {:?}: {:?}",
                        &message, &error
                    );
                }
            }
            GossipActorMessage::BroadcastMessages(messages) => {
                debug!("Trying to broadcast message: {:?}", &messages);
                for message in messages {
                    match state
                        .verify_and_save_broadcast_message(message.clone())
                        .await
                    {
                        Ok(broadcast_message) => {
                            // This is our own message, so we will broadcast it to all peers immediately.
                            for (peer, peer_state) in &state.peer_states {
                                let session = peer_state.session;
                                match &peer_state.filter {
                                    Some(cursor) if cursor < &broadcast_message.cursor() => {
                                        state
                                            .send_message_to_session(
                                                session,
                                                GossipMessage::BroadcastMessagesFilterResult(
                                                    broadcast_message
                                                        .create_broadcast_messages_filter_result(),
                                                ),
                                            )
                                            .await?;
                                    }
                                    _ => {
                                        debug!(
                                        "Ignoring broadcast message for peer {:?}: {:?} as its cursor is {:?}",
                                        peer, &broadcast_message, &peer_state.filter
                                    );
                                    }
                                }
                            }
                        }
                        Err(error) => {
                            // This should never happen because we have already verified the message before broadcasting.
                            // But it is possible that we failed to obtain the block timestamp for the message.
                            error!(
                                "Failed to verify and save broadcast message {:?}: {:?}",
                                &message, &error
                            );
                            return Ok(());
                        }
                    };
                }
            }
            GossipActorMessage::TickNetworkMaintenance => {
                debug!(
                    "Network maintenance ticked, current state: num of peers: {}, is syncing: {}",
                    state.peer_states.len(),
                    state.is_syncing()
                );

                // Remove disconnected peers from my_filter_map. Add enough peers to my_filter_map if needed.
                state
                    .my_filter_map
                    .retain(|k, _| state.peer_states.contains_key(k));

                let current_num_peers = state.my_filter_map.len();
                if current_num_peers < NUM_PEERS_TO_RECEIVE_BROADCASTS && !state.is_syncing() {
                    let peers = state
                        .peer_states
                        .keys()
                        .filter(|p| !state.my_filter_map.contains_key(p))
                        .take(NUM_PEERS_TO_RECEIVE_BROADCASTS - current_num_peers)
                        .cloned()
                        .collect::<Vec<_>>();

                    for peer_id in peers {
                        state.send_broadcast_message_filter(&peer_id).await;
                    }
                }

                // Broadcast messages to peers.
                for peer_state in state.peer_states.values_mut() {
                    if peer_state.is_syncing_with_us() {
                        continue;
                    }
                    loop {
                        let obtained_messages = state.store.get_broadcast_messages(
                            &peer_state.after_cursor,
                            Some(DEFAULT_NUM_OF_BROADCAST_MESSAGE),
                        );
                        if obtained_messages.is_empty() {
                            break;
                        }
                        // To avoid obtain the same messages multiple times, we will update the after_cursor
                        // even if non of the messages should be sent to the peer.
                        peer_state.update_for_messages(&obtained_messages);
                        let messages = obtained_messages
                            .into_iter()
                            .map(Into::into)
                            .filter(|m| have_related_messages_in_store(&state.store, m))
                            .collect::<Vec<BroadcastMessage>>();
                        if messages.is_empty() {
                            break;
                        }
                        send_message_to_session(
                            &state.control,
                            peer_state.session,
                            GossipMessage::BroadcastMessagesFilterResult(
                                BroadcastMessagesFilterResult { messages },
                            ),
                        )
                        .await
                        .expect("send message to session");
                    }
                }

                // Query missing messages from peers.
                let pending_queries = std::mem::take(&mut state.pending_queries);
                for chunk in pending_queries.chunks(MAX_NUM_OF_BROADCAST_MESSAGES as usize) {
                    let queries = chunk.to_vec();
                    let id = state.get_and_increment_request_id();
                    for peer_state in state
                        .peer_states
                        .values()
                        .take(NUM_SIMULTANEOUS_GET_REQUESTS)
                    {
                        let message =
                            GossipMessage::QueryBroadcastMessages(QueryBroadcastMessages {
                                id,
                                chain_hash: get_chain_hash(),
                                queries: queries.clone(),
                            });
                        send_message_to_session(&state.control, peer_state.session, message)
                            .await?;
                    }
                }
            }

            GossipActorMessage::InitialSyncingFinished => {
                if let Some(sync_actor) = state.gossip_sync_actor.take() {
                    sync_actor.stop(Some("initial syncing finished".to_string()));
                }
            }

            GossipActorMessage::GossipMessage(GossipMessageWithPeerId { peer_id, message }) => {
                match message {
                    GossipMessage::BroadcastMessagesFilter(BroadcastMessagesFilter {
                        chain_hash,
                        after_cursor,
                    }) => {
                        check_chain_hash(&chain_hash)?;
                        let peer_state = match state.peer_states.get_mut(&peer_id) {
                            Some(peer_state) => {
                                peer_state.filter = Some(after_cursor.clone());
                                peer_state.after_cursor = after_cursor.clone();
                                peer_state
                            }
                            None => {
                                warn!(
                                    "Received BroadcastMessagesFilter from unknown peer: {:?}",
                                    &peer_id
                                );
                                return Ok(());
                            }
                        };
                        // Immediately send existing messages after the cursor in the store to the peer.
                        loop {
                            let messages = state.store.get_broadcast_messages(
                                &peer_state.after_cursor,
                                Some(DEFAULT_NUM_OF_BROADCAST_MESSAGE),
                            );
                            if messages.is_empty() {
                                break;
                            }
                            peer_state.update_for_messages(messages.as_slice());
                            let message = GossipMessage::BroadcastMessagesFilterResult(
                                BroadcastMessagesFilterResult {
                                    messages: messages.iter().map(|m| m.clone().into()).collect(),
                                },
                            );
                            if let Err(error) =
                                send_message_to_session(&state.control, peer_state.session, message)
                                    .await
                            {
                                warn!(
                                    "Failed to send BroadcastMessagesFilterResult to peer {:?}: {:?}",
                                    &peer_id, error
                                );
                            }
                        }
                    }
                    GossipMessage::BroadcastMessagesFilterResult(
                        BroadcastMessagesFilterResult { messages },
                    ) => {
                        for message in messages {
                            let _ = state.verify_and_save_broadcast_message(message).await;
                        }
                    }
                    GossipMessage::GetBroadcastMessages(get_broadcast_messages) => {
                        check_chain_hash(&get_broadcast_messages.chain_hash)?;
                        if get_broadcast_messages.count > MAX_NUM_OF_BROADCAST_MESSAGES {
                            warn!(
                                "Received GetBroadcastMessages with too many messages: {:?}",
                                get_broadcast_messages.count
                            );
                            return Ok(());
                        }
                        let id = get_broadcast_messages.id;
                        let messages = state.store.get_broadcast_messages(
                            &get_broadcast_messages.after_cursor,
                            Some(get_broadcast_messages.count as u16),
                        );
                        let result =
                            GossipMessage::GetBroadcastMessagesResult(GetBroadcastMessagesResult {
                                id,
                                messages: messages.into_iter().map(|m| m.into()).collect(),
                            });
                        if let Err(error) = state.send_message_to_peer(&peer_id, result).await {
                            error!(
                                "Failed to send GetBroadcastMessagesResult to peer {:?}: {:?}",
                                &peer_id, error
                            );
                        }
                    }
                    GossipMessage::GetBroadcastMessagesResult(result) => {
                        if let Some(syncing_actor) = &state.gossip_sync_actor {
                            syncing_actor
                                .send_message(GossipSyncerMessage::ResponseReceived(
                                    peer_id, result,
                                ))
                                .expect("gossip sync actor alive");
                        } else {
                            warn!(
                                "Received GetBroadcastMessagesResult but not syncing: {:?}",
                                &result
                            );
                        }
                    }
                    GossipMessage::QueryBroadcastMessages(QueryBroadcastMessages {
                        id,
                        chain_hash,
                        queries,
                    }) => {
                        check_chain_hash(&chain_hash)?;
                        if queries.len() > MAX_NUM_OF_BROADCAST_MESSAGES as usize {
                            warn!(
                                "Received QueryBroadcastMessages with too many queries: {:?}",
                                queries.len()
                            );
                            return Ok(());
                        }
                        let (results, missing_queries) =
                            state.store.query_broadcast_messages(queries);
                        let result = GossipMessage::QueryBroadcastMessagesResult(
                            QueryBroadcastMessagesResult {
                                id,
                                messages: results.into_iter().map(|m| m.into()).collect(),
                                missing_queries: missing_queries,
                            },
                        );
                        if let Err(error) = state.send_message_to_peer(&peer_id, result).await {
                            error!(
                                "Failed to send QueryBroadcastMessagesResult to peer {:?}: {:?}",
                                &peer_id, error
                            );
                        }
                    }
                    GossipMessage::QueryBroadcastMessagesResult(QueryBroadcastMessagesResult {
                        id,
                        messages,
                        missing_queries,
                    }) => {
                        let is_finished = missing_queries.is_empty();
                        for message in messages {
                            let _ = state.verify_and_save_broadcast_message(message).await;
                        }
                        // TODO: mark requests corresponding to id as finished
                        // TODO: if not finished, send another QueryBroadcastMessages.
                    }
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

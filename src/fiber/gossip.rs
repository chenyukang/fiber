use std::collections::HashMap;

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
    types::{BroadcastMessage, BroadcastMessagesFilter, Cursor, GossipMessage, Pubkey},
};

pub(crate) enum GossipActorMessage {
    /// Network events to be processed by this actor.
    PeerConnected(PeerId, Pubkey, SessionContext),
    PeerDisconnected(PeerId, SessionContext),

    // Command to broadcast BroadcastMessage to the network
    BroadcastMessage(BroadcastMessage),
    // Received GossipMessage from a peer
    GossipMessage(GossipMessageWithPeerId),
}

pub(crate) struct GossipActor {}

impl GossipActor {
    fn new() -> Self {
        Self {}
    }
}

pub(crate) struct GossipActorState {
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
    pub(crate) async fn new(supervisor: ActorCell) -> Self {
        let (sender, receiver) = oneshot::channel();

        let (actor, _handle) = ActorRuntime::spawn_linked_instant(
            Some("gossip actor".to_string()),
            GossipActor::new(),
            receiver,
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
impl Actor for GossipActor {
    type Msg = GossipActorMessage;
    type State = GossipActorState;
    type Arguments = oneshot::Receiver<ServiceAsyncControl>;

    async fn pre_start(
        &self,
        myself: ActorRef<Self::Msg>,
        rx: Self::Arguments,
    ) -> Result<Self::State, ActorProcessingErr> {
        let control = timeout(Duration::from_secs(1), rx)
            .await
            .expect("received control timely")
            .expect("receive control");
        debug!("Gossip actor received service control");
        let state = Self::State {
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

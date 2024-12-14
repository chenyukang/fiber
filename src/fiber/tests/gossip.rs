use std::{collections::HashSet, str::FromStr, sync::Arc};

use ractor::{async_trait, concurrency::Duration, Actor, ActorProcessingErr, ActorRef};
use tempfile::tempdir;
use tentacle::{
    builder::ServiceBuilder,
    context::ServiceContext,
    multiaddr::MultiAddr,
    secio::SecioKeyPair,
    service::{ServiceError, ServiceEvent},
    traits::ServiceHandle,
};
use tokio::{spawn, sync::RwLock};

use crate::{
    ckb::tests::actor::create_mock_chain_actor,
    fiber::{
        gossip::{
            ExtendedGossipMessageStore, ExtendedGossipMessageStoreMessage, GossipMessageStore,
            GossipMessageUpdates, GossipProtocolHandle, SubscribableGossipMessageStore,
        },
        types::{BroadcastMessage, BroadcastMessageWithTimestamp},
    },
    gen_rand_node_announcement,
    store::Store,
};

use super::test_utils::get_test_root_actor;

struct DummyServiceHandle;

impl DummyServiceHandle {
    pub fn new() -> Self {
        DummyServiceHandle
    }
}

#[async_trait]
impl ServiceHandle for DummyServiceHandle {
    async fn handle_error(&mut self, _context: &mut ServiceContext, error: ServiceError) {
        println!("Service error: {:?}", error);
    }
    async fn handle_event(&mut self, _context: &mut ServiceContext, event: ServiceEvent) {
        println!("Service event: {:?}", event);
    }
}

// The gossip actor expects us to pass a tentacle control. This is a dummy tentacle service that
// passes the control to the gossip actor. It serves no other purpose.
async fn run_dummy_tentacle_service(gossip_handle: GossipProtocolHandle) {
    let secio_kp = SecioKeyPair::secp256k1_generated();
    let mut service = ServiceBuilder::default()
        .insert_protocol(gossip_handle.create_meta())
        .handshake_type(secio_kp.into())
        .build(DummyServiceHandle::new());
    let _ = service
        .listen(
            MultiAddr::from_str("/ip4/127.0.0.1/tcp/0").expect("valid tentacle listening address"),
        )
        .await
        .expect("listen tentacle");

    let _ = spawn(async move {
        service.run().await;
    });
}

// This function creates a gossip store that can be subscribed to. The first return value is the
// the underlying store, the second is the actor that can be used to save messages to the store,
// The third is an entity from which we can subscribe to store updates.
async fn create_subscribable_gossip_store() -> (
    Store,
    ActorRef<ExtendedGossipMessageStoreMessage>,
    ExtendedGossipMessageStore<Store>,
) {
    let dir = tempdir().unwrap();
    let path = dir.path().join("gossip_store");
    let store = Store::new(path).expect("created store failed");
    let chain_actor = create_mock_chain_actor().await;
    let root_actor = get_test_root_actor().await;
    let (gossip_handle, store_update_subscriber) = GossipProtocolHandle::new(
        None,
        Duration::from_millis(50).into(),
        Duration::from_millis(50).into(),
        store.clone(),
        chain_actor,
        root_actor.get_cell(),
    )
    .await;

    run_dummy_tentacle_service(gossip_handle).await;

    (
        store,
        store_update_subscriber.actor.clone(),
        store_update_subscriber,
    )
}

// This function creates a gossip store that can be subscribed to. The first return value is the
// the underlying store, the second is the actor that can be used to save messages to the store,
// The third is an entity from which we can subscribe to store updates. The fourth is a vector
// that stores all the messages that the subscriber has received.
async fn create_subscribable_gossip_store_with_subscriber() -> (
    Store,
    ActorRef<ExtendedGossipMessageStoreMessage>,
    ExtendedGossipMessageStore<Store>,
    Arc<RwLock<Vec<BroadcastMessageWithTimestamp>>>,
) {
    let (store, store_actor, store_update_subscriber) = create_subscribable_gossip_store().await;
    let (subscriber, messages) = Subscriber::start_actor().await;
    store_update_subscriber
        .subscribe(None, subscriber, |m| Some(SubscriberMessage::Update(m)))
        .await
        .expect("subscribe to store updates");
    (store, store_actor, store_update_subscriber, messages)
}

// A subscriber which subscribes to the store updates and save all updates to a vector.
struct Subscriber {
    messages: Arc<RwLock<Vec<BroadcastMessageWithTimestamp>>>,
}

impl Subscriber {
    fn new() -> Self {
        Subscriber {
            messages: Arc::new(RwLock::new(Vec::new())),
        }
    }

    async fn start_actor() -> (
        ActorRef<SubscriberMessage>,
        Arc<RwLock<Vec<BroadcastMessageWithTimestamp>>>,
    ) {
        let subscriber = Subscriber::new();
        let messages = subscriber.messages.clone();
        let (actor, _) = Actor::spawn(None, subscriber, ())
            .await
            .expect("start subscriber");
        (actor, messages)
    }
}

enum SubscriberMessage {
    Update(GossipMessageUpdates),
}

#[async_trait]
impl Actor for Subscriber {
    type Msg = SubscriberMessage;
    type State = ();
    type Arguments = ();

    async fn pre_start(
        &self,
        _: ActorRef<Self::Msg>,
        _: Self::Arguments,
    ) -> Result<Self::State, ActorProcessingErr> {
        Ok(())
    }

    async fn post_stop(
        &self,
        _myself: ActorRef<Self::Msg>,
        _state: &mut Self::State,
    ) -> Result<(), ActorProcessingErr> {
        Ok(())
    }

    async fn handle(
        &self,
        _myself: ActorRef<Self::Msg>,
        message: Self::Msg,
        _state: &mut Self::State,
    ) -> Result<(), ActorProcessingErr> {
        match message {
            SubscriberMessage::Update(updates) => {
                let mut messages = self.messages.write().await;
                messages.extend(updates.messages);
            }
        }
        Ok(())
    }
}

#[tokio::test]
async fn test_save_gossip_message() {
    let (store, store_actor, _store_update_subscriber) = create_subscribable_gossip_store().await;
    let (_, announcement) = gen_rand_node_announcement();
    store_actor
        .send_message(ExtendedGossipMessageStoreMessage::SaveMessage(
            BroadcastMessage::NodeAnnouncement(announcement.clone()),
        ))
        .expect("send message");
    tokio::time::sleep(Duration::from_millis(200).into()).await;
    let new_announcement = store
        .get_latest_node_announcement(&announcement.node_id)
        .expect("get latest node announcement");
    assert_eq!(new_announcement, announcement);
}

#[tokio::test]
async fn test_gossip_store_updates_basic_subscription() {
    let (_, store_actor, _, messages) = create_subscribable_gossip_store_with_subscriber().await;
    let (_, announcement) = gen_rand_node_announcement();
    store_actor
        .send_message(ExtendedGossipMessageStoreMessage::SaveMessage(
            BroadcastMessage::NodeAnnouncement(announcement.clone()),
        ))
        .expect("send message");
    tokio::time::sleep(Duration::from_millis(200).into()).await;
    let messages = messages.read().await;
    assert!(messages.len() == 1);
    assert_eq!(
        messages[0],
        BroadcastMessageWithTimestamp::NodeAnnouncement(announcement)
    );
}

#[tokio::test]
async fn test_gossip_store_updates_repeated_saving() {
    let (_, store_actor, _, messages) = create_subscribable_gossip_store_with_subscriber().await;
    let (_, announcement) = gen_rand_node_announcement();
    for _ in 0..10 {
        store_actor
            .send_message(ExtendedGossipMessageStoreMessage::SaveMessage(
                BroadcastMessage::NodeAnnouncement(announcement.clone()),
            ))
            .expect("send message");
    }
    tokio::time::sleep(Duration::from_millis(200).into()).await;
    let messages = messages.read().await;
    assert!(messages.len() == 1);
    assert_eq!(
        messages[0],
        BroadcastMessageWithTimestamp::NodeAnnouncement(announcement)
    );
}

#[tokio::test]
async fn test_gossip_store_updates_saving_multiple_messages() {
    let (_, store_actor, _, messages) = create_subscribable_gossip_store_with_subscriber().await;
    let announcements = (0..10)
        .into_iter()
        .map(|_| gen_rand_node_announcement().1)
        .collect::<Vec<_>>();
    for annoncement in &announcements {
        store_actor
            .send_message(ExtendedGossipMessageStoreMessage::SaveMessage(
                BroadcastMessage::NodeAnnouncement(annoncement.clone()),
            ))
            .expect("send message");
    }
    tokio::time::sleep(Duration::from_millis(200).into()).await;
    let messages = messages.read().await;
    assert_eq!(
        messages.iter().cloned().collect::<HashSet<_>>(),
        announcements
            .into_iter()
            .map(|a| BroadcastMessageWithTimestamp::NodeAnnouncement(a))
            .collect::<HashSet<_>>()
    );
}

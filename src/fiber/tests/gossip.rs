use std::{collections::HashSet, str::FromStr, sync::Arc};

use ckb_jsonrpc_types::Status;
use ckb_types::core::TransactionView;
use ckb_types::packed::Bytes;
use ckb_types::prelude::{Builder, Entity};
use molecule::prelude::Byte;
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

use crate::create_invalid_ecdsa_signature;
use crate::{
    ckb::{
        tests::{actor::create_mock_chain_actor, test_utils::submit_tx},
        CkbChainMessage,
    },
    fiber::{
        gossip::{
            ExtendedGossipMessageStore, ExtendedGossipMessageStoreMessage, GossipMessageStore,
            GossipMessageUpdates, GossipProtocolHandle, SubscribableGossipMessageStore,
        },
        types::{BroadcastMessage, BroadcastMessageWithTimestamp, Cursor},
    },
    gen_node_announcement_from_privkey, gen_rand_channel_announcement, gen_rand_node_announcement,
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

struct GossipTestingContext {
    chain_actor: ActorRef<CkbChainMessage>,
    store_update_subscriber: ExtendedGossipMessageStore<Store>,
}

impl GossipTestingContext {
    async fn new() -> Self {
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
            chain_actor.clone(),
            root_actor.get_cell(),
        )
        .await;

        run_dummy_tentacle_service(gossip_handle).await;

        Self {
            chain_actor,
            store_update_subscriber,
        }
    }
}

impl GossipTestingContext {
    fn get_chain_actor(&self) -> &ActorRef<CkbChainMessage> {
        &self.chain_actor
    }

    fn get_store_update_subscriber(&self) -> &ExtendedGossipMessageStore<Store> {
        &self.store_update_subscriber
    }

    fn get_store(&self) -> &Store {
        &self.store_update_subscriber.store
    }

    fn get_store_actor(&self) -> &ActorRef<ExtendedGossipMessageStoreMessage> {
        &self.store_update_subscriber.actor
    }

    async fn subscribe(
        &self,
        cursor: Option<Cursor>,
    ) -> Arc<RwLock<Vec<BroadcastMessageWithTimestamp>>> {
        let (subscriber, messages) = Subscriber::start_actor().await;
        self.get_store_update_subscriber()
            .subscribe(cursor, subscriber, |m| Some(SubscriberMessage::Update(m)))
            .await
            .expect("subscribe to store updates");
        messages
    }

    fn save_message(&self, message: BroadcastMessage) {
        self.get_store_actor()
            .send_message(ExtendedGossipMessageStoreMessage::SaveMessage(message))
            .expect("send message");
    }

    async fn submit_tx(&self, tx: TransactionView) -> Status {
        submit_tx(self.get_chain_actor().clone(), tx).await
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
    let context = GossipTestingContext::new().await;
    let (_, announcement) = gen_rand_node_announcement();
    context.save_message(BroadcastMessage::NodeAnnouncement(announcement.clone()));
    tokio::time::sleep(Duration::from_millis(200).into()).await;
    let new_announcement = context
        .get_store()
        .get_latest_node_announcement(&announcement.node_id)
        .expect("get latest node announcement");
    assert_eq!(new_announcement, announcement);
}

#[tokio::test]
async fn test_saving_unconfirmed_channel_announcement() {
    let context = GossipTestingContext::new().await;
    let (_, announcement, _, _, _) = gen_rand_channel_announcement();
    context.save_message(BroadcastMessage::ChannelAnnouncement(announcement.clone()));
    tokio::time::sleep(Duration::from_millis(200).into()).await;
    let new_announcement = context
        .get_store()
        .get_latest_channel_announcement(&announcement.channel_outpoint);
    assert_eq!(new_announcement, None);
}

#[tokio::test]
async fn test_saving_confirmed_channel_announcement() {
    let context = GossipTestingContext::new().await;
    let (_, announcement, tx, _, _) = gen_rand_channel_announcement();
    context.save_message(BroadcastMessage::ChannelAnnouncement(announcement.clone()));
    let status = context.submit_tx(tx).await;
    assert_eq!(status, Status::Committed);
    tokio::time::sleep(Duration::from_millis(200).into()).await;
    let new_announcement = context
        .get_store()
        .get_latest_channel_announcement(&announcement.channel_outpoint);
    assert_eq!(new_announcement, None);
}

#[tokio::test]
async fn test_saving_invalid_channel_announcement() {
    let context = GossipTestingContext::new().await;
    let (_, announcement, tx, _, _) = gen_rand_channel_announcement();
    context.save_message(BroadcastMessage::ChannelAnnouncement(announcement.clone()));
    let output = tx.output(0).expect("get output").clone();
    let invalid_lock = output
        .lock()
        .as_builder()
        .args(
            Bytes::new_builder()
                .set(
                    b"wrong lock args"
                        .into_iter()
                        .map(|b| Byte::new(*b))
                        .collect(),
                )
                .build(),
        )
        .build();
    let invalid_output = output.as_builder().lock(invalid_lock).build();
    let invalid_tx = tx
        .as_advanced_builder()
        .set_outputs(vec![invalid_output])
        .build();
    let status = context.submit_tx(invalid_tx).await;
    assert_eq!(status, Status::Committed);
    tokio::time::sleep(Duration::from_millis(200).into()).await;
    let new_announcement = context
        .get_store()
        .get_latest_channel_announcement(&announcement.channel_outpoint);
    assert_eq!(new_announcement, None);
}

#[tokio::test]
async fn test_save_outdated_gossip_message() {
    let context = GossipTestingContext::new().await;
    let (sk, old_announcement) = gen_rand_node_announcement();
    // Make sure new announcement has a different timestamp
    tokio::time::sleep(Duration::from_millis(2).into()).await;
    let new_announcement = gen_node_announcement_from_privkey(&sk);
    context.save_message(BroadcastMessage::NodeAnnouncement(new_announcement.clone()));
    tokio::time::sleep(Duration::from_millis(200).into()).await;
    let announcement_in_store = context
        .get_store()
        .get_latest_node_announcement(&new_announcement.node_id)
        .expect("get latest node announcement");
    assert_eq!(announcement_in_store, new_announcement);

    context.save_message(BroadcastMessage::NodeAnnouncement(old_announcement.clone()));
    tokio::time::sleep(Duration::from_millis(200).into()).await;
    let announcement_in_store = context
        .get_store()
        .get_latest_node_announcement(&new_announcement.node_id)
        .expect("get latest node announcement");
    assert_eq!(announcement_in_store, new_announcement);
}

#[tokio::test]
async fn test_gossip_store_updates_basic_subscription() {
    let context = GossipTestingContext::new().await;
    let messages = context.subscribe(None).await;
    let (_, announcement) = gen_rand_node_announcement();
    context.save_message(BroadcastMessage::NodeAnnouncement(announcement.clone()));
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
    let context = GossipTestingContext::new().await;
    let messages = context.subscribe(None).await;
    let (_, announcement) = gen_rand_node_announcement();
    for _ in 0..10 {
        context.save_message(BroadcastMessage::NodeAnnouncement(announcement.clone()));
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
    let context = GossipTestingContext::new().await;
    let messages = context.subscribe(None).await;
    let announcements = (0..10)
        .into_iter()
        .map(|_| gen_rand_node_announcement().1)
        .collect::<Vec<_>>();
    for annoncement in &announcements {
        context.save_message(BroadcastMessage::NodeAnnouncement(annoncement.clone()));
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

#[tokio::test]
async fn test_gossip_store_updates_saving_outdated_message() {
    let context = GossipTestingContext::new().await;
    let messages = context.subscribe(None).await;
    let (sk, old_announcement) = gen_rand_node_announcement();
    // Make sure new announcement has a different timestamp
    tokio::time::sleep(Duration::from_millis(2).into()).await;
    let new_announcement = gen_node_announcement_from_privkey(&sk);
    for announcement in [&old_announcement, &new_announcement] {
        context.save_message(BroadcastMessage::NodeAnnouncement(announcement.clone()));
    }

    tokio::time::sleep(Duration::from_millis(200).into()).await;
    let messages = messages.read().await;
    // The subscriber may or may not receive the old announcement, but it should always receive the
    // new announcement.
    assert_eq!(
        messages[messages.len() - 1],
        BroadcastMessageWithTimestamp::NodeAnnouncement(new_announcement)
    );
}

// Old message is invalid, new message is valid
#[tokio::test]
async fn test_gossip_store_updates_saving_invalid_message_1() {
    let context = GossipTestingContext::new().await;
    let messages = context.subscribe(None).await;
    let (sk, mut old_announcement) = gen_rand_node_announcement();
    old_announcement.signature = Some(create_invalid_ecdsa_signature());
    // Make sure new announcement has a different timestamp
    tokio::time::sleep(Duration::from_millis(2).into()).await;
    let new_announcement = gen_node_announcement_from_privkey(&sk);
    for announcement in [&old_announcement, &new_announcement] {
        context.save_message(BroadcastMessage::NodeAnnouncement(announcement.clone()));
    }

    tokio::time::sleep(Duration::from_millis(200).into()).await;
    let messages = messages.read().await;
    assert_eq!(messages.len(), 1,);
    assert_eq!(
        messages[0],
        BroadcastMessageWithTimestamp::NodeAnnouncement(new_announcement)
    );
}

// New message is invalid, old message is valid
#[tokio::test]
async fn test_gossip_store_updates_saving_invalid_message_2() {
    let context = GossipTestingContext::new().await;
    let messages = context.subscribe(None).await;
    let (sk, old_announcement) = gen_rand_node_announcement();
    // Make sure new announcement has a different timestamp
    tokio::time::sleep(Duration::from_millis(2).into()).await;
    let mut new_announcement = gen_node_announcement_from_privkey(&sk);
    new_announcement.signature = Some(create_invalid_ecdsa_signature());
    for announcement in [&old_announcement, &new_announcement] {
        context.save_message(BroadcastMessage::NodeAnnouncement(announcement.clone()));
    }

    tokio::time::sleep(Duration::from_millis(200).into()).await;
    let messages = messages.read().await;
    assert_eq!(messages.len(), 1,);
    assert_eq!(
        messages[0],
        BroadcastMessageWithTimestamp::NodeAnnouncement(old_announcement)
    );
}

// Both messages have the same timestamp, but there is one invalid message
#[tokio::test]
async fn test_gossip_store_updates_saving_invalid_message_3() {
    let context = GossipTestingContext::new().await;
    let messages = context.subscribe(None).await;
    let (sk, old_announcement) = gen_rand_node_announcement();
    let mut new_announcement = old_announcement.clone();
    new_announcement.signature = Some(create_invalid_ecdsa_signature());
    for announcement in [&old_announcement, &new_announcement] {
        context.save_message(BroadcastMessage::NodeAnnouncement(announcement.clone()));
    }

    tokio::time::sleep(Duration::from_millis(200).into()).await;
    let messages = messages.read().await;
    assert_eq!(messages.len(), 1,);
    assert_eq!(
        messages[0],
        BroadcastMessageWithTimestamp::NodeAnnouncement(old_announcement)
    );
}

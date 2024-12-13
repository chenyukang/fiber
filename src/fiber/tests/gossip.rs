use std::str::FromStr;

use ractor::{async_trait, concurrency::Duration, ActorRef};
use tempfile::tempdir;
use tentacle::{
    builder::ServiceBuilder,
    context::ServiceContext,
    multiaddr::MultiAddr,
    secio::SecioKeyPair,
    service::{ServiceError, ServiceEvent},
    traits::ServiceHandle,
};
use tokio::spawn;

use crate::{
    ckb::tests::actor::create_mock_chain_actor,
    fiber::{
        gossip::{
            ExtendedGossipMessageStore, ExtendedGossipMessageStoreMessage, GossipMessageStore,
            GossipProtocolHandle,
        },
        types::BroadcastMessage,
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

async fn create_gossip_store_update_subscriber() -> (
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

#[tokio::test]
async fn test_save_gossip_message() {
    let (store, store_actor, _store_update_subscriber) =
        create_gossip_store_update_subscriber().await;
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

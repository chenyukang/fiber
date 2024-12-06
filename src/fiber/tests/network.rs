use super::test_utils::{init_tracing, NetworkNode};
use crate::{
    fiber::{
        channel::{MESSAGE_OF_NODE1_FLAG, MESSAGE_OF_NODE2_FLAG},
        gossip::GossipMessageStore,
        graph::ChannelUpdateInfo,
        network::{get_chain_hash, NetworkActorStateStore},
        tests::test_utils::NetworkNodeConfigBuilder,
        types::{
            BroadcastMessage, ChannelAnnouncement, ChannelUpdate, NodeAnnouncement, Privkey, Pubkey,
        },
        NetworkActorCommand, NetworkActorEvent, NetworkActorMessage,
    },
    now_timestamp, NetworkServiceEvent,
};
use ckb_hash::blake2b_256;
use ckb_jsonrpc_types::Status;
use ckb_types::{
    core::TransactionView,
    packed::{CellOutput, ScriptBuilder},
};
use ckb_types::{
    packed::OutPoint,
    prelude::{Builder, Entity, Pack},
};
use std::{borrow::Cow, str::FromStr};
use tentacle::{
    multiaddr::{MultiAddr, Protocol},
    secio::PeerId,
};

fn get_test_priv_key() -> Privkey {
    Privkey::from_slice(&[42u8; 32])
}

fn get_test_pub_key() -> Pubkey {
    get_test_priv_key().pubkey()
}

fn get_test_peer_id() -> PeerId {
    let pub_key = get_test_pub_key().into();
    PeerId::from_public_key(&pub_key)
}

fn get_fake_peer_id_and_address() -> (PeerId, MultiAddr) {
    let peer_id = PeerId::random();
    let mut address = MultiAddr::from_str(&format!(
        "/ip4/{}.{}.{}.{}/tcp/{}",
        rand::random::<u8>(),
        rand::random::<u8>(),
        rand::random::<u8>(),
        rand::random::<u8>(),
        rand::random::<u16>()
    ))
    .expect("valid multiaddr");
    address.push(Protocol::P2P(Cow::Owned(peer_id.clone().into_bytes())));
    (peer_id, address)
}

fn create_fake_channel_announcement_mesage(
    priv_key: Privkey,
    capacity: u64,
    outpoint: OutPoint,
) -> (NodeAnnouncement, NodeAnnouncement, ChannelAnnouncement) {
    let x_only_pub_key = priv_key.x_only_pub_key();
    let sk1 = Privkey::from([1u8; 32]);
    let node_announcement1 = create_fake_node_announcement_mesage_with_priv_key(&sk1);
    let sk2 = Privkey::from([2u8; 32]);
    let node_announcement2 = create_fake_node_announcement_mesage_with_priv_key(&sk2);

    let mut channel_announcement = ChannelAnnouncement::new_unsigned(
        &sk1.pubkey(),
        &sk2.pubkey(),
        outpoint,
        get_chain_hash(),
        &x_only_pub_key,
        capacity as u128,
        None,
    );
    let message = channel_announcement.message_to_sign();

    channel_announcement.ckb_signature = Some(priv_key.sign_schnorr(message));
    channel_announcement.node1_signature = Some(sk1.sign(message));
    channel_announcement.node2_signature = Some(sk2.sign(message));
    (node_announcement1, node_announcement2, channel_announcement)
}

fn create_fake_node_announcement_mesage_with_priv_key(priv_key: &Privkey) -> NodeAnnouncement {
    let node_name = "fake node";
    let addresses =
        vec!["/ip4/1.1.1.1/tcp/8346/p2p/QmaFDJb9CkMrXy7nhTWBY5y9mvuykre3EzzRsCJUAVXprZ"]
            .iter()
            .map(|x| MultiAddr::from_str(x).expect("valid multiaddr"))
            .collect();
    NodeAnnouncement::new(node_name.into(), addresses, priv_key, now_timestamp(), 0)
}

fn create_fake_node_announcement_mesage() -> NodeAnnouncement {
    let priv_key = get_test_priv_key();
    create_fake_node_announcement_mesage_with_priv_key(&priv_key)
}

#[tokio::test]
async fn test_sync_channel_announcement_on_startup() {
    init_tracing();

    let mut node1 = NetworkNode::new_with_node_name("node1").await;
    let mut node2 = NetworkNode::new_with_node_name("node2").await;

    let capacity = 42;
    let priv_key: Privkey = get_test_priv_key();
    let pubkey = priv_key.x_only_pub_key().serialize();
    let pubkey_hash = &blake2b_256(pubkey.as_slice())[0..20];
    let tx = TransactionView::new_advanced_builder()
        .output(
            CellOutput::new_builder()
                .capacity(capacity.pack())
                .lock(ScriptBuilder::default().args(pubkey_hash.pack()).build())
                .build(),
        )
        .output_data(vec![0u8; 8].pack())
        .build();
    let outpoint = tx.output_pts()[0].clone();
    let (node_announcement_1, node_announcement_2, channel_announcement) =
        create_fake_channel_announcement_mesage(priv_key, capacity, outpoint);

    assert_eq!(node1.submit_tx(tx.clone()).await, Status::Committed);

    for message in [
        BroadcastMessage::NodeAnnouncement(node_announcement_1.clone()),
        BroadcastMessage::NodeAnnouncement(node_announcement_2.clone()),
        BroadcastMessage::ChannelAnnouncement(channel_announcement.clone()),
    ] {
        node1
            .network_actor
            .send_message(NetworkActorMessage::Event(
                NetworkActorEvent::GossipMessage(
                    get_test_peer_id(),
                    message.create_broadcast_messages_filter_result(),
                ),
            ))
            .expect("send message to network actor");
    }

    node1.connect_to(&node2).await;

    assert_eq!(node2.submit_tx(tx.clone()).await, Status::Committed);

    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
    let channels = node2.get_network_graph_channels().await;
    assert!(!channels.is_empty());
}

async fn create_a_channel() -> (NetworkNode, ChannelAnnouncement, Privkey, Privkey) {
    init_tracing();

    let node_a_funding_amount = 100000000000;
    let node_b_funding_amount = 6200000000;

    let (node1, mut node2, _, funding_tx) = NetworkNode::new_2_nodes_with_established_channel(
        node_a_funding_amount,
        node_b_funding_amount,
        true,
    )
    .await;

    // Wait for the broadcast message to be processed.
    tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;
    let outpoint = funding_tx.output_pts_iter().next().unwrap();
    node2.stop().await;

    let (_, channel_announcement) = node2
        .store
        .get_latest_channel_announcement(&outpoint)
        .expect("get channel");

    let node1_priv_key = node1.get_private_key().clone();
    let node2_priv_key = node2.get_private_key().clone();
    if channel_announcement.node1_id == node1_priv_key.pubkey() {
        (node1, channel_announcement, node1_priv_key, node2_priv_key)
    } else {
        (node1, channel_announcement, node2_priv_key, node1_priv_key)
    }
}

#[tokio::test]
async fn test_node1_node2_channel_update() {
    let (node, channel_announcement, sk1, sk2) = create_a_channel().await;

    let create_channel_update = |timestamp: u64, message_flags: u32, key: Privkey| {
        let mut channel_update = ChannelUpdate::new_unsigned(
            get_chain_hash(),
            channel_announcement.out_point().clone(),
            timestamp,
            message_flags,
            0,
            42,
            0,
            0,
            10,
        );

        channel_update.signature = Some(key.sign(channel_update.message_to_sign()));
        node.network_actor
            .send_message(NetworkActorMessage::Event(
                NetworkActorEvent::GossipMessage(
                    get_test_peer_id(),
                    BroadcastMessage::ChannelUpdate(channel_update.clone())
                        .create_broadcast_messages_filter_result(),
                ),
            ))
            .expect("send message to network actor");
        channel_update
    };

    let channel_update_of_node1 = create_channel_update(now_timestamp(), 0, sk1);
    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

    let new_channel_info = node
        .get_network_graph_channel(channel_announcement.out_point())
        .await
        .unwrap();
    assert_eq!(
        new_channel_info.update_of_node1,
        Some(ChannelUpdateInfo::from(&channel_update_of_node1))
    );

    let channel_update_of_node2 = create_channel_update(now_timestamp(), 1, sk2);
    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

    let new_channel_info = node
        .get_network_graph_channel(channel_announcement.out_point())
        .await
        .unwrap();
    assert_eq!(
        new_channel_info.update_of_node1,
        Some(ChannelUpdateInfo::from(&channel_update_of_node1))
    );
    assert_eq!(
        new_channel_info.update_of_node2,
        Some(ChannelUpdateInfo::from(&channel_update_of_node2))
    );
}

#[tokio::test]
async fn test_channel_update_version() {
    let (node, channel_info, sk1, sk2) = create_a_channel().await;

    let create_channel_update = |key: &Privkey| {
        let message_flag = if key == &sk1 {
            MESSAGE_OF_NODE1_FLAG
        } else {
            MESSAGE_OF_NODE2_FLAG
        };
        let mut channel_update = ChannelUpdate::new_unsigned(
            get_chain_hash(),
            channel_info.out_point().clone(),
            now_timestamp(),
            message_flag,
            0,
            42,
            0,
            0,
            10,
        );
        tracing::debug!(
            "Signing channel update: {:?} with key (pub {:?}) (pk1 {:?}) (pk2 {:?})",
            &channel_update,
            &key.pubkey(),
            &sk1.pubkey(),
            &sk2.pubkey()
        );

        channel_update.signature = Some(key.sign(channel_update.message_to_sign()));
        channel_update
    };

    let (channel_update_1, channel_update_2, channel_update_3) = (
        create_channel_update(&sk1),
        create_channel_update(&sk1),
        create_channel_update(&sk1),
    );

    node.network_actor
        .send_message(NetworkActorMessage::Event(
            NetworkActorEvent::GossipMessage(
                get_test_peer_id(),
                BroadcastMessage::ChannelUpdate(channel_update_2.clone())
                    .create_broadcast_messages_filter_result(),
            ),
        ))
        .expect("send message to network actor");
    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
    let new_channel_info = node
        .get_network_graph_channel(channel_info.out_point())
        .await
        .unwrap();
    assert_eq!(
        new_channel_info.update_of_node1,
        Some(ChannelUpdateInfo::from(&channel_update_2))
    );

    // Old channel update will not replace the new one.
    node.network_actor
        .send_message(NetworkActorMessage::Event(
            NetworkActorEvent::GossipMessage(
                get_test_peer_id(),
                BroadcastMessage::ChannelUpdate(channel_update_1.clone())
                    .create_broadcast_messages_filter_result(),
            ),
        ))
        .expect("send message to network actor");
    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
    let new_channel_info = node
        .get_network_graph_channel(channel_info.out_point())
        .await
        .unwrap();
    assert_eq!(
        new_channel_info.update_of_node1,
        Some(ChannelUpdateInfo::from(&channel_update_2))
    );

    // New channel update will replace the old one.
    node.network_actor
        .send_message(NetworkActorMessage::Event(
            NetworkActorEvent::GossipMessage(
                get_test_peer_id(),
                BroadcastMessage::ChannelUpdate(channel_update_3.clone())
                    .create_broadcast_messages_filter_result(),
            ),
        ))
        .expect("send message to network actor");
    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
    let new_channel_info = node
        .get_network_graph_channel(channel_info.out_point())
        .await
        .unwrap();
    assert_eq!(
        new_channel_info.update_of_node1,
        Some(ChannelUpdateInfo::from(&channel_update_3))
    );
}

#[tokio::test]
async fn test_sync_node_announcement_version() {
    init_tracing();

    let node = NetworkNode::new_with_node_name("node").await;
    let test_pub_key = get_test_pub_key();
    let test_peer_id = get_test_peer_id();

    let [node_announcement_message_version1, node_announcement_message_version2, node_announcement_message_version3] = [
        create_fake_node_announcement_mesage(),
        create_fake_node_announcement_mesage(),
        create_fake_node_announcement_mesage(),
    ];
    let timestamp_version2 = node_announcement_message_version2.timestamp;
    let timestamp_version3 = node_announcement_message_version3.timestamp;

    node.network_actor
        .send_message(NetworkActorMessage::Event(
            NetworkActorEvent::GossipMessage(
                test_peer_id.clone(),
                BroadcastMessage::NodeAnnouncement(node_announcement_message_version2)
                    .create_broadcast_messages_filter_result(),
            ),
        ))
        .expect("send message to network actor");

    // Wait for the broadcast message to be processed.
    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
    let node_info = node.get_network_graph_node(&test_pub_key).await;
    match node_info {
        Some(n) if n.timestamp == timestamp_version2 => {}
        _ => panic!(
            "Must have version 2 announcement message, found {:?}",
            &node_info
        ),
    }

    node.network_actor
        .send_message(NetworkActorMessage::Event(
            NetworkActorEvent::GossipMessage(
                test_peer_id.clone(),
                BroadcastMessage::NodeAnnouncement(node_announcement_message_version1)
                    .create_broadcast_messages_filter_result(),
            ),
        ))
        .expect("send message to network actor");

    // Wait for the broadcast message to be processed.
    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
    let node_info = node.get_network_graph_node(&test_pub_key).await;
    match node_info {
        Some(n) if n.timestamp == timestamp_version2 => {}
        _ => panic!(
            "Must have version 2 announcement message, found {:?}",
            &node_info
        ),
    }

    node.network_actor
        .send_message(NetworkActorMessage::Event(
            NetworkActorEvent::GossipMessage(
                test_peer_id.clone(),
                BroadcastMessage::NodeAnnouncement(node_announcement_message_version3)
                    .create_broadcast_messages_filter_result(),
            ),
        ))
        .expect("send message to network actor");
    // Wait for the broadcast message to be processed.
    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
    let node_info = node.get_network_graph_node(&test_pub_key).await;
    match node_info {
        Some(n) if n.timestamp == timestamp_version3 => {}
        _ => panic!(
            "Must have version 3 announcement message, found {:?}",
            &node_info
        ),
    }
}

// Test that we can sync the network graph with peers.
// We will first create a node and announce a fake node announcement to the network.
// Then we will create another node and connect to the first node.
// We will see if the second node has the fake node announcement.
#[tokio::test]
async fn test_sync_node_announcement_on_startup() {
    init_tracing();

    let mut node1 = NetworkNode::new_with_node_name("node1").await;
    let mut node2 = NetworkNode::new_with_node_name("node2").await;
    let test_pub_key = get_test_pub_key();
    let test_peer_id = get_test_peer_id();

    node1
        .network_actor
        .send_message(NetworkActorMessage::Event(
            NetworkActorEvent::GossipMessage(
                test_peer_id.clone(),
                BroadcastMessage::NodeAnnouncement(create_fake_node_announcement_mesage())
                    .create_broadcast_messages_filter_result(),
            ),
        ))
        .expect("send message to network actor");

    node1.connect_to(&node2).await;

    // Wait for the broadcast message to be processed.
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

    let node_info = node1.get_network_graph_node(&test_pub_key).await;
    assert!(node_info.is_some());

    let node_info = node2.get_network_graph_node(&test_pub_key).await;
    assert!(node_info.is_some());
}

// Test that we can sync the network graph with peers.
// We will first create a node and announce a fake node announcement to the network.
// Then we will create another node and connect to the first node.
// We will see if the second node has the fake node announcement.
#[tokio::test]
async fn test_sync_node_announcement_after_restart() {
    init_tracing();

    let [mut node1, mut node2] = NetworkNode::new_n_interconnected_nodes().await;

    node2.stop().await;

    let test_pub_key = get_test_pub_key();
    let test_peer_id = get_test_peer_id();
    node1
        .network_actor
        .send_message(NetworkActorMessage::Event(
            NetworkActorEvent::GossipMessage(
                test_peer_id.clone(),
                BroadcastMessage::NodeAnnouncement(create_fake_node_announcement_mesage())
                    .create_broadcast_messages_filter_result(),
            ),
        ))
        .expect("send message to network actor");

    node2.start().await;
    node2.connect_to(&node1).await;

    // Wait for the broadcast message to be processed.
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    let node_info = node1.get_network_graph_node(&test_pub_key).await;
    assert!(node_info.is_some());

    let node_info = node2.get_network_graph_node(&test_pub_key).await;
    assert!(node_info.is_some());
}

#[tokio::test]
async fn test_persisting_network_state() {
    let mut node = NetworkNode::new().await;
    let state = node.store.clone();
    let peer_id = node.peer_id.clone();
    node.stop().await;
    assert!(state.get_network_actor_state(&peer_id).is_some())
}

#[tokio::test]
async fn test_persisting_bootnode() {
    let (boot_peer_id, address) = get_fake_peer_id_and_address();
    let address_string = format!("{}", &address);

    let mut node = NetworkNode::new_with_config(
        NetworkNodeConfigBuilder::new()
            .fiber_config_updater(move |config| config.bootnode_addrs = vec![address_string])
            .build(),
    )
    .await;
    let state = node.store.clone();
    let peer_id = node.peer_id.clone();
    node.stop().await;

    let state = state.get_network_actor_state(&peer_id).unwrap();
    let peers = state.sample_n_peers_to_connect(1);
    assert_eq!(peers.get(&boot_peer_id), Some(&vec![address]));
}

#[tokio::test]
async fn test_persisting_announced_nodes() {
    let mut node = NetworkNode::new_with_node_name("test").await;

    let announcement = create_fake_node_announcement_mesage();
    let node_pk = announcement.node_id;
    let peer_id = node_pk.tentacle_peer_id();

    node.network_actor
        .send_message(NetworkActorMessage::Event(
            NetworkActorEvent::GossipMessage(
                peer_id.clone(),
                BroadcastMessage::NodeAnnouncement(announcement)
                    .create_broadcast_messages_filter_result(),
            ),
        ))
        .expect("send message to network actor");

    // Wait for the above message to be processed.
    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

    node.stop().await;
    let peers = node
        .with_network_graph(|graph| graph.sample_n_peers_to_connect(1))
        .await;
    assert!(peers.get(&peer_id).is_some());
}

#[tokio::test]
async fn test_connecting_to_bootnode() {
    let boot_node = NetworkNode::new().await;
    let boot_node_address = format!("{}", boot_node.get_node_address());
    let boot_node_id = &boot_node.peer_id;

    let mut node = NetworkNode::new_with_config(
        NetworkNodeConfigBuilder::new()
            .fiber_config_updater(move |config| config.bootnode_addrs = vec![boot_node_address])
            .build(),
    )
    .await;

    node.expect_event(
        |event| matches!(event, NetworkServiceEvent::PeerConnected(id, _addr) if id == boot_node_id),
    )
    .await;
}

#[tokio::test]
async fn test_saving_and_connecting_to_node() {
    init_tracing();

    let node1 = NetworkNode::new().await;
    let node1_address = node1.get_node_address().clone();
    let node1_id = &node1.peer_id;

    let mut node2 = NetworkNode::new().await;

    node2
        .network_actor
        .send_message(NetworkActorMessage::new_command(
            NetworkActorCommand::SavePeerAddress(node1_address),
        ))
        .expect("send message to network actor");

    // Wait for the above message to be processed.
    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

    node2.restart().await;

    node2.expect_event(
        |event| matches!(event, NetworkServiceEvent::PeerConnected(id, _addr) if id == node1_id),
    )
    .await;
}

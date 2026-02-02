use crate::fiber::channel::{AppliedFlags, TlcInfo};
use crate::fiber::channel::{
    CommitmentNumbers, InboundTlcStatus, OutboundTlcStatus, TLCId, TlcState, TlcStatus,
};
use crate::fiber::hash_algorithm::HashAlgorithm;
use crate::fiber::types::RemoveTlcFulfill;
use crate::fiber::types::TlcErrorCode;
use crate::fiber::types::{Hash256, NO_SHARED_SECRET};
use crate::fiber::types::{PaymentOnionPacket, RemoveTlcReason};
use crate::gen_rand_sha256_hash;
use crate::now_timestamp_as_millis_u64;
use ckb_hash::new_blake2b;
use ckb_types::packed::Byte32;

use ractor::{Actor, ActorProcessingErr, ActorRef};
use std::collections::HashMap;

fn sign_tlcs<'a>(tlcs: impl Iterator<Item = &'a TlcInfo>) -> Hash256 {
    // serialize active_tls to ge a hash
    let mut keyparts = tlcs
        .map(|tlc| (tlc.amount, tlc.payment_hash))
        .collect::<Vec<_>>();

    keyparts.sort_by(|a, b| {
        let a: Byte32 = a.1.into();
        let b: Byte32 = b.1.into();
        a.cmp(&b)
    });

    eprintln!("keyparts: {:?}", keyparts);
    let serialized = serde_json::to_string(&keyparts).expect("Failed to serialize tls");

    // Hash the serialized data using SHA-256
    let mut hasher = new_blake2b();
    hasher.update(serialized.to_string().as_bytes());
    let mut result = [0u8; 32];
    hasher.finalize(&mut result);

    result.into()
}

pub struct TlcActorState {
    pub tlc_state: TlcState,
    pub peer_id: String,
}

impl TlcActorState {
    pub fn get_peer(&self) -> String {
        if self.peer_id == "peer_a" {
            "peer_b".to_string()
        } else {
            "peer_a".to_string()
        }
    }
}

pub struct NetworkActorState {
    network: ActorRef<NetworkActorMessage>,
    pub peers: HashMap<String, ActorRef<TlcActorMessage>>,
}

impl NetworkActorState {
    pub async fn add_peer(&mut self, peer_id: String) {
        let network = self.network.clone();
        let actor = Actor::spawn_linked(
            Some(peer_id.clone()),
            TlcActor::new(network.clone()),
            peer_id.clone(),
            network.clone().get_cell(),
        )
        .await
        .expect("Failed to start tlc actor")
        .0;
        self.peers.insert(peer_id.clone(), actor);
        eprintln!("add_peer: {:?} added successfully ...", peer_id);
    }
}

pub struct TlcActor {
    network: ActorRef<NetworkActorMessage>,
}

impl TlcActor {
    pub fn new(network: ActorRef<NetworkActorMessage>) -> Self {
        Self { network }
    }
}

#[derive(Debug, Clone)]
pub struct AddTlcCommand {
    pub amount: u128,
    pub payment_hash: Hash256,
    /// The attempt id associate with the tlc
    pub attempt_id: Option<u64>,
    pub expiry: u64,
    pub hash_algorithm: HashAlgorithm,
    pub onion_packet: Option<PaymentOnionPacket>,
    pub shared_secret: [u8; 32],
    #[allow(dead_code)]
    pub previous_tlc: Option<(Hash256, u64)>,
}

pub struct NetworkActor {}

#[derive(Debug)]
pub enum TlcActorMessage {
    Debug,
    CommandAddTlc(AddTlcCommand),
    CommandRemoveTlc(u64),
    PeerAddTlc(TlcInfo),
    PeerRemoveTlc(u64),
    PeerCommitmentSigned(Hash256),
    PeerRevokeAndAck(Hash256),
    //PeerRemoveTlc,
}

#[derive(Debug)]
pub enum NetworkActorMessage {
    RegisterPeer(String),
    AddTlc(String, AddTlcCommand),
    RemoveTlc(String, u64),
    PeerMsg(String, TlcActorMessage),
}

#[cfg_attr(target_arch="wasm32",async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl Actor for NetworkActor {
    type Msg = NetworkActorMessage;
    type State = NetworkActorState;
    type Arguments = ();

    async fn handle(
        &self,
        _myself: ActorRef<Self::Msg>,
        message: Self::Msg,
        state: &mut Self::State,
    ) -> Result<(), ActorProcessingErr> {
        match message {
            NetworkActorMessage::RegisterPeer(peer_id) => {
                state.add_peer(peer_id).await;
            }
            NetworkActorMessage::AddTlc(peer_id, add_tlc) => {
                eprintln!("NetworkActorMessage::AddTlc");
                if let Some(actor) = state.peers.get(&peer_id) {
                    actor
                        .send_message(TlcActorMessage::CommandAddTlc(add_tlc))
                        .expect("send ok");
                }
            }
            NetworkActorMessage::RemoveTlc(peer_id, tlc_id) => {
                if let Some(actor) = state.peers.get(&peer_id) {
                    actor
                        .send_message(TlcActorMessage::CommandRemoveTlc(tlc_id))
                        .expect("send ok");
                }
            }
            NetworkActorMessage::PeerMsg(peer_id, peer_msg) => {
                if let Some(actor) = state.peers.get(&peer_id) {
                    eprintln!("NetworkActorMessage::PeerMsg: {:?}", peer_msg);
                    actor.send_message(peer_msg).expect("send ok");
                }
            }
        }
        Ok(())
    }

    async fn pre_start(
        &self,
        myself: ActorRef<Self::Msg>,
        _args: Self::Arguments,
    ) -> Result<Self::State, ActorProcessingErr> {
        eprintln!("NetworkActor pre_start");
        Ok(NetworkActorState {
            peers: Default::default(),
            network: myself.clone(),
        })
    }
}

#[cfg_attr(target_arch="wasm32",async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl Actor for TlcActor {
    type Msg = TlcActorMessage;
    type State = TlcActorState;
    type Arguments = String;

    async fn handle(
        &self,
        _myself: ActorRef<Self::Msg>,
        message: Self::Msg,
        state: &mut Self::State,
    ) -> Result<(), ActorProcessingErr> {
        match message {
            TlcActorMessage::Debug => {
                eprintln!("Peer {} Debug", state.peer_id);
                for tlc in state.tlc_state.offered_tlcs.tlcs.iter() {
                    eprintln!("offered_tlc: {:?}", tlc.log());
                }
                for tlc in state.tlc_state.received_tlcs.tlcs.iter() {
                    eprintln!("received_tlc: {:?}", tlc.log());
                }
            }
            TlcActorMessage::CommandAddTlc(command) => {
                eprintln!(
                    "Peer {} TlcActorMessage::Command_AddTlc: {:?}",
                    state.peer_id, command
                );
                let next_offer_id = state.tlc_state.get_next_offering();
                let add_tlc = TlcInfo {
                    tlc_id: TLCId::Offered(next_offer_id),
                    amount: command.amount,
                    payment_hash: command.payment_hash,
                    attempt_id: command.attempt_id,
                    expiry: command.expiry,
                    hash_algorithm: command.hash_algorithm,
                    created_at: CommitmentNumbers::default(),
                    removed_reason: None,
                    onion_packet: command.onion_packet,
                    shared_secret: command.shared_secret,
                    forwarding_tlc: None,
                    status: TlcStatus::Outbound(OutboundTlcStatus::LocalAnnounced),
                    removed_confirmed_at: None,
                    applied_flags: AppliedFlags::empty(),
                    total_amount: None,
                    payment_secret: None,
                };
                state.tlc_state.add_offered_tlc(add_tlc.clone());
                state.tlc_state.increment_offering();
                let peer = state.get_peer();
                self.network
                    .send_message(NetworkActorMessage::PeerMsg(
                        peer.clone(),
                        TlcActorMessage::PeerAddTlc(add_tlc),
                    ))
                    .expect("send ok");

                // send commitment signed
                let tlcs = state.tlc_state.commitment_signed_tlcs(false);
                let hash = sign_tlcs(tlcs);
                eprintln!("got hash: {:?}", hash);
                self.network
                    .send_message(NetworkActorMessage::PeerMsg(
                        peer,
                        TlcActorMessage::PeerCommitmentSigned(hash),
                    ))
                    .expect("send ok");
            }
            TlcActorMessage::CommandRemoveTlc(tlc_id) => {
                eprintln!("Peer {} process remove tlc ....", state.peer_id);
                state.tlc_state.set_received_tlc_removed(
                    tlc_id,
                    RemoveTlcReason::RemoveTlcFulfill(RemoveTlcFulfill {
                        payment_preimage: Default::default(),
                    }),
                );
                let peer = state.get_peer();
                self.network
                    .send_message(NetworkActorMessage::PeerMsg(
                        peer.clone(),
                        TlcActorMessage::PeerRemoveTlc(tlc_id),
                    ))
                    .expect("send ok");

                // send commitment signed
                let tlcs = state.tlc_state.commitment_signed_tlcs(false);
                let hash = sign_tlcs(tlcs);
                eprintln!("got hash: {:?}", hash);
                self.network
                    .send_message(NetworkActorMessage::PeerMsg(
                        peer,
                        TlcActorMessage::PeerCommitmentSigned(hash),
                    ))
                    .expect("send ok");
            }
            TlcActorMessage::PeerAddTlc(add_tlc) => {
                eprintln!(
                    "Peer {} process peer add_tlc .... with tlc_id: {:?}",
                    state.peer_id, add_tlc.tlc_id
                );
                let mut tlc = add_tlc.clone();
                tlc.flip_mut();
                tlc.status = TlcStatus::Inbound(InboundTlcStatus::RemoteAnnounced);
                state.tlc_state.add_received_tlc(tlc);
                eprintln!("add peer tlc successfully: {:?}", add_tlc);
            }
            TlcActorMessage::PeerRemoveTlc(tlc_id) => {
                eprintln!(
                    "Peer {} process peer remove tlc .... with tlc_id: {}",
                    state.peer_id, tlc_id
                );
                dbg!("set offered tlc removed", &tlc_id);
                state.tlc_state.set_offered_tlc_removed(
                    tlc_id,
                    RemoveTlcReason::RemoveTlcFulfill(RemoveTlcFulfill {
                        payment_preimage: Default::default(),
                    }),
                );
            }
            TlcActorMessage::PeerCommitmentSigned(peer_hash) => {
                eprintln!(
                    "\nPeer {} processed peer commitment_signed ....",
                    state.peer_id
                );
                let tlcs = state.tlc_state.commitment_signed_tlcs(true);
                let hash = sign_tlcs(tlcs);
                assert_eq!(hash, peer_hash);

                let peer = state.get_peer();

                state.tlc_state.update_for_commitment_signed();

                eprintln!("sending peer revoke and ack ....");
                let tlcs = state.tlc_state.commitment_signed_tlcs(false);
                let hash = sign_tlcs(tlcs);
                self.network
                    .send_message(NetworkActorMessage::PeerMsg(
                        peer.clone(),
                        TlcActorMessage::PeerRevokeAndAck(hash),
                    ))
                    .expect("send ok");

                // send commitment signed from our side if necessary
                if state.tlc_state.need_another_commitment_signed() {
                    eprintln!("sending another commitment signed ....");
                    let tlcs = state.tlc_state.commitment_signed_tlcs(false);
                    let hash = sign_tlcs(tlcs);
                    self.network
                        .send_message(NetworkActorMessage::PeerMsg(
                            peer,
                            TlcActorMessage::PeerCommitmentSigned(hash),
                        ))
                        .expect("send ok");
                }
            }
            TlcActorMessage::PeerRevokeAndAck(peer_hash) => {
                eprintln!("Peer {} processed peer revoke and ack ....", state.peer_id);
                let tlcs = state.tlc_state.commitment_signed_tlcs(true);
                let hash = sign_tlcs(tlcs);
                assert_eq!(hash, peer_hash);

                state
                    .tlc_state
                    .update_for_revoke_and_ack(CommitmentNumbers::default());
            }
        }
        Ok(())
    }

    async fn pre_start(
        &self,
        _myself: ActorRef<Self::Msg>,
        args: Self::Arguments,
    ) -> Result<Self::State, ActorProcessingErr> {
        let peer_id = args;
        {
            Ok(TlcActorState {
                tlc_state: Default::default(),
                peer_id,
            })
        }
    }
}

#[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
async fn test_tlc_actor() {
    let (network_actor, _handle) = Actor::spawn(None, NetworkActor {}, ())
        .await
        .expect("Failed to start tlc actor");
    network_actor
        .send_message(NetworkActorMessage::RegisterPeer("peer_a".to_string()))
        .unwrap();
    network_actor
        .send_message(NetworkActorMessage::RegisterPeer("peer_b".to_string()))
        .unwrap();

    network_actor
        .send_message(NetworkActorMessage::AddTlc(
            "peer_a".to_string(),
            AddTlcCommand {
                amount: 10000,
                payment_hash: gen_rand_sha256_hash(),
                attempt_id: None,
                expiry: now_timestamp_as_millis_u64() + 1000,
                hash_algorithm: HashAlgorithm::Sha256,
                onion_packet: None,
                shared_secret: NO_SHARED_SECRET,
                previous_tlc: None,
            },
        ))
        .unwrap();

    ractor::concurrency::sleep(tokio::time::Duration::from_millis(1000)).await;

    network_actor
        .send_message(NetworkActorMessage::AddTlc(
            "peer_a".to_string(),
            AddTlcCommand {
                amount: 20000,
                payment_hash: gen_rand_sha256_hash(),
                attempt_id: None,
                expiry: now_timestamp_as_millis_u64() + 1000,
                hash_algorithm: HashAlgorithm::Sha256,
                onion_packet: None,
                shared_secret: NO_SHARED_SECRET,
                previous_tlc: None,
            },
        ))
        .unwrap();

    ractor::concurrency::sleep(tokio::time::Duration::from_millis(1000)).await;

    network_actor
        .send_message(NetworkActorMessage::AddTlc(
            "peer_b".to_string(),
            AddTlcCommand {
                amount: 30000,
                payment_hash: gen_rand_sha256_hash(),
                attempt_id: None,
                expiry: now_timestamp_as_millis_u64() + 1000,
                hash_algorithm: HashAlgorithm::Sha256,
                onion_packet: None,
                shared_secret: NO_SHARED_SECRET,
                previous_tlc: None,
            },
        ))
        .unwrap();

    ractor::concurrency::sleep(tokio::time::Duration::from_millis(1000)).await;

    network_actor
        .send_message(NetworkActorMessage::AddTlc(
            "peer_b".to_string(),
            AddTlcCommand {
                amount: 50000,
                payment_hash: gen_rand_sha256_hash(),
                attempt_id: None,
                expiry: now_timestamp_as_millis_u64() + 1000,
                hash_algorithm: HashAlgorithm::Sha256,
                onion_packet: None,
                shared_secret: NO_SHARED_SECRET,
                previous_tlc: None,
            },
        ))
        .unwrap();

    ractor::concurrency::sleep(tokio::time::Duration::from_millis(1000)).await;
    // remove tlc from peer_b
    network_actor
        .send_message(NetworkActorMessage::RemoveTlc("peer_b".to_string(), 0))
        .unwrap();

    ractor::concurrency::sleep(tokio::time::Duration::from_millis(1000)).await;
    network_actor
        .send_message(NetworkActorMessage::PeerMsg(
            "peer_a".to_string(),
            TlcActorMessage::Debug,
        ))
        .unwrap();

    ractor::concurrency::sleep(tokio::time::Duration::from_millis(100)).await;
    network_actor
        .send_message(NetworkActorMessage::PeerMsg(
            "peer_b".to_string(),
            TlcActorMessage::Debug,
        ))
        .unwrap();

    ractor::concurrency::sleep(tokio::time::Duration::from_millis(2000)).await;
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_tlc_state_v2() {
    let mut tlc_state = TlcState::default();
    let mut add_tlc1 = TlcInfo {
        amount: 10000,
        status: TlcStatus::Outbound(OutboundTlcStatus::LocalAnnounced),
        payment_hash: gen_rand_sha256_hash(),
        attempt_id: None,
        expiry: now_timestamp_as_millis_u64() + 1000,
        hash_algorithm: HashAlgorithm::Sha256,
        onion_packet: None,
        shared_secret: NO_SHARED_SECRET,
        tlc_id: TLCId::Offered(0),
        created_at: CommitmentNumbers::default(),
        removed_reason: None,
        forwarding_tlc: None,
        removed_confirmed_at: None,
        applied_flags: AppliedFlags::empty(),
        total_amount: None,
        payment_secret: None,
    };
    let mut add_tlc2 = TlcInfo {
        amount: 20000,
        status: TlcStatus::Outbound(OutboundTlcStatus::LocalAnnounced),
        payment_hash: gen_rand_sha256_hash(),
        attempt_id: None,
        expiry: now_timestamp_as_millis_u64() + 2000,
        hash_algorithm: HashAlgorithm::Sha256,
        onion_packet: None,
        shared_secret: NO_SHARED_SECRET,
        tlc_id: TLCId::Offered(1),
        created_at: CommitmentNumbers::default(),
        removed_reason: None,
        forwarding_tlc: None,
        removed_confirmed_at: None,
        applied_flags: AppliedFlags::empty(),
        total_amount: None,
        payment_secret: None,
    };
    tlc_state.add_offered_tlc(add_tlc1.clone());
    tlc_state.add_offered_tlc(add_tlc2.clone());

    let mut tlc_state_2 = TlcState::default();
    add_tlc1.flip_mut();
    add_tlc2.flip_mut();
    add_tlc1.status = TlcStatus::Inbound(InboundTlcStatus::RemoteAnnounced);
    add_tlc2.status = TlcStatus::Inbound(InboundTlcStatus::RemoteAnnounced);
    tlc_state_2.add_received_tlc(add_tlc1);
    tlc_state_2.add_received_tlc(add_tlc2);

    let hash1 = sign_tlcs(tlc_state.commitment_signed_tlcs(true));
    eprintln!("hash1: {:?}", hash1);

    let hash2 = sign_tlcs(tlc_state_2.commitment_signed_tlcs(false));
    eprintln!("hash2: {:?}", hash2);
    assert_eq!(hash1, hash2);
}

// ============================================================================
// Corner case tests for TlcState
// ============================================================================

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_tlc_state_empty() {
    let tlc_state = TlcState::default();

    // Verify empty state behavior
    assert_eq!(tlc_state.get_next_offering(), 0);
    assert_eq!(tlc_state.get_next_received(), 0);
    assert!(!tlc_state.waiting_ack);
    assert!(!tlc_state.need_another_commitment_signed());

    // Verify all_tlcs is empty
    assert_eq!(tlc_state.all_tlcs().count(), 0);

    // Verify commitment_signed_tlcs is empty
    assert_eq!(tlc_state.commitment_signed_tlcs(true).count(), 0);
    assert_eq!(tlc_state.commitment_signed_tlcs(false).count(), 0);

    // Verify get returns None for non-existent TLCs
    assert!(tlc_state.get(&TLCId::Offered(0)).is_none());
    assert!(tlc_state.get(&TLCId::Received(0)).is_none());
    assert!(tlc_state.get(&TLCId::Offered(u64::MAX)).is_none());
    assert!(tlc_state.get(&TLCId::Received(u64::MAX)).is_none());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_tlc_state_increment_ids() {
    let mut tlc_state = TlcState::default();

    // Test incrementing offering IDs
    assert_eq!(tlc_state.get_next_offering(), 0);
    tlc_state.increment_offering();
    assert_eq!(tlc_state.get_next_offering(), 1);
    tlc_state.increment_offering();
    assert_eq!(tlc_state.get_next_offering(), 2);

    // Test incrementing received IDs
    assert_eq!(tlc_state.get_next_received(), 0);
    tlc_state.increment_received();
    assert_eq!(tlc_state.get_next_received(), 1);
    tlc_state.increment_received();
    assert_eq!(tlc_state.get_next_received(), 2);

    // Verify independence of offered and received counters
    assert_eq!(tlc_state.get_next_offering(), 2);
    assert_eq!(tlc_state.get_next_received(), 2);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_tlc_state_waiting_ack_flag() {
    let mut tlc_state = TlcState::default();

    // Test setting waiting_ack
    assert!(!tlc_state.waiting_ack);
    tlc_state.set_waiting_ack(true);
    assert!(tlc_state.waiting_ack);
    tlc_state.set_waiting_ack(false);
    assert!(!tlc_state.waiting_ack);

    // Test toggle behavior
    tlc_state.set_waiting_ack(true);
    tlc_state.set_waiting_ack(true);
    assert!(tlc_state.waiting_ack);
}

fn create_test_tlc(id: u64, is_offered: bool, amount: u128) -> TlcInfo {
    TlcInfo {
        amount,
        status: if is_offered {
            TlcStatus::Outbound(OutboundTlcStatus::LocalAnnounced)
        } else {
            TlcStatus::Inbound(InboundTlcStatus::RemoteAnnounced)
        },
        payment_hash: gen_rand_sha256_hash(),
        attempt_id: None,
        expiry: now_timestamp_as_millis_u64() + 1000,
        hash_algorithm: HashAlgorithm::Sha256,
        onion_packet: None,
        shared_secret: NO_SHARED_SECRET,
        tlc_id: if is_offered {
            TLCId::Offered(id)
        } else {
            TLCId::Received(id)
        },
        created_at: CommitmentNumbers::default(),
        removed_reason: None,
        forwarding_tlc: None,
        removed_confirmed_at: None,
        applied_flags: AppliedFlags::empty(),
        total_amount: None,
        payment_secret: None,
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_tlc_state_add_and_get() {
    let mut tlc_state = TlcState::default();

    // Add an offered TLC
    let tlc1 = create_test_tlc(0, true, 10000);
    tlc_state.add_offered_tlc(tlc1.clone());

    // Verify we can get it back
    let got = tlc_state.get(&TLCId::Offered(0)).expect("should find tlc");
    assert_eq!(got.amount, 10000);
    assert_eq!(got.tlc_id, TLCId::Offered(0));

    // Add a received TLC
    let tlc2 = create_test_tlc(0, false, 20000);
    tlc_state.add_received_tlc(tlc2.clone());

    // Verify we can get both
    let got1 = tlc_state
        .get(&TLCId::Offered(0))
        .expect("should find offered tlc");
    let got2 = tlc_state
        .get(&TLCId::Received(0))
        .expect("should find received tlc");
    assert_eq!(got1.amount, 10000);
    assert_eq!(got2.amount, 20000);

    // Verify all_tlcs count
    assert_eq!(tlc_state.all_tlcs().count(), 2);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_tlc_state_apply_remove() {
    let mut tlc_state = TlcState::default();

    // Add multiple TLCs
    tlc_state.add_offered_tlc(create_test_tlc(0, true, 10000));
    tlc_state.add_offered_tlc(create_test_tlc(1, true, 20000));
    tlc_state.add_received_tlc(create_test_tlc(0, false, 30000));
    tlc_state.add_received_tlc(create_test_tlc(1, false, 40000));

    assert_eq!(tlc_state.all_tlcs().count(), 4);

    // Remove an offered TLC
    tlc_state.apply_remove_tlc(TLCId::Offered(0));
    assert_eq!(tlc_state.all_tlcs().count(), 3);
    assert!(tlc_state.get(&TLCId::Offered(0)).is_none());
    assert!(tlc_state.get(&TLCId::Offered(1)).is_some());

    // Remove a received TLC
    tlc_state.apply_remove_tlc(TLCId::Received(1));
    assert_eq!(tlc_state.all_tlcs().count(), 2);
    assert!(tlc_state.get(&TLCId::Received(1)).is_none());
    assert!(tlc_state.get(&TLCId::Received(0)).is_some());

    // Remove non-existent TLC (should be no-op)
    tlc_state.apply_remove_tlc(TLCId::Offered(999));
    assert_eq!(tlc_state.all_tlcs().count(), 2);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_tlc_state_get_mut() {
    let mut tlc_state = TlcState::default();

    // Add TLCs
    tlc_state.add_offered_tlc(create_test_tlc(0, true, 10000));
    tlc_state.add_received_tlc(create_test_tlc(0, false, 20000));

    // Modify offered TLC
    {
        let tlc = tlc_state
            .get_mut(&TLCId::Offered(0))
            .expect("should find tlc");
        tlc.amount = 15000;
    }

    // Verify modification
    let tlc = tlc_state.get(&TLCId::Offered(0)).expect("should find tlc");
    assert_eq!(tlc.amount, 15000);

    // Modify received TLC
    {
        let tlc = tlc_state
            .get_mut(&TLCId::Received(0))
            .expect("should find tlc");
        tlc.amount = 25000;
    }

    // Verify modification
    let tlc = tlc_state.get(&TLCId::Received(0)).expect("should find tlc");
    assert_eq!(tlc.amount, 25000);

    // get_mut on non-existent returns None
    assert!(tlc_state.get_mut(&TLCId::Offered(999)).is_none());
    assert!(tlc_state.get_mut(&TLCId::Received(999)).is_none());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_tlc_state_commitment_signed_tlcs_filtering() {
    let mut tlc_state = TlcState::default();

    // Add an offered TLC with LocalAnnounced status
    let mut tlc1 = create_test_tlc(0, true, 10000);
    tlc1.status = TlcStatus::Outbound(OutboundTlcStatus::LocalAnnounced);
    tlc_state.add_offered_tlc(tlc1);

    // Add an offered TLC with Committed status
    let mut tlc2 = create_test_tlc(1, true, 20000);
    tlc2.status = TlcStatus::Outbound(OutboundTlcStatus::Committed);
    tlc_state.add_offered_tlc(tlc2);

    // Add an offered TLC with RemoveAckConfirmed status (should be filtered out)
    let mut tlc3 = create_test_tlc(2, true, 30000);
    tlc3.status = TlcStatus::Outbound(OutboundTlcStatus::RemoveAckConfirmed);
    tlc_state.add_offered_tlc(tlc3);

    // For remote: LocalAnnounced should be included
    let for_remote: Vec<_> = tlc_state.commitment_signed_tlcs(true).collect();
    assert_eq!(for_remote.len(), 2); // LocalAnnounced and Committed

    // For local: LocalAnnounced should NOT be included
    let for_local: Vec<_> = tlc_state.commitment_signed_tlcs(false).collect();
    assert_eq!(for_local.len(), 1); // Only Committed
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_tlc_state_need_another_commitment_signed() {
    let mut tlc_state = TlcState::default();

    // Empty state: no commitment needed
    assert!(!tlc_state.need_another_commitment_signed());

    // Add committed TLC: still no commitment needed
    let mut tlc1 = create_test_tlc(0, true, 10000);
    tlc1.status = TlcStatus::Outbound(OutboundTlcStatus::Committed);
    tlc_state.add_offered_tlc(tlc1);
    assert!(!tlc_state.need_another_commitment_signed());

    // Add LocalAnnounced TLC: commitment needed
    let mut tlc2 = create_test_tlc(1, true, 20000);
    tlc2.status = TlcStatus::Outbound(OutboundTlcStatus::LocalAnnounced);
    tlc_state.add_offered_tlc(tlc2);
    assert!(tlc_state.need_another_commitment_signed());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_tlc_state_update_for_commitment_signed() {
    let mut tlc_state = TlcState::default();

    // Add RemoteAnnounced received TLC
    let mut tlc = create_test_tlc(0, false, 10000);
    tlc.status = TlcStatus::Inbound(InboundTlcStatus::RemoteAnnounced);
    tlc_state.add_received_tlc(tlc);

    // Without waiting_ack, should transition to AnnounceWaitAck
    tlc_state.set_waiting_ack(false);
    tlc_state.update_for_commitment_signed();

    let tlc = tlc_state.get(&TLCId::Received(0)).expect("should find tlc");
    assert_eq!(tlc.inbound_status(), InboundTlcStatus::AnnounceWaitAck);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_tlc_state_update_for_commitment_signed_with_waiting_ack() {
    let mut tlc_state = TlcState::default();

    // Add RemoteAnnounced received TLC
    let mut tlc = create_test_tlc(0, false, 10000);
    tlc.status = TlcStatus::Inbound(InboundTlcStatus::RemoteAnnounced);
    tlc_state.add_received_tlc(tlc);

    // With waiting_ack, should transition to AnnounceWaitPrevAck
    tlc_state.set_waiting_ack(true);
    tlc_state.update_for_commitment_signed();

    let tlc = tlc_state.get(&TLCId::Received(0)).expect("should find tlc");
    assert_eq!(tlc.inbound_status(), InboundTlcStatus::AnnounceWaitPrevAck);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_tlc_state_update_for_revoke_and_ack() {
    let mut tlc_state = TlcState::default();

    // Add LocalAnnounced offered TLC
    let mut tlc = create_test_tlc(0, true, 10000);
    tlc.status = TlcStatus::Outbound(OutboundTlcStatus::LocalAnnounced);
    tlc_state.add_offered_tlc(tlc);

    // After revoke and ack, should transition to Committed
    let mut commitment_numbers = CommitmentNumbers::default();
    commitment_numbers.increment_local();
    commitment_numbers.increment_remote();
    tlc_state.update_for_revoke_and_ack(commitment_numbers);

    let tlc = tlc_state.get(&TLCId::Offered(0)).expect("should find tlc");
    assert_eq!(tlc.outbound_status(), OutboundTlcStatus::Committed);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_tlc_state_get_expired_offered_tlcs() {
    let mut tlc_state = TlcState::default();
    let now = now_timestamp_as_millis_u64();

    // Add expired TLC (committed status, past expiry)
    let mut expired_tlc = create_test_tlc(0, true, 10000);
    expired_tlc.status = TlcStatus::Outbound(OutboundTlcStatus::Committed);
    expired_tlc.expiry = now - 1000; // Already expired
    tlc_state.add_offered_tlc(expired_tlc);

    // Add non-expired TLC
    let mut valid_tlc = create_test_tlc(1, true, 20000);
    valid_tlc.status = TlcStatus::Outbound(OutboundTlcStatus::Committed);
    valid_tlc.expiry = now + 10000; // Future expiry
    tlc_state.add_offered_tlc(valid_tlc);

    // Add LocalAnnounced TLC (should not be included even if expired)
    let mut local_announced = create_test_tlc(2, true, 30000);
    local_announced.status = TlcStatus::Outbound(OutboundTlcStatus::LocalAnnounced);
    local_announced.expiry = now - 1000; // Already expired
    tlc_state.add_offered_tlc(local_announced);

    let expired: Vec<_> = tlc_state.get_expired_offered_tlcs(now).collect();
    assert_eq!(expired.len(), 1);
    assert_eq!(expired[0].tlc_id, TLCId::Offered(0));
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_tlc_state_get_committed_received_tlcs() {
    let mut tlc_state = TlcState::default();

    // Add committed received TLC
    let mut committed_tlc = create_test_tlc(0, false, 10000);
    committed_tlc.status = TlcStatus::Inbound(InboundTlcStatus::Committed);
    tlc_state.add_received_tlc(committed_tlc);

    // Add remote announced TLC (not committed)
    let mut remote_announced = create_test_tlc(1, false, 20000);
    remote_announced.status = TlcStatus::Inbound(InboundTlcStatus::RemoteAnnounced);
    tlc_state.add_received_tlc(remote_announced);

    // Add locally removed TLC (not committed state anymore)
    let mut local_removed = create_test_tlc(2, false, 30000);
    local_removed.status = TlcStatus::Inbound(InboundTlcStatus::LocalRemoved);
    tlc_state.add_received_tlc(local_removed);

    let committed: Vec<_> = tlc_state.get_committed_received_tlcs().collect();
    assert_eq!(committed.len(), 1);
    assert_eq!(committed[0].tlc_id, TLCId::Received(0));
}

// ============================================================================
// Corner case tests for TLCId
// ============================================================================

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_tlc_id_basic_operations() {
    let offered = TLCId::Offered(42);
    let received = TLCId::Received(42);

    assert!(offered.is_offered());
    assert!(!offered.is_received());
    assert!(!received.is_offered());
    assert!(received.is_received());

    // Test conversion to u64
    assert_eq!(u64::from(offered), 42);
    assert_eq!(u64::from(received), 42);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_tlc_id_flip() {
    let offered = TLCId::Offered(42);
    let received = TLCId::Received(42);

    // Test flip (immutable)
    assert_eq!(offered.flip(), TLCId::Received(42));
    assert_eq!(received.flip(), TLCId::Offered(42));

    // Verify original is unchanged
    assert!(offered.is_offered());
    assert!(received.is_received());

    // Test flip_mut
    let mut id = TLCId::Offered(42);
    id.flip_mut();
    assert_eq!(id, TLCId::Received(42));
    id.flip_mut();
    assert_eq!(id, TLCId::Offered(42));
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_tlc_id_boundary_values() {
    // Test with 0
    let zero_offered = TLCId::Offered(0);
    let zero_received = TLCId::Received(0);
    assert_eq!(u64::from(zero_offered), 0);
    assert_eq!(u64::from(zero_received), 0);
    assert_eq!(zero_offered.flip(), TLCId::Received(0));

    // Test with u64::MAX
    let max_offered = TLCId::Offered(u64::MAX);
    let max_received = TLCId::Received(u64::MAX);
    assert_eq!(u64::from(max_offered), u64::MAX);
    assert_eq!(u64::from(max_received), u64::MAX);
    assert_eq!(max_offered.flip(), TLCId::Received(u64::MAX));
    assert_eq!(max_received.flip(), TLCId::Offered(u64::MAX));
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_tlc_id_ordering() {
    // Test ordering - Offered comes before Received with same id
    let offered_0 = TLCId::Offered(0);
    let offered_1 = TLCId::Offered(1);
    let received_0 = TLCId::Received(0);
    let received_1 = TLCId::Received(1);

    assert!(offered_0 < offered_1);
    assert!(received_0 < received_1);
    assert!(offered_0 < received_0); // Offered variant comes before Received
    assert!(offered_1 < received_0); // Offered variant comes before Received
}

// ============================================================================
// Corner case tests for TlcStatus
// ============================================================================

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_tlc_status_as_methods() {
    let outbound = TlcStatus::Outbound(OutboundTlcStatus::Committed);
    let inbound = TlcStatus::Inbound(InboundTlcStatus::Committed);

    assert_eq!(outbound.as_outbound_status(), OutboundTlcStatus::Committed);
    assert_eq!(inbound.as_inbound_status(), InboundTlcStatus::Committed);
}

// ============================================================================
// Corner case tests for CommitmentNumbers
// ============================================================================

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_commitment_numbers_default() {
    let cn = CommitmentNumbers::default();
    assert_eq!(cn.get_local(), 0);
    assert_eq!(cn.get_remote(), 0);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_commitment_numbers_increment() {
    let mut cn = CommitmentNumbers::default();

    cn.increment_local();
    assert_eq!(cn.get_local(), 1);
    assert_eq!(cn.get_remote(), 0);

    cn.increment_remote();
    assert_eq!(cn.get_local(), 1);
    assert_eq!(cn.get_remote(), 1);

    // Multiple increments
    for _ in 0..10 {
        cn.increment_local();
        cn.increment_remote();
    }
    assert_eq!(cn.get_local(), 11);
    assert_eq!(cn.get_remote(), 11);
}

// ============================================================================
// Corner case tests for AppliedFlags
// ============================================================================

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_applied_flags() {
    let empty = AppliedFlags::empty();
    assert!(!empty.contains(AppliedFlags::ADD));
    assert!(!empty.contains(AppliedFlags::REMOVE));

    let add_only = AppliedFlags::ADD;
    assert!(add_only.contains(AppliedFlags::ADD));
    assert!(!add_only.contains(AppliedFlags::REMOVE));

    let remove_only = AppliedFlags::REMOVE;
    assert!(!remove_only.contains(AppliedFlags::ADD));
    assert!(remove_only.contains(AppliedFlags::REMOVE));

    let both = AppliedFlags::ADD | AppliedFlags::REMOVE;
    assert!(both.contains(AppliedFlags::ADD));
    assert!(both.contains(AppliedFlags::REMOVE));

    // Test all() contains everything
    let all = AppliedFlags::all();
    assert!(all.contains(AppliedFlags::ADD));
    assert!(all.contains(AppliedFlags::REMOVE));
}

// ============================================================================
// Corner case tests for SettlementTlc
// ============================================================================

use crate::fiber::channel::SettlementTlc;
use crate::gen_rand_fiber_private_key;

fn create_test_settlement_tlc(offered: bool) -> SettlementTlc {
    let local_key = gen_rand_fiber_private_key();
    let remote_key = gen_rand_fiber_private_key().pubkey();
    let payment_hash = gen_rand_sha256_hash();

    SettlementTlc {
        tlc_id: if offered {
            TLCId::Offered(0)
        } else {
            TLCId::Received(0)
        },
        hash_algorithm: HashAlgorithm::Sha256,
        payment_amount: 10000,
        payment_hash,
        expiry: now_timestamp_as_millis_u64() + 1000 * 60 * 60, // 1 hour from now
        local_key,
        remote_key,
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_settlement_tlc_to_witness_offered() {
    let tlc = create_test_settlement_tlc(true);
    let witness_local = tlc.to_witness(false);
    let witness_remote = tlc.to_witness(true);

    // Witness should not be empty
    assert!(!witness_local.is_empty());
    assert!(!witness_remote.is_empty());

    // Witness for local and remote should be different (different key order)
    assert_ne!(witness_local, witness_remote);

    // First byte should encode hash algorithm and offered flag
    // For offered with Sha256: (HashAlgorithm::Sha256 as u8 << 1) + 0 = (1 << 1) + 0 = 2
    assert_eq!(witness_local[0], 2);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_settlement_tlc_to_witness_received() {
    let tlc = create_test_settlement_tlc(false);
    let witness_local = tlc.to_witness(false);
    let witness_remote = tlc.to_witness(true);

    // First byte should encode hash algorithm and offered flag
    // For received with Sha256: (HashAlgorithm::Sha256 as u8 << 1) + 1 = (1 << 1) + 1 = 3
    assert_eq!(witness_local[0], 3);
    assert_eq!(witness_remote[0], 3);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_settlement_tlc_to_witness_ckb_hash() {
    let local_key = gen_rand_fiber_private_key();
    let remote_key = gen_rand_fiber_private_key().pubkey();
    let payment_hash = gen_rand_sha256_hash();

    let tlc = SettlementTlc {
        tlc_id: TLCId::Offered(0),
        hash_algorithm: HashAlgorithm::CkbHash,
        payment_amount: 10000,
        payment_hash,
        expiry: now_timestamp_as_millis_u64() + 1000 * 60 * 60,
        local_key,
        remote_key,
    };

    let witness = tlc.to_witness(false);
    // For CkbHash offered: (HashAlgorithm::CkbHash as u8 << 1) + 0 = (0 << 1) + 0 = 0
    assert_eq!(witness[0], 0);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_settlement_tlc_local_pubkey_hash() {
    let tlc = create_test_settlement_tlc(true);
    let pubkey_hash = tlc.local_pubkey_hash();

    // Hash should be 20 bytes
    assert_eq!(pubkey_hash.len(), 20);

    // Same key should produce same hash
    let pubkey_hash2 = tlc.local_pubkey_hash();
    assert_eq!(pubkey_hash, pubkey_hash2);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_settlement_tlc_witness_contains_amount() {
    let local_key = gen_rand_fiber_private_key();
    let remote_key = gen_rand_fiber_private_key().pubkey();
    let payment_hash = gen_rand_sha256_hash();

    let tlc = SettlementTlc {
        tlc_id: TLCId::Offered(0),
        hash_algorithm: HashAlgorithm::Sha256,
        payment_amount: 0x123456789ABCDEF0u128,
        payment_hash,
        expiry: 1000000,
        local_key,
        remote_key,
    };

    let witness = tlc.to_witness(false);

    // Bytes 1-16 should contain the payment_amount in little-endian
    let amount_bytes = &witness[1..17];
    let amount = u128::from_le_bytes(amount_bytes.try_into().unwrap());
    assert_eq!(amount, 0x123456789ABCDEF0u128);
}

// ============================================================================
// Corner case tests for SettlementData
// ============================================================================

use crate::fiber::channel::SettlementData;

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_settlement_data_empty_tlcs() {
    let local_key = gen_rand_fiber_private_key();
    let remote_key = gen_rand_fiber_private_key().pubkey();

    let data = SettlementData {
        local_amount: 100000,
        remote_amount: 200000,
        tlcs: vec![],
    };

    let witness_local = data.to_witness(false, local_key.clone(), remote_key);
    let witness_remote = data.to_witness(true, local_key, remote_key);

    // First byte should be 0 (number of TLCs)
    assert_eq!(witness_local[0], 0);
    assert_eq!(witness_remote[0], 0);

    // Witnesses should be different due to different key order
    assert_ne!(witness_local, witness_remote);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_settlement_data_with_tlcs() {
    let local_key = gen_rand_fiber_private_key();
    let remote_key = gen_rand_fiber_private_key().pubkey();

    let tlc1 = create_test_settlement_tlc(true);
    let tlc2 = create_test_settlement_tlc(false);

    let data = SettlementData {
        local_amount: 100000,
        remote_amount: 200000,
        tlcs: vec![tlc1, tlc2],
    };

    let witness_local = data.to_witness(false, local_key.clone(), remote_key);
    let witness_remote = data.to_witness(true, local_key, remote_key);

    // First byte should be 2 (number of TLCs)
    assert_eq!(witness_local[0], 2);
    assert_eq!(witness_remote[0], 2);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_settlement_data_amounts_in_witness() {
    let local_key = gen_rand_fiber_private_key();
    let remote_key = gen_rand_fiber_private_key().pubkey();

    let data = SettlementData {
        local_amount: 0x1234567890ABCDEFu128,
        remote_amount: 0xFEDCBA0987654321u128,
        tlcs: vec![],
    };

    let witness = data.to_witness(false, local_key, remote_key);

    // For local witness: after TLC count (1 byte) and pubkey hash (20 bytes)
    // comes local_amount (16 bytes), then remote pubkey hash (20 bytes), then remote_amount (16 bytes)
    // Total layout: [tlc_count(1)] [local_pubkey_hash(20)] [local_amount(16)] [remote_pubkey_hash(20)] [remote_amount(16)]

    // Verify local_amount at offset 21 (after 1 + 20 bytes)
    let local_amount_bytes = &witness[21..37];
    let local_amount = u128::from_le_bytes(local_amount_bytes.try_into().unwrap());
    assert_eq!(local_amount, 0x1234567890ABCDEFu128);

    // Verify remote_amount at offset 57 (after 1 + 20 + 16 + 20 bytes)
    let remote_amount_bytes = &witness[57..73];
    let remote_amount = u128::from_le_bytes(remote_amount_bytes.try_into().unwrap());
    assert_eq!(remote_amount, 0xFEDCBA0987654321u128);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_settlement_data_serialization() {
    let tlc = create_test_settlement_tlc(true);
    let data = SettlementData {
        local_amount: 100000,
        remote_amount: 200000,
        tlcs: vec![tlc],
    };

    // Test serialization roundtrip
    let serialized = serde_json::to_string(&data).expect("serialize failed");
    let deserialized: SettlementData =
        serde_json::from_str(&serialized).expect("deserialize failed");
    assert_eq!(data, deserialized);
}

// ============================================================================
// Corner case tests for TlcInfo methods
// ============================================================================

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_tlc_info_log() {
    let tlc = create_test_tlc(42, true, 10000);
    let log_str = tlc.log();

    // Should contain TLC ID info
    assert!(log_str.contains("42"));
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_tlc_info_id() {
    let offered_tlc = create_test_tlc(42, true, 10000);
    let received_tlc = create_test_tlc(99, false, 20000);

    assert_eq!(offered_tlc.id(), 42);
    assert_eq!(received_tlc.id(), 99);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_tlc_info_is_offered_received() {
    let offered_tlc = create_test_tlc(0, true, 10000);
    let received_tlc = create_test_tlc(0, false, 10000);

    assert!(offered_tlc.is_offered());
    assert!(!offered_tlc.is_received());

    assert!(!received_tlc.is_offered());
    assert!(received_tlc.is_received());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_tlc_info_flip_mut() {
    let mut tlc = create_test_tlc(42, true, 10000);
    assert!(tlc.is_offered());

    tlc.flip_mut();
    assert!(tlc.is_received());
    assert_eq!(tlc.id(), 42); // ID should remain the same

    tlc.flip_mut();
    assert!(tlc.is_offered());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_tlc_info_is_fail_remove_confirmed() {
    let mut tlc = create_test_tlc(0, true, 10000);

    // Initially not removed
    assert!(!tlc.is_fail_remove_confirmed());

    // Set to removed with fail reason and proper status
    tlc.removed_reason = Some(RemoveTlcReason::RemoveTlcFail(
        crate::fiber::types::TlcErrPacket::new(
            crate::fiber::types::TlcErr::new(TlcErrorCode::TemporaryNodeFailure),
            &NO_SHARED_SECRET,
        ),
    ));
    // Must set status to one of the confirmed states
    tlc.status = TlcStatus::Outbound(OutboundTlcStatus::RemoveAckConfirmed);

    assert!(tlc.is_fail_remove_confirmed());

    // With fulfill reason, should return false
    let mut tlc2 = create_test_tlc(1, true, 10000);
    tlc2.removed_reason = Some(RemoveTlcReason::RemoveTlcFulfill(RemoveTlcFulfill {
        payment_preimage: gen_rand_sha256_hash(),
    }));
    tlc2.status = TlcStatus::Outbound(OutboundTlcStatus::RemoveAckConfirmed);

    assert!(!tlc2.is_fail_remove_confirmed());

    // Test with RemoveWaitAck status
    let mut tlc3 = create_test_tlc(2, true, 10000);
    tlc3.removed_reason = Some(RemoveTlcReason::RemoveTlcFail(
        crate::fiber::types::TlcErrPacket::new(
            crate::fiber::types::TlcErr::new(TlcErrorCode::TemporaryNodeFailure),
            &NO_SHARED_SECRET,
        ),
    ));
    tlc3.status = TlcStatus::Outbound(OutboundTlcStatus::RemoveWaitAck);

    assert!(tlc3.is_fail_remove_confirmed());

    // Test with inbound TLC
    let mut tlc4 = create_test_tlc(0, false, 10000);
    tlc4.removed_reason = Some(RemoveTlcReason::RemoveTlcFail(
        crate::fiber::types::TlcErrPacket::new(
            crate::fiber::types::TlcErr::new(TlcErrorCode::TemporaryNodeFailure),
            &NO_SHARED_SECRET,
        ),
    ));
    tlc4.status = TlcStatus::Inbound(InboundTlcStatus::RemoveAckConfirmed);

    assert!(tlc4.is_fail_remove_confirmed());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_tlc_info_get_htlc_type() {
    // HashAlgorithm: CkbHash = 0, Sha256 = 1
    // htlc_type = (hash_algorithm << 1) | (is_received ? 1 : 0)

    // Test offered TLC with SHA256
    let mut offered_sha256 = create_test_tlc(0, true, 10000);
    offered_sha256.hash_algorithm = HashAlgorithm::Sha256;
    // htlc_type = (1 << 1) | 0 = 2
    assert_eq!(offered_sha256.get_htlc_type(), 0b10);

    // Test received TLC with SHA256
    let mut received_sha256 = create_test_tlc(0, false, 10000);
    received_sha256.hash_algorithm = HashAlgorithm::Sha256;
    // htlc_type = (1 << 1) | 1 = 3
    assert_eq!(received_sha256.get_htlc_type(), 0b11);

    // Test offered TLC with CkbHash
    let mut offered_ckb = create_test_tlc(0, true, 10000);
    offered_ckb.hash_algorithm = HashAlgorithm::CkbHash;
    // htlc_type = (0 << 1) | 0 = 0
    assert_eq!(offered_ckb.get_htlc_type(), 0b00);

    // Test received TLC with CkbHash
    let mut received_ckb = create_test_tlc(0, false, 10000);
    received_ckb.hash_algorithm = HashAlgorithm::CkbHash;
    // htlc_type = (0 << 1) | 1 = 1
    assert_eq!(received_ckb.get_htlc_type(), 0b01);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_tlc_info_get_commitment_numbers() {
    let mut tlc = create_test_tlc(0, true, 10000);

    // Default commitment numbers
    let cn = tlc.get_commitment_numbers();
    assert_eq!(cn.get_local(), 0);
    assert_eq!(cn.get_remote(), 0);

    // Update commitment numbers
    tlc.created_at.increment_local();
    tlc.created_at.increment_remote();

    let cn = tlc.get_commitment_numbers();
    assert_eq!(cn.get_local(), 1);
    assert_eq!(cn.get_remote(), 1);
}

// ============================================================================
// Corner case tests for TlcKind (LocalTlcs/RemoteTlcs)
// ============================================================================

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_tlc_kind_iter_mut() {
    let mut tlc_state = TlcState::default();

    // Add some TLCs
    let tlc1 = create_test_tlc(0, true, 10000);
    let tlc2 = create_test_tlc(1, true, 20000);
    tlc_state.add_offered_tlc(tlc1);
    tlc_state.add_offered_tlc(tlc2);

    // Test iter_mut on local_tlcs
    let count = tlc_state.offered_tlcs.iter_mut().count();
    assert_eq!(count, 2);

    // Modify through iter_mut
    for tlc in tlc_state.offered_tlcs.iter_mut() {
        tlc.amount += 1000;
    }

    // Verify modifications
    let first = tlc_state.get(&TLCId::Offered(0)).unwrap();
    assert_eq!(first.amount, 11000);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_tlc_kind_get_next_id_and_increment() {
    let mut tlc_state = TlcState::default();

    // Initial next IDs should be 0
    assert_eq!(tlc_state.offered_tlcs.get_next_id(), 0);
    assert_eq!(tlc_state.received_tlcs.get_next_id(), 0);

    // Increment and verify
    tlc_state.offered_tlcs.increment_next_id();
    assert_eq!(tlc_state.offered_tlcs.get_next_id(), 1);

    tlc_state.received_tlcs.increment_next_id();
    tlc_state.received_tlcs.increment_next_id();
    assert_eq!(tlc_state.received_tlcs.get_next_id(), 2);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_tlc_state_info_and_debug() {
    let mut tlc_state = TlcState::default();

    // Add some TLCs
    let tlc1 = create_test_tlc(0, true, 10000);
    let tlc2 = create_test_tlc(1, true, 20000);
    tlc_state.add_offered_tlc(tlc1);
    tlc_state.add_offered_tlc(tlc2);

    // Test info() returns a non-empty string
    let info = tlc_state.info();
    assert!(!info.is_empty());

    // Test debug() doesn't panic (it prints via tracing)
    tlc_state.debug();
}

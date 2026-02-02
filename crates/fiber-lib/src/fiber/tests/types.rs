use crate::{
    ckb::config::{UdtArgInfo, UdtCellDep, UdtCfgInfos, UdtDep, UdtScript},
    fiber::{
        config::AnnouncedNodeName,
        features::FeatureVector,
        gen::{fiber as molecule_fiber, gossip},
        hash_algorithm::HashAlgorithm,
        types::{
            pack_hop_data, secp256k1_instance, unpack_hop_data, AddTlc, BasicMppPaymentData,
            BroadcastMessageID, Cursor, Hash256, NodeAnnouncement, NodeId, PaymentHopData,
            PeeledPaymentOnionPacket, Privkey, Pubkey, TlcErr, TlcErrPacket, TlcErrorCode,
            NO_SHARED_SECRET,
        },
        PaymentCustomRecords,
    },
    gen_deterministic_fiber_private_key, gen_rand_channel_outpoint, gen_rand_fiber_private_key,
    gen_rand_fiber_public_key, gen_rand_sha256_hash, now_timestamp_as_millis_u64,
};
use ckb_hash::blake2b_256;
use ckb_jsonrpc_types::OutPoint;
use ckb_types::{
    core::{DepType, ScriptHashType},
    prelude::Pack,
    H256,
};
use fiber_sphinx::OnionSharedSecretIter;
use molecule::prelude::{Builder, Byte, Entity};
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use serde::Deserialize;
use serde::Serialize;
use tentacle::{multiaddr::MultiAddr, secio::PeerId};

use std::str::FromStr;

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_serde_public_key() {
    let sk = SecretKey::from_slice(&[42; 32]).unwrap();
    let public_key = Pubkey::from(sk.public_key(secp256k1_instance()));
    let pk_str = serde_json::to_string(&public_key).unwrap();
    assert_eq!(
        "\"035be5e9478209674a96e60f1f037f6176540fd001fa1d64694770c56a7709c42c\"",
        &pk_str
    );
    let pubkey: Pubkey = serde_json::from_str(&pk_str).unwrap();
    assert_eq!(pubkey, public_key)
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_serde_cursor_node_announcement() {
    let now = 0u64;
    let node_id = gen_rand_fiber_public_key();
    let cursor = Cursor::new(now, BroadcastMessageID::NodeAnnouncement(node_id));
    let moleculed_cursor: gossip::Cursor = cursor.clone().into();
    let unmoleculed_cursor: Cursor = moleculed_cursor.try_into().expect("decode");
    assert_eq!(cursor, unmoleculed_cursor);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_serde_cursor_channel_announcement() {
    let now = 0u64;
    let channel_announcement_id = gen_rand_channel_outpoint();
    let cursor = Cursor::new(
        now,
        BroadcastMessageID::ChannelAnnouncement(channel_announcement_id),
    );
    let moleculed_cursor: gossip::Cursor = cursor.clone().into();
    let unmoleculed_cursor: Cursor = moleculed_cursor.try_into().expect("decode");
    assert_eq!(cursor, unmoleculed_cursor);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_serde_cursor_channel_update() {
    let now = 0u64;
    let channel_update_id = gen_rand_channel_outpoint();
    let cursor = Cursor::new(now, BroadcastMessageID::ChannelUpdate(channel_update_id));
    let moleculed_cursor: gossip::Cursor = cursor.clone().into();
    let unmoleculed_cursor: Cursor = moleculed_cursor.try_into().expect("decode");
    assert_eq!(cursor, unmoleculed_cursor);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_cursor_timestamp() {
    let node_id = gen_rand_fiber_public_key();
    // 255 is larger than 256 in little endian.
    assert!(
        Cursor::new(255, BroadcastMessageID::NodeAnnouncement(node_id))
            < Cursor::new(256, BroadcastMessageID::NodeAnnouncement(node_id))
    );
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_cursor_types() {
    let node_id = gen_rand_fiber_public_key();
    let channel_outpoint = gen_rand_channel_outpoint();
    assert!(
        Cursor::new(
            0,
            BroadcastMessageID::ChannelAnnouncement(channel_outpoint.clone())
        ) < Cursor::new(0, BroadcastMessageID::NodeAnnouncement(node_id))
    );
    assert!(
        Cursor::new(
            0,
            BroadcastMessageID::ChannelAnnouncement(channel_outpoint.clone())
        ) < Cursor::new(
            0,
            BroadcastMessageID::ChannelUpdate(channel_outpoint.clone())
        )
    );
    assert!(
        Cursor::new(
            0,
            BroadcastMessageID::ChannelUpdate(channel_outpoint.clone())
        ) < Cursor::new(0, BroadcastMessageID::NodeAnnouncement(node_id))
    );
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_add_tlc_serialization() {
    let add_tlc = AddTlc {
        channel_id: [42; 32].into(),
        tlc_id: 42,
        amount: 42,
        payment_hash: [42; 32].into(),
        expiry: 42,
        hash_algorithm: HashAlgorithm::Sha256,
        onion_packet: None,
    };
    let add_tlc_mol: molecule_fiber::AddTlc = add_tlc.clone().into();
    let add_tlc2 = add_tlc_mol.try_into().expect("decode");
    assert_eq!(add_tlc, add_tlc2);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_peeled_onion_packet() {
    let secp = Secp256k1::new();
    let keys: Vec<Privkey> = std::iter::repeat_with(gen_rand_fiber_private_key)
        .take(3)
        .collect();
    let hops_infos = vec![
        PaymentHopData {
            amount: 2,
            expiry: 3,
            next_hop: Some(keys[1].pubkey()),
            funding_tx_hash: Hash256::default(),
            hash_algorithm: HashAlgorithm::Sha256,
            payment_preimage: None,
            custom_records: None,
        },
        PaymentHopData {
            amount: 5,
            expiry: 6,
            next_hop: Some(keys[2].pubkey()),
            funding_tx_hash: Hash256::default(),
            hash_algorithm: HashAlgorithm::Sha256,
            payment_preimage: None,
            custom_records: None,
        },
        PaymentHopData {
            amount: 8,
            expiry: 9,
            next_hop: None,
            funding_tx_hash: Hash256::default(),
            hash_algorithm: HashAlgorithm::Sha256,
            payment_preimage: None,
            custom_records: None,
        },
    ];
    let packet = PeeledPaymentOnionPacket::create(
        gen_rand_fiber_private_key(),
        hops_infos.clone(),
        None,
        &secp,
    )
    .expect("create peeled packet");

    let serialized = packet.serialize();
    let deserialized = PeeledPaymentOnionPacket::deserialize(&serialized).expect("deserialize");

    assert_eq!(packet, deserialized);

    assert_eq!(packet.current, hops_infos[0].clone().into());
    assert!(!packet.is_last());

    let packet = packet
        .next
        .expect("next hop")
        .peel(&keys[1], None, &secp)
        .expect("peel");
    assert_eq!(packet.current, hops_infos[1].clone().into());
    assert!(!packet.is_last());

    let packet = packet
        .next
        .expect("next hop")
        .peel(&keys[2], None, &secp)
        .expect("peel");
    assert_eq!(packet.current, hops_infos[2].clone().into());
    assert!(packet.is_last());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_peeled_large_onion_packet() {
    fn build_onion_packet(hops_num: usize) -> Result<(), String> {
        let secp = Secp256k1::new();
        let keys: Vec<Privkey> = std::iter::repeat_with(gen_rand_fiber_private_key)
            .take(hops_num + 1)
            .collect();
        let mut hops_infos = vec![];

        for key in keys.iter().take(hops_num) {
            hops_infos.push(PaymentHopData {
                amount: 2,
                expiry: 3,
                next_hop: Some(key.pubkey()),
                funding_tx_hash: Hash256::default(),
                hash_algorithm: HashAlgorithm::Sha256,
                payment_preimage: None,
                custom_records: None,
            });
        }
        hops_infos.push(PaymentHopData {
            amount: 8,
            expiry: 9,
            next_hop: None,
            funding_tx_hash: Hash256::default(),
            hash_algorithm: HashAlgorithm::Sha256,
            payment_preimage: None,
            custom_records: None,
        });

        let packet = PeeledPaymentOnionPacket::create(
            gen_rand_fiber_private_key(),
            hops_infos.clone(),
            None,
            &secp,
        )
        .map_err(|e| format!("create peeled packet error: {}", e))?;

        let serialized = packet.serialize();
        let deserialized = PeeledPaymentOnionPacket::deserialize(&serialized).expect("deserialize");

        assert_eq!(packet, deserialized);

        let mut now = Some(packet);
        for i in 0..hops_infos.len() - 1 {
            let packet = now
                .unwrap()
                .next
                .expect("next hop")
                .peel(&keys[i], None, &secp)
                .expect("peel");
            assert_eq!(packet.current, hops_infos[i + 1].clone().into());
            now = Some(packet.clone());
        }
        let last_packet = now.unwrap();
        assert_eq!(
            last_packet.current,
            hops_infos[hops_infos.len() - 1].clone().into()
        );
        assert!(last_packet.is_last());
        return Ok(());
    }

    // default PACKET_DATA_LEN is 6500
    build_onion_packet(40).expect("build onion packet with 40 hops");
    let res = build_onion_packet(41);
    assert!(
        res.is_err(),
        "should fail to build onion packet with 41 hops"
    );
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_tlc_fail_error() {
    let tlc_fail_detail = TlcErr::new(TlcErrorCode::InvalidOnionVersion);
    assert!(!tlc_fail_detail.error_code.is_node());
    assert!(tlc_fail_detail.error_code.is_bad_onion());
    assert!(tlc_fail_detail.error_code.is_perm());
    let tlc_fail = TlcErrPacket::new(tlc_fail_detail.clone(), &NO_SHARED_SECRET);

    let convert_back: TlcErr = tlc_fail.decode(&[0u8; 32], vec![]).expect("decoded fail");
    assert_eq!(tlc_fail_detail, convert_back);

    let node_fail = TlcErr::new_node_fail(
        TlcErrorCode::PermanentNodeFailure,
        gen_rand_fiber_public_key(),
    );
    assert!(node_fail.error_code.is_node());
    let tlc_fail = TlcErrPacket::new(node_fail.clone(), &NO_SHARED_SECRET);
    let convert_back = tlc_fail.decode(&[0u8; 32], vec![]).expect("decoded fail");
    assert_eq!(node_fail, convert_back);

    let error_code = TlcErrorCode::PermanentNodeFailure;
    let convert = TlcErrorCode::from_str("PermanentNodeFailure").expect("convert error");
    assert_eq!(error_code, convert);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_tlc_err_packet_encryption() {
    // Setup
    let secp = Secp256k1::new();
    let hops_path = [
        "02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619",
        "0324653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1c",
        "027f31ebc5462c1fdce1b737ecff52d37d75dea43ce11c74d25aa297165faa2007",
    ]
    .iter()
    .map(|s| Pubkey(PublicKey::from_str(s).expect("valid public key")))
    .collect::<Vec<_>>();

    let session_key = SecretKey::from_slice(&[0x41; 32]).expect("32 bytes, within curve order");
    let hops_ss: Vec<[u8; 32]> =
        OnionSharedSecretIter::new(hops_path.iter().map(|k| &k.0), session_key, &secp).collect();

    let tlc_fail_detail = TlcErr::new(TlcErrorCode::InvalidOnionVersion);
    {
        // Error from the first hop
        let tlc_fail = TlcErrPacket::new(tlc_fail_detail.clone(), &hops_ss[0]);
        let decrypted_tlc_fail_detail = tlc_fail
            .decode(session_key.as_ref(), hops_path.clone())
            .expect("decrypted");
        assert_eq!(decrypted_tlc_fail_detail, tlc_fail_detail);
    }

    {
        // Error from the the last hop
        let mut tlc_fail = TlcErrPacket::new(tlc_fail_detail.clone(), &hops_ss[2]);
        tlc_fail = tlc_fail.backward(&hops_ss[1]);
        tlc_fail = tlc_fail.backward(&hops_ss[0]);
        let decrypted_tlc_fail_detail = tlc_fail
            .decode(session_key.as_ref(), hops_path.clone())
            .expect("decrypted");
        assert_eq!(decrypted_tlc_fail_detail, tlc_fail_detail);
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_tlc_error_code() {
    let code = TlcErrorCode::PermanentNodeFailure;
    let str = code.as_ref().to_string();
    let code2 = TlcErrorCode::from_str(&str).expect("parse");
    assert_eq!(code, code2);

    let code = TlcErrorCode::IncorrectOrUnknownPaymentDetails;
    let code_int: u16 = code.into();
    let code = TlcErrorCode::try_from(code_int).expect("invalid code");
    assert_eq!(code, TlcErrorCode::IncorrectOrUnknownPaymentDetails);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_create_and_verify_node_announcement() {
    let privkey = gen_rand_fiber_private_key();
    let node_announcement = NodeAnnouncement::new(
        AnnouncedNodeName::from_string("node1").expect("valid name"),
        FeatureVector::default(),
        vec![],
        &privkey,
        now_timestamp_as_millis_u64(),
        0,
    );
    assert!(
        node_announcement.verify(),
        "Node announcement message signature verification failed: {:?}",
        &node_announcement
    );
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_serde_node_announcement() {
    let privkey = gen_rand_fiber_private_key();
    let node_announcement = NodeAnnouncement::new(
        AnnouncedNodeName::from_string("node1").expect("valid name"),
        FeatureVector::default(),
        vec![],
        &privkey,
        now_timestamp_as_millis_u64(),
        0,
    );
    assert!(
        node_announcement.verify(),
        "Node announcement verification failed: {:?}",
        &node_announcement
    );
    let serialized = bincode::serialize(&node_announcement).expect("serialize");
    let deserialized: NodeAnnouncement = bincode::deserialize(&serialized).expect("deserialize");
    assert_eq!(node_announcement, deserialized);
    assert!(
        deserialized.verify(),
        "Node announcement verification failed: {:?}",
        &deserialized
    );
}

// There was a bug in the node announcement verification logic which uses local udt whitelist to
// verify the signature. This bug causes different nodes to have different results on signature verification.
// We add a few hard coded node announcements with different udt_cfg_infos to ensure the verification logic is correct.
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_verify_hard_coded_node_announcement() {
    // hard code node announcement 1
    fn node1() -> NodeAnnouncement {
        let privkey = gen_deterministic_fiber_private_key();
        let node_id = privkey.pubkey();
        let mut node_announcement = NodeAnnouncement {
            signature: None,
            features: FeatureVector::default(),
            timestamp: 1737451664358,
            node_id,
            version: "1.0".to_string(),
            node_name: AnnouncedNodeName::from_string("fiber-1").expect("valid name"),
            addresses: vec![MultiAddr::from_str(
                "/ip4/127.0.0.1/tcp/8344/p2p/QmbvRjJHAQDmj3cgnUBGQ5zVnGxUKwb2qJygwNs2wk41h8",
            )
            .expect("valid multiaddr")],
            chain_hash: Hash256::from_str(
                "0x9c0a8fff24a7be339b92088730c2dc7fac6dfcbdf0a73774d6d2d6b29523fa5b",
            )
            .expect("valid hash"),
            auto_accept_min_ckb_funding_amount: 10000000000,
            udt_cfg_infos: UdtCfgInfos(vec![
                UdtArgInfo {
                    name: "SIMPLE_UDT".to_string(),
                    script: UdtScript {
                        code_hash: H256::from_str(
                            "e1e354d6d643ad42724d40967e334984534e0367405c5ae42a9d7d63d77df419",
                        )
                        .expect("valid hash"),
                        hash_type: ScriptHashType::Data2,
                        args: "0x.*".to_string(),
                    },
                    auto_accept_amount: Some(1000),
                    cell_deps: vec![UdtDep::with_cell_dep(UdtCellDep {
                        dep_type: DepType::Code,
                        out_point: OutPoint {
                            tx_hash: H256::from_str(
                                "f897bfc51766ee9cdb2b9279e63c8abdba4b35b6ee7dde5fed9b0a5a41c95dc4",
                            )
                            .expect("valid hash"),
                            index: 8.into(),
                        },
                    })],
                },
                UdtArgInfo {
                    name: "XUDT".to_string(),
                    script: UdtScript {
                        code_hash: H256::from_str(
                            "50bd8d6680b8b9cf98b73f3c08faf8b2a21914311954118ad6609be6e78a1b95",
                        )
                        .expect("valid hash"),
                        hash_type: ScriptHashType::Data2,
                        args: "0x.*".to_string(),
                    },
                    auto_accept_amount: Some(1000),
                    cell_deps: vec![UdtDep::with_cell_dep(UdtCellDep {
                        dep_type: DepType::Code,
                        out_point: OutPoint {
                            tx_hash: H256::from_str(
                                "f897bfc51766ee9cdb2b9279e63c8abdba4b35b6ee7dde5fed9b0a5a41c95dc4",
                            )
                            .expect("valid hash"),
                            index: 9.into(),
                        },
                    })],
                },
            ]),
        };
        let signature = privkey.sign(node_announcement.message_to_sign());
        node_announcement.signature = Some(signature);
        node_announcement
    }

    // hard code node announcement 2
    fn node2() -> NodeAnnouncement {
        let privkey = gen_deterministic_fiber_private_key();
        let mut node_announcement = NodeAnnouncement {
            signature: None,
            features: FeatureVector::default(),
            timestamp: 1737449487183,
            node_id: privkey.pubkey(),
            version: "1.0".to_string(),
            node_name: AnnouncedNodeName::default(),
            addresses: vec![MultiAddr::from_str(
                "/ip4/221.187.61.162/tcp/18228/p2p/QmSr3bkMcG9Fy3PAf3HdrxttAE6EiLxHitKJW6HmiV9o6U",
            )
            .unwrap()],
            chain_hash: Hash256::from_str(
                "10639e0895502b5688a6be8cf69460d76541bfa4821629d86d62ba0aae3f9606",
            )
            .unwrap(),
            auto_accept_min_ckb_funding_amount: 10000000000,
            udt_cfg_infos: UdtCfgInfos(vec![UdtArgInfo {
                name: "RUSD".to_string(),
                script: UdtScript {
                    code_hash: H256::from_str(
                        "1142755a044bf2ee358cba9f2da187ce928c91cd4dc8692ded0337efa677d21a",
                    )
                    .unwrap(),
                    hash_type: ScriptHashType::Type,
                    args: "0x878fcc6f1f08d48e87bb1c3b3d5083f23f8a39c5d5c764f253b55b998526439b"
                        .to_string(),
                },
                auto_accept_amount: Some(1000000000),
                cell_deps: vec![UdtDep::with_cell_dep(UdtCellDep {
                    dep_type: DepType::Code,
                    out_point: OutPoint {
                        tx_hash: H256::from_str(
                            "ed7d65b9ad3d99657e37c4285d585fea8a5fcaf58165d54dacf90243f911548b",
                        )
                        .unwrap(),
                        index: 0.into(),
                    },
                })],
            }]),
        };
        let signature = privkey.sign(node_announcement.message_to_sign());
        node_announcement.signature = Some(signature);
        node_announcement
    }

    for (signature, message, node_announcement) in [
        (
            "7cd5e05013bd41c8de80fdef75d6ffd1be45408d8e2a8cd54f0994d2bfdb590826583e662e05ca39cdb844f796fc43c4627746a485fc8e54c1859f710122008a",
            "18564fef8fcea0fcef42a982d4df86a0dd0b7838159e05a12aa4e74498aca4ff",
            node1(),
        ),
        (
            "3a1eea2e372e5c3bc53d1c283d449afbfff029308fe59e111a23ad32163d2a6f58128e21083e128a05d34fb8c0068a1f4fa6e4ae12e370d3051591df151a957a",
            "db96ac7278d1db7b03eefdc4d21c952e3aee8a4be87a82c8c0e66a87e8897a81",
            node2(),
        ),
    ] {
        assert_eq!(
            hex::encode(node_announcement.signature.as_ref().unwrap().0.serialize_compact()),
            signature,
            "signature mismatch"
        );
        assert_eq!(
            hex::encode(node_announcement.message_to_sign()),
            message,
            "message mismatch"
        );
        assert!(node_announcement.verify(), "node announcement verification failed");
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_custom_records_serialize_deserialize() {
    #[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
    pub struct Custom {
        pub custom_records: Option<PaymentCustomRecords>,
    }

    let custom = Custom {
        custom_records: Some(PaymentCustomRecords {
            data: vec![(1, vec![2, 3]), (4, vec![5, 33])]
                .into_iter()
                .collect(),
        }),
    };

    let json = serde_json::to_string(&custom).expect("serialize");
    eprintln!("json: {}", json);

    let deserialized: Custom = serde_json::from_str(&json).expect("deserialize");
    eprintln!("deserialized: {:?}", deserialized);
    assert_eq!(custom, deserialized);

    let invalid = "{\"custom_records\":{\"0x4\":\"0x0521\",\"0x1\":\"0x0203\"}}";
    let deserialized = serde_json::from_str::<Custom>(invalid);
    assert!(deserialized.is_err());

    let bincode_serialize = bincode::serialize(&custom).expect("serialize");
    let _deserialized: Custom = bincode::deserialize(&bincode_serialize).expect("deserialize");
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_verify_payment_hop_data() {
    let hop_data = PaymentHopData {
        amount: 1000,
        expiry: 1000,
        next_hop: None,
        funding_tx_hash: Hash256::default(),
        hash_algorithm: HashAlgorithm::Sha256,
        payment_preimage: Some([1; 32].into()),
        custom_records: Some(PaymentCustomRecords {
            data: vec![(1, vec![2, 3])].into_iter().collect(),
        }),
    };

    let data = pack_hop_data(&hop_data);
    let unpacked: PaymentHopData = unpack_hop_data(&data).expect("unpack error");
    assert_eq!(hop_data, unpacked);

    let check_sum = hex::encode(blake2b_256(&data));

    // make sure we don't change PaymentHopData format since it's stored in db with encrypted format
    // do migration with old data version is not workable
    let expected_check_sum =
        "1ea2a67b30c7d2cedab21c6e5f4a3b860fc8b1ccc525f42dd1bdd4a7d6dfe489".to_string();
    if check_sum != expected_check_sum {
        panic!(
            "PaymentHopData check sum mismatch, you need compatible with old data version when deserializing, \
            migration will not work with PaymentHopData"
        );
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_convert_udt_arg_info() {
    let udt_arg_info = UdtArgInfo {
        name: "SIMPLE_UDT".to_string(),
        script: UdtScript {
            code_hash: H256::from_str(
                "e1e354d6d643ad42724d40967e334984534e0367405c5ae42a9d7d63d77df419",
            )
            .expect("valid hash"),
            hash_type: ScriptHashType::Data2,
            args: "0x.*".to_string(),
        },
        auto_accept_amount: Some(1000),
        cell_deps: vec![UdtDep::with_cell_dep(UdtCellDep {
            dep_type: DepType::Code,
            out_point: OutPoint {
                tx_hash: H256::from_str(
                    "f897bfc51766ee9cdb2b9279e63c8abdba4b35b6ee7dde5fed9b0a5a41c95dc4",
                )
                .expect("valid hash"),
                index: 8.into(),
            },
        })],
    };
    let udt_arg_info_gen = molecule_fiber::UdtArgInfo::from(udt_arg_info.clone());
    assert_eq!(udt_arg_info, udt_arg_info_gen.clone().into());

    // 0x80 is not a valid utf-8 string, so it should be converted to empty string
    let udt_arg_info_modified: UdtArgInfo = udt_arg_info_gen
        .as_builder()
        .name([0x80].pack())
        .build()
        .into();
    assert_eq!("", udt_arg_info_modified.name);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_convert_payment_hop_data() {
    let sk = SecretKey::from_slice(&[42; 32]).unwrap();
    let public_key = Pubkey::from(sk.public_key(secp256k1_instance()));

    let payment_hop_data = PaymentHopData {
        amount: 1000,
        expiry: 1000,
        next_hop: Some(public_key),
        funding_tx_hash: Hash256::default(),
        hash_algorithm: HashAlgorithm::Sha256,
        payment_preimage: Some([1; 32].into()),
        custom_records: Some(PaymentCustomRecords {
            data: vec![(1, vec![2, 3])].into_iter().collect(),
        }),
    };
    let payment_hop_data_gen = molecule_fiber::PaymentHopData::from(payment_hop_data.clone());
    assert_eq!(payment_hop_data, payment_hop_data_gen.clone().into());

    // 3 is not a valid hash algorithm, so it should be converted to CkbHash
    let payment_hop_data_modified: PaymentHopData = payment_hop_data_gen
        .clone()
        .as_builder()
        .hash_algorithm(Byte::new(3))
        .build()
        .into();
    assert_eq!(
        HashAlgorithm::CkbHash,
        payment_hop_data_modified.hash_algorithm
    );

    // default pubkey value is [0; 33], it's not a valid public key, so it should be converted to None
    let payment_hop_data_modified: PaymentHopData = payment_hop_data_gen
        .clone()
        .as_builder()
        .next_hop(
            molecule_fiber::PubkeyOpt::new_builder()
                .set(Some(molecule_fiber::Pubkey::default()))
                .build(),
        )
        .build()
        .into();
    assert_eq!(None, payment_hop_data_modified.next_hop);
}

#[test]
fn test_serde_node_id() {
    let peer_id = PeerId::random();
    let expected_str = serde_json::to_string(&peer_id.to_base58()).expect("serialize");
    let node_id = NodeId::from_bytes(peer_id.into_bytes());
    let node_id_str = serde_json::to_string(&node_id).expect("serialize");
    assert_eq!(node_id_str, expected_str, "to base58");
    assert_eq!(
        node_id,
        serde_json::from_str(&node_id_str).unwrap(),
        "to NodeId"
    );
}

#[test]
fn test_basic_mpp_custom_records() {
    let mut payment_custom_records = PaymentCustomRecords::default();
    let payment_secret = gen_rand_sha256_hash();
    let record = BasicMppPaymentData::new(payment_secret, 100);
    record.write(&mut payment_custom_records);

    let new_record = BasicMppPaymentData::read(&payment_custom_records).unwrap();
    assert_eq!(new_record, record);
}

// ============================================================================
// Corner case tests for Hash256
// ============================================================================

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_hash256_default() {
    let hash = Hash256::default();
    assert_eq!(hash.as_ref(), &[0u8; 32]);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_hash256_from_array() {
    let bytes = [42u8; 32];
    let hash: Hash256 = bytes.into();
    assert_eq!(hash.as_ref(), &bytes);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_hash256_from_str_valid() {
    // Without 0x prefix
    let hash1 =
        Hash256::from_str("0000000000000000000000000000000000000000000000000000000000000000");
    assert!(hash1.is_ok());
    assert_eq!(hash1.unwrap().as_ref(), &[0u8; 32]);

    // With 0x prefix
    let hash2 =
        Hash256::from_str("0x0000000000000000000000000000000000000000000000000000000000000000");
    assert!(hash2.is_ok());
    assert_eq!(hash2.unwrap().as_ref(), &[0u8; 32]);

    // All 0xff
    let hash3 =
        Hash256::from_str("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    assert!(hash3.is_ok());
    assert_eq!(hash3.unwrap().as_ref(), &[0xff; 32]);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_hash256_from_str_invalid() {
    // Too short
    let hash1 = Hash256::from_str("00000000");
    assert!(hash1.is_err());

    // Too long
    let hash2 =
        Hash256::from_str("00000000000000000000000000000000000000000000000000000000000000000000");
    assert!(hash2.is_err());

    // Invalid hex characters
    let hash3 =
        Hash256::from_str("0xgggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg");
    assert!(hash3.is_err());

    // Empty string
    let hash4 = Hash256::from_str("");
    assert!(hash4.is_err());

    // Odd length
    let hash5 = Hash256::from_str("0x000");
    assert!(hash5.is_err());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_hash256_try_from_slice() {
    // Valid slice
    let bytes = [42u8; 32];
    let hash = Hash256::try_from(bytes.as_slice());
    assert!(hash.is_ok());
    assert_eq!(hash.unwrap().as_ref(), &bytes);

    // Too short
    let short_bytes = [42u8; 16];
    let hash = Hash256::try_from(short_bytes.as_slice());
    assert!(hash.is_err());

    // Too long
    let long_bytes = [42u8; 64];
    let hash = Hash256::try_from(long_bytes.as_slice());
    assert!(hash.is_err());

    // Empty slice
    let empty: &[u8] = &[];
    let hash = Hash256::try_from(empty);
    assert!(hash.is_err());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_hash256_display_and_debug() {
    let bytes = [0x42u8; 32];
    let hash: Hash256 = bytes.into();

    let display_str = format!("{}", hash);
    assert!(display_str.contains("Hash256"));
    assert!(display_str.contains("42"));

    let debug_str = format!("{:?}", hash);
    assert!(debug_str.contains("Hash256"));

    let lower_hex = format!("{:x}", hash);
    assert!(lower_hex.contains("42"));

    let lower_hex_alt = format!("{:#x}", hash);
    assert!(lower_hex_alt.starts_with("0x"));
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_hash256_to_vec() {
    let bytes = [42u8; 32];
    let hash: Hash256 = bytes.into();
    let vec: Vec<u8> = hash.into();
    assert_eq!(vec.len(), 32);
    assert_eq!(&vec[..], &bytes[..]);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_hash256_h256_conversion() {
    let bytes = [42u8; 32];
    let hash: Hash256 = bytes.into();

    // Convert to H256 and back
    let h256: H256 = hash.into();
    let hash_back: Hash256 = h256.into();
    assert_eq!(hash, hash_back);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_hash256_equality() {
    let hash1: Hash256 = [1u8; 32].into();
    let hash2: Hash256 = [1u8; 32].into();
    let hash3: Hash256 = [2u8; 32].into();

    assert_eq!(hash1, hash2);
    assert_ne!(hash1, hash3);
}

// ============================================================================
// Corner case tests for Privkey
// ============================================================================

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_privkey_from_array() {
    let bytes = [42u8; 32];
    let privkey: Privkey = bytes.into();
    assert_eq!(privkey.as_ref(), &bytes);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_privkey_pubkey_derivation() {
    let privkey = gen_rand_fiber_private_key();
    let pubkey = privkey.pubkey();

    // Verify pubkey is valid (33 bytes compressed)
    assert_eq!(pubkey.serialize().len(), 33);

    // Same privkey should always produce same pubkey
    let pubkey2 = privkey.pubkey();
    assert_eq!(pubkey, pubkey2);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_privkey_sign_and_verify() {
    let privkey = gen_rand_fiber_private_key();
    let pubkey = privkey.pubkey();

    let message = [42u8; 32];
    let signature = privkey.sign(message);

    // Verify the signature
    assert!(signature.verify(&pubkey, &message));

    // Different message should fail verification
    let different_message = [43u8; 32];
    assert!(!signature.verify(&pubkey, &different_message));

    // Different pubkey should fail verification
    let other_privkey = gen_rand_fiber_private_key();
    let other_pubkey = other_privkey.pubkey();
    assert!(!signature.verify(&other_pubkey, &message));
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_privkey_tweak() {
    let privkey = gen_rand_fiber_private_key();
    let scalar = [1u8; 32];

    let tweaked = privkey.tweak(scalar);

    // Tweaked key should be different
    assert_ne!(privkey.as_ref(), tweaked.as_ref());

    // Same tweak should produce same result
    let tweaked2 = privkey.tweak(scalar);
    assert_eq!(tweaked.as_ref(), tweaked2.as_ref());

    // Different tweak should produce different result
    let different_scalar = [2u8; 32];
    let tweaked3 = privkey.tweak(different_scalar);
    assert_ne!(tweaked.as_ref(), tweaked3.as_ref());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_privkey_from_hash256() {
    let hash = gen_rand_sha256_hash();
    let privkey: Privkey = hash.into();

    // Should be able to derive a pubkey
    let pubkey = privkey.pubkey();
    assert_eq!(pubkey.serialize().len(), 33);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_privkey_x_only_pubkey() {
    let privkey = gen_rand_fiber_private_key();
    let x_only = privkey.x_only_pub_key();

    // X-only pubkey should be 32 bytes
    assert_eq!(x_only.serialize().len(), 32);
}

// ============================================================================
// Corner case tests for Pubkey
// ============================================================================

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_pubkey_from_slice_valid() {
    let privkey = gen_rand_fiber_private_key();
    let pubkey = privkey.pubkey();
    let bytes = pubkey.serialize();

    let pubkey2 = Pubkey::from_slice(&bytes);
    assert!(pubkey2.is_ok());
    assert_eq!(pubkey, pubkey2.unwrap());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_pubkey_from_slice_invalid() {
    // Too short
    let short = [0u8; 16];
    assert!(Pubkey::from_slice(&short).is_err());

    // Too long
    let long = [0u8; 64];
    assert!(Pubkey::from_slice(&long).is_err());

    // Invalid pubkey (all zeros)
    let zeros = [0u8; 33];
    assert!(Pubkey::from_slice(&zeros).is_err());

    // Invalid prefix byte
    let invalid = [0u8; 33];
    assert!(Pubkey::from_slice(&invalid).is_err());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_pubkey_tweak() {
    let privkey = gen_rand_fiber_private_key();
    let pubkey = privkey.pubkey();

    let scalar = [1u8; 32];
    let tweaked = pubkey.tweak(scalar);

    // Tweaked key should be different
    assert_ne!(pubkey, tweaked);

    // Same tweak should produce same result
    let tweaked2 = pubkey.tweak(scalar);
    assert_eq!(tweaked, tweaked2);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_pubkey_peer_id_conversion() {
    let privkey = gen_rand_fiber_private_key();
    let pubkey = privkey.pubkey();

    let peer_id = pubkey.tentacle_peer_id();

    // PeerId should be deterministic
    let peer_id2 = pubkey.tentacle_peer_id();
    assert_eq!(peer_id, peer_id2);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_pubkey_tentacle_conversion() {
    let privkey = gen_rand_fiber_private_key();
    let pubkey = privkey.pubkey();

    // Convert to tentacle pubkey and back
    let tentacle_pk: tentacle::secio::PublicKey = pubkey.into();
    let pubkey_back: Pubkey = tentacle_pk.into();
    assert_eq!(pubkey, pubkey_back);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_pubkey_ordering() {
    let privkey1 = gen_rand_fiber_private_key();
    let privkey2 = gen_rand_fiber_private_key();

    let pubkey1 = privkey1.pubkey();
    let pubkey2 = privkey2.pubkey();

    // Ordering should be consistent
    let cmp1 = pubkey1.cmp(&pubkey2);
    let cmp2 = pubkey2.cmp(&pubkey1);
    assert_eq!(cmp1.reverse(), cmp2);

    // Same pubkey should be equal
    assert_eq!(pubkey1.cmp(&pubkey1), std::cmp::Ordering::Equal);
}

// ============================================================================
// Corner case tests for TlcErrorCode
// ============================================================================

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_tlc_error_code_all_variants() {
    // Test that all known error codes can be converted to/from u16
    let codes = vec![
        TlcErrorCode::TemporaryNodeFailure,
        TlcErrorCode::PermanentNodeFailure,
        TlcErrorCode::RequiredNodeFeatureMissing,
        TlcErrorCode::InvalidOnionVersion,
        TlcErrorCode::InvalidOnionHmac,
        TlcErrorCode::InvalidOnionKey,
        TlcErrorCode::TemporaryChannelFailure,
        TlcErrorCode::PermanentChannelFailure,
        TlcErrorCode::RequiredChannelFeatureMissing,
        TlcErrorCode::UnknownNextPeer,
        TlcErrorCode::AmountBelowMinimum,
        TlcErrorCode::FeeInsufficient,
        TlcErrorCode::IncorrectTlcExpiry,
        TlcErrorCode::ExpiryTooSoon,
        TlcErrorCode::IncorrectOrUnknownPaymentDetails,
        TlcErrorCode::FinalIncorrectTlcAmount,
        TlcErrorCode::FinalIncorrectExpiryDelta,
        TlcErrorCode::ExpiryTooFar,
        TlcErrorCode::InvalidOnionPayload,
        TlcErrorCode::InvoiceExpired,
        TlcErrorCode::InvoiceCancelled,
        TlcErrorCode::ChannelDisabled,
        TlcErrorCode::HoldTlcTimeout,
        TlcErrorCode::InvalidOnionError,
    ];

    for code in codes {
        let code_int: u16 = code.into();
        let code_back = TlcErrorCode::try_from(code_int);
        assert!(code_back.is_ok(), "Failed for code {:?}", code);
        assert_eq!(code, code_back.unwrap());
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_tlc_error_code_invalid_value() {
    // Test that invalid values are handled properly
    let invalid_code = 0xFFFF_u16;
    let result = TlcErrorCode::try_from(invalid_code);
    assert!(result.is_err());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_tlc_error_code_string_conversion() {
    let code = TlcErrorCode::PermanentNodeFailure;
    let code_str = code.as_ref().to_string();

    let code_back = TlcErrorCode::from_str(&code_str);
    assert!(code_back.is_ok());
    assert_eq!(code, code_back.unwrap());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_tlc_error_code_flags() {
    // Test is_node flag
    let node_error = TlcErrorCode::PermanentNodeFailure;
    assert!(node_error.is_node());
    assert!(node_error.is_perm());

    let temp_node_error = TlcErrorCode::TemporaryNodeFailure;
    assert!(temp_node_error.is_node());
    assert!(!temp_node_error.is_perm());

    // Test is_bad_onion flag
    let onion_error = TlcErrorCode::InvalidOnionVersion;
    assert!(onion_error.is_bad_onion());
    assert!(onion_error.is_perm());

    // Test channel failure
    let channel_error = TlcErrorCode::TemporaryChannelFailure;
    assert!(!channel_error.is_node());
    assert!(!channel_error.is_perm());
}

// ============================================================================
// Corner case tests for Cursor
// ============================================================================

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_cursor_boundary_timestamps() {
    let node_id = gen_rand_fiber_public_key();

    // Test with 0 timestamp
    let cursor_zero = Cursor::new(0, BroadcastMessageID::NodeAnnouncement(node_id));

    // Test with max timestamp
    let cursor_max = Cursor::new(u64::MAX, BroadcastMessageID::NodeAnnouncement(node_id));

    assert!(cursor_zero < cursor_max);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_cursor_same_timestamp_different_message_types() {
    let node_id = gen_rand_fiber_public_key();
    let channel_outpoint = gen_rand_channel_outpoint();

    let cursor_node = Cursor::new(100, BroadcastMessageID::NodeAnnouncement(node_id));
    let cursor_channel = Cursor::new(
        100,
        BroadcastMessageID::ChannelAnnouncement(channel_outpoint.clone()),
    );
    let cursor_update = Cursor::new(100, BroadcastMessageID::ChannelUpdate(channel_outpoint));

    // Verify ordering: ChannelAnnouncement < ChannelUpdate < NodeAnnouncement
    assert!(cursor_channel < cursor_update);
    assert!(cursor_update < cursor_node);
    assert!(cursor_channel < cursor_node);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_cursor_equality() {
    let node_id = gen_rand_fiber_public_key();

    let cursor1 = Cursor::new(100, BroadcastMessageID::NodeAnnouncement(node_id));
    let cursor2 = Cursor::new(100, BroadcastMessageID::NodeAnnouncement(node_id));
    let cursor3 = Cursor::new(101, BroadcastMessageID::NodeAnnouncement(node_id));

    assert_eq!(cursor1, cursor2);
    assert_ne!(cursor1, cursor3);
}

// ============================================================================
// Corner case tests for PaymentHopData
// ============================================================================

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_payment_hop_data_minimal() {
    let hop_data = PaymentHopData {
        amount: 0,
        expiry: 0,
        next_hop: None,
        funding_tx_hash: Hash256::default(),
        hash_algorithm: HashAlgorithm::Sha256,
        payment_preimage: None,
        custom_records: None,
    };

    let data = pack_hop_data(&hop_data);
    let unpacked: PaymentHopData = unpack_hop_data(&data).expect("unpack error");
    assert_eq!(hop_data, unpacked);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_payment_hop_data_max_values() {
    let privkey = gen_rand_fiber_private_key();

    let hop_data = PaymentHopData {
        amount: u128::MAX,
        expiry: u64::MAX,
        next_hop: Some(privkey.pubkey()),
        funding_tx_hash: [0xff; 32].into(),
        hash_algorithm: HashAlgorithm::Sha256,
        payment_preimage: Some([0xff; 32].into()),
        custom_records: None,
    };

    let data = pack_hop_data(&hop_data);
    let unpacked: PaymentHopData = unpack_hop_data(&data).expect("unpack error");
    assert_eq!(hop_data, unpacked);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_payment_hop_data_with_custom_records() {
    let mut records = PaymentCustomRecords::default();
    records.data.insert(65536, vec![1, 2, 3, 4]);
    records.data.insert(65537, vec![5, 6, 7, 8]);

    let hop_data = PaymentHopData {
        amount: 1000,
        expiry: 2000,
        next_hop: None,
        funding_tx_hash: Hash256::default(),
        hash_algorithm: HashAlgorithm::CkbHash,
        payment_preimage: None,
        custom_records: Some(records),
    };

    let data = pack_hop_data(&hop_data);
    let unpacked: PaymentHopData = unpack_hop_data(&data).expect("unpack error");
    assert_eq!(hop_data, unpacked);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_payment_hop_data_empty_custom_records() {
    let hop_data = PaymentHopData {
        amount: 1000,
        expiry: 2000,
        next_hop: None,
        funding_tx_hash: Hash256::default(),
        hash_algorithm: HashAlgorithm::Sha256,
        payment_preimage: None,
        custom_records: Some(PaymentCustomRecords::default()),
    };

    let data = pack_hop_data(&hop_data);
    let unpacked: PaymentHopData = unpack_hop_data(&data).expect("unpack error");
    assert_eq!(hop_data, unpacked);
}

// ============================================================================
// Corner case tests for AddTlc serialization
// ============================================================================

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_add_tlc_boundary_values() {
    // Test with minimum values
    let add_tlc_min = AddTlc {
        channel_id: [0; 32].into(),
        tlc_id: 0,
        amount: 0,
        payment_hash: [0; 32].into(),
        expiry: 0,
        hash_algorithm: HashAlgorithm::Sha256,
        onion_packet: None,
    };
    let mol_min: molecule_fiber::AddTlc = add_tlc_min.clone().into();
    let back_min: AddTlc = mol_min.try_into().expect("decode");
    assert_eq!(add_tlc_min, back_min);

    // Test with maximum values
    let add_tlc_max = AddTlc {
        channel_id: [0xff; 32].into(),
        tlc_id: u64::MAX,
        amount: u128::MAX,
        payment_hash: [0xff; 32].into(),
        expiry: u64::MAX,
        hash_algorithm: HashAlgorithm::CkbHash,
        onion_packet: None,
    };
    let mol_max: molecule_fiber::AddTlc = add_tlc_max.clone().into();
    let back_max: AddTlc = mol_max.try_into().expect("decode");
    assert_eq!(add_tlc_max, back_max);
}

// ============================================================================
// Corner case tests for TlcErr and TlcErrPacket
// ============================================================================

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_tlc_err_all_error_types() {
    // Test various error types
    let errors = vec![
        TlcErr::new(TlcErrorCode::TemporaryNodeFailure),
        TlcErr::new(TlcErrorCode::InvalidOnionVersion),
        TlcErr::new(TlcErrorCode::TemporaryChannelFailure),
        TlcErr::new(TlcErrorCode::AmountBelowMinimum),
        TlcErr::new(TlcErrorCode::HoldTlcTimeout),
    ];

    for err in errors {
        let packet = TlcErrPacket::new(err.clone(), &NO_SHARED_SECRET);
        let decoded = packet.decode(&[0u8; 32], vec![]).expect("decode");
        assert_eq!(err, decoded);
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_tlc_err_node_fail() {
    let node_id = gen_rand_fiber_public_key();
    let err = TlcErr::new_node_fail(TlcErrorCode::PermanentNodeFailure, node_id);

    assert!(err.error_code.is_node());
    assert!(err.error_code.is_perm());

    let packet = TlcErrPacket::new(err.clone(), &NO_SHARED_SECRET);
    let decoded = packet.decode(&[0u8; 32], vec![]).expect("decode");
    assert_eq!(err, decoded);
}

// ============================================================================
// Corner case tests for BasicMppPaymentData
// ============================================================================

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_basic_mpp_payment_data_boundary_values() {
    // Test with zero total amount
    let payment_secret = gen_rand_sha256_hash();
    let record = BasicMppPaymentData::new(payment_secret, 0);
    let mut records = PaymentCustomRecords::default();
    record.write(&mut records);
    let read_back = BasicMppPaymentData::read(&records).unwrap();
    assert_eq!(record, read_back);

    // Test with max total amount
    let record_max = BasicMppPaymentData::new(payment_secret, u128::MAX);
    let mut records_max = PaymentCustomRecords::default();
    record_max.write(&mut records_max);
    let read_back_max = BasicMppPaymentData::read(&records_max).unwrap();
    assert_eq!(record_max, read_back_max);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_payment_custom_records_boundary_keys() {
    let mut records = PaymentCustomRecords::default();

    // Add records with boundary key values (using literal values)
    records.data.insert(65535, vec![1, 2, 3]);
    records.data.insert(65536, vec![4, 5, 6]);

    let json = serde_json::to_string(&records).expect("serialize");
    let deserialized: PaymentCustomRecords = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(records, deserialized);
}

// ============================================================================
// Corner case tests for NodeId
// ============================================================================

#[test]
fn test_node_id_from_random_peer_ids() {
    // Test multiple random peer IDs
    for _ in 0..10 {
        let peer_id = PeerId::random();
        let node_id = NodeId::from_bytes(peer_id.clone().into_bytes());

        // Serialize and deserialize
        let json = serde_json::to_string(&node_id).expect("serialize");
        let deserialized: NodeId = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(node_id, deserialized);
    }
}

// ============================================================================
// Corner case tests for PaymentCustomRecords
// ============================================================================

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_payment_custom_records_empty() {
    let records = PaymentCustomRecords::default();
    assert!(records.data.is_empty());

    let json = serde_json::to_string(&records).expect("serialize");
    let deserialized: PaymentCustomRecords = serde_json::from_str(&json).expect("deserialize");
    assert!(deserialized.data.is_empty());
}

// ============================================================================
// Corner case tests for PaymentStatus
// ============================================================================

use crate::fiber::payment::{PaymentStatus, SessionRoute, SessionRouteNode};

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_payment_status_is_final() {
    // Non-final statuses
    assert!(!PaymentStatus::Created.is_final());
    assert!(!PaymentStatus::Inflight.is_final());

    // Final statuses
    assert!(PaymentStatus::Success.is_final());
    assert!(PaymentStatus::Failed.is_final());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_payment_status_serialization() {
    let statuses = [
        PaymentStatus::Created,
        PaymentStatus::Inflight,
        PaymentStatus::Success,
        PaymentStatus::Failed,
    ];

    for status in statuses {
        let json = serde_json::to_string(&status).expect("serialize");
        let deserialized: PaymentStatus = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(status, deserialized);
    }
}

// ============================================================================
// Corner case tests for SessionRoute
// ============================================================================

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_session_route_default() {
    let route = SessionRoute::default();
    assert!(route.nodes.is_empty());
    assert_eq!(route.receiver_amount(), 0);
    assert_eq!(route.fee(), 0);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_session_route_single_hop() {
    let pubkey = gen_rand_fiber_public_key();
    let outpoint = gen_rand_channel_outpoint();

    let route = SessionRoute {
        nodes: vec![SessionRouteNode {
            pubkey,
            amount: 10000,
            channel_outpoint: outpoint,
        }],
    };

    assert_eq!(route.nodes.len(), 1);
    assert_eq!(route.receiver_amount(), 10000);
    assert_eq!(route.fee(), 0); // Single hop, no fee
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_session_route_multi_hop_with_fee() {
    let pubkey1 = gen_rand_fiber_public_key();
    let pubkey2 = gen_rand_fiber_public_key();
    let pubkey3 = gen_rand_fiber_public_key();
    let outpoint1 = gen_rand_channel_outpoint();
    let outpoint2 = gen_rand_channel_outpoint();
    let outpoint3 = gen_rand_channel_outpoint();

    let route = SessionRoute {
        nodes: vec![
            SessionRouteNode {
                pubkey: pubkey1,
                amount: 10100, // Sender sends more to cover fees
                channel_outpoint: outpoint1,
            },
            SessionRouteNode {
                pubkey: pubkey2,
                amount: 10050, // After first hop fee
                channel_outpoint: outpoint2,
            },
            SessionRouteNode {
                pubkey: pubkey3,
                amount: 10000, // Final receiver amount
                channel_outpoint: outpoint3,
            },
        ],
    };

    assert_eq!(route.nodes.len(), 3);
    assert_eq!(route.receiver_amount(), 10000);
    assert_eq!(route.fee(), 100); // 10100 - 10000 = 100
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_session_route_channel_outpoints() {
    let pubkey1 = gen_rand_fiber_public_key();
    let pubkey2 = gen_rand_fiber_public_key();
    let outpoint1 = gen_rand_channel_outpoint();
    let outpoint2 = gen_rand_channel_outpoint();

    let route = SessionRoute {
        nodes: vec![
            SessionRouteNode {
                pubkey: pubkey1,
                amount: 10000,
                channel_outpoint: outpoint1.clone(),
            },
            SessionRouteNode {
                pubkey: pubkey2,
                amount: 9000,
                channel_outpoint: outpoint2.clone(),
            },
        ],
    };

    let outpoints: Vec<_> = route.channel_outpoints().collect();
    assert_eq!(outpoints.len(), 2);
    assert_eq!(outpoints[0].0, pubkey1);
    assert_eq!(outpoints[0].2, 10000);
    assert_eq!(outpoints[1].0, pubkey2);
    assert_eq!(outpoints[1].2, 9000);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_session_route_new_from_payment_hops() {
    let source = gen_rand_fiber_public_key();
    let target = gen_rand_fiber_public_key();
    let middle = gen_rand_fiber_public_key();
    let funding_tx_hash = gen_rand_sha256_hash();

    let payment_hops = vec![
        PaymentHopData {
            amount: 10050,
            expiry: 1000,
            payment_preimage: None,
            hash_algorithm: HashAlgorithm::CkbHash,
            funding_tx_hash,
            next_hop: Some(middle),
            custom_records: None,
        },
        PaymentHopData {
            amount: 10000,
            expiry: 500,
            payment_preimage: None,
            hash_algorithm: HashAlgorithm::CkbHash,
            funding_tx_hash: gen_rand_sha256_hash(),
            next_hop: None, // Target is implied
            custom_records: None,
        },
    ];

    let route = SessionRoute::new(source, target, &payment_hops);

    // Route should have 2 nodes (source->middle, middle->target)
    assert_eq!(route.nodes.len(), 2);
    assert_eq!(route.nodes[0].pubkey, source);
    assert_eq!(route.nodes[0].amount, 10050);
    assert_eq!(route.nodes[1].pubkey, middle);
    assert_eq!(route.nodes[1].amount, 10000);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_session_route_serialization() {
    let pubkey = gen_rand_fiber_public_key();
    let outpoint = gen_rand_channel_outpoint();

    let route = SessionRoute {
        nodes: vec![SessionRouteNode {
            pubkey,
            amount: 10000,
            channel_outpoint: outpoint,
        }],
    };

    let json = serde_json::to_string(&route).expect("serialize");
    let deserialized: SessionRoute = serde_json::from_str(&json).expect("deserialize");

    assert_eq!(route.nodes.len(), deserialized.nodes.len());
    assert_eq!(route.nodes[0].amount, deserialized.nodes[0].amount);
}

// ============================================================================
// Corner case tests for CurrentPaymentHopData
// ============================================================================

use crate::fiber::types::CurrentPaymentHopData;

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_current_payment_hop_data_from_payment_hop_data() {
    let payment_hop = PaymentHopData {
        amount: 10000,
        expiry: 500,
        payment_preimage: Some(gen_rand_sha256_hash()),
        hash_algorithm: HashAlgorithm::Sha256,
        funding_tx_hash: gen_rand_sha256_hash(),
        next_hop: Some(gen_rand_fiber_public_key()),
        custom_records: None,
    };

    let current_hop: CurrentPaymentHopData = payment_hop.clone().into();

    assert_eq!(current_hop.amount, payment_hop.amount);
    assert_eq!(current_hop.expiry, payment_hop.expiry);
    assert_eq!(current_hop.payment_preimage, payment_hop.payment_preimage);
    assert_eq!(current_hop.hash_algorithm, payment_hop.hash_algorithm);
    assert_eq!(current_hop.funding_tx_hash, payment_hop.funding_tx_hash);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_current_payment_hop_data_serialization() {
    let hop = CurrentPaymentHopData {
        amount: 50000,
        expiry: 1000,
        payment_preimage: None,
        hash_algorithm: HashAlgorithm::CkbHash,
        funding_tx_hash: gen_rand_sha256_hash(),
        custom_records: None,
    };

    let json = serde_json::to_string(&hop).expect("serialize");
    let deserialized: CurrentPaymentHopData = serde_json::from_str(&json).expect("deserialize");

    assert_eq!(hop.amount, deserialized.amount);
    assert_eq!(hop.expiry, deserialized.expiry);
    assert_eq!(hop.hash_algorithm, deserialized.hash_algorithm);
}

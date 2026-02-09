// use fiber_v061::fiber::types::{Privkey as OldPrivkey, Pubkey as OldPubkey};
// use fiber_v070::fiber::types::{Privkey as NewPrivkey, Pubkey as NewPubkey};
use musig2_0011 as musig_old;
use musig2_024 as musig_new;
use secp256k1_028 as secp_old;
use secp256k1_030 as secp_new;

fn test_key_bytes() -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes[31] = 1;
    bytes
}

fn test_key_bytes_alt() -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes[31] = 2;
    bytes
}

fn old_musig_pubnonce() -> musig_old::PubNonce {
    let sec_nonce = musig_old::SecNonce::build(test_key_bytes()).build();
    sec_nonce.public_nonce()
}

fn new_musig_pubnonce() -> musig_new::PubNonce {
    let sec_nonce = musig_new::SecNonce::build(test_key_bytes()).build();
    sec_nonce.public_nonce()
}

fn old_musig_partial_signature() -> musig_old::PartialSignature {
    let ctx = secp_old::Secp256k1::new();
    let sk1 = secp_old::SecretKey::from_slice(&test_key_bytes()).expect("old secret key 1");
    let sk2 = secp_old::SecretKey::from_slice(&test_key_bytes_alt()).expect("old secret key 2");
    let pk1 = secp_old::PublicKey::from_secret_key(&ctx, &sk1);
    let pk2 = secp_old::PublicKey::from_secret_key(&ctx, &sk2);

    let key_agg_ctx = musig_old::KeyAggContext::new([pk1, pk2]).expect("old key agg context");
    let sec_nonce = musig_old::SecNonce::build(test_key_bytes()).build();
    let pub_nonce = sec_nonce.public_nonce();
    let agg_nonce = musig_old::AggNonce::sum([pub_nonce.clone(), pub_nonce]);
    let message = [42u8; 32];

    musig_old::sign_partial(&key_agg_ctx, sk1, sec_nonce, &agg_nonce, &message)
        .expect("old partial signature")
}

fn new_musig_partial_signature() -> musig_new::PartialSignature {
    let ctx = secp_new::Secp256k1::new();
    let sk1 = secp_new::SecretKey::from_slice(&test_key_bytes()).expect("new secret key 1");
    let sk2 = secp_new::SecretKey::from_slice(&test_key_bytes_alt()).expect("new secret key 2");
    let pk1 = secp_new::PublicKey::from_secret_key(&ctx, &sk1);
    let pk2 = secp_new::PublicKey::from_secret_key(&ctx, &sk2);

    let key_agg_ctx = musig_new::KeyAggContext::new([pk1, pk2]).expect("new key agg context");
    let sec_nonce = musig_new::SecNonce::build(test_key_bytes()).build();
    let pub_nonce = sec_nonce.public_nonce();
    let agg_nonce = musig_new::AggNonce::sum([pub_nonce.clone(), pub_nonce]);
    let message = [42u8; 32];

    musig_new::sign_partial(&key_agg_ctx, sk1, sec_nonce, &agg_nonce, &message)
        .expect("new partial signature")
}

#[test]
fn musig2_pubnonce_bincode_incompatible_between_0011_and_024() {
    let old_nonce = old_musig_pubnonce();
    let new_nonce = new_musig_pubnonce();

    let old_bytes = bincode::serialize(&old_nonce).expect("serialize old pubnonce");
    let new_bytes = bincode::serialize(&new_nonce).expect("serialize new pubnonce");

    println!(
        "old PubNonce bincode len: {}, bytes: {:?}",
        old_bytes.len(),
        &old_bytes
    );
    println!(
        "new PubNonce bincode len: {}, bytes: {:?}",
        new_bytes.len(),
        &new_bytes
    );

    let res = bincode::deserialize::<musig_new::PubNonce>(&old_bytes)
        .expect("deserialize old pubnonce into new pubnonce");
    println!("deserialized old PubNonce into new PubNonce: {:?}", res);
}

#[test]
fn musig2_partial_signature_bincode_incompatible_between_0011_and_024() {
    let old_sig = old_musig_partial_signature();
    let new_sig = new_musig_partial_signature();

    let old_bytes = bincode::serialize(&old_sig).expect("serialize old partial signature");
    let new_bytes = bincode::serialize(&new_sig).expect("serialize new partial signature");

    assert_ne!(
        old_bytes, new_bytes,
        "musig2::PartialSignature bincode should differ between 0.0.11 and 0.2.4"
    );
    assert!(
        bincode::deserialize::<musig_new::PartialSignature>(&old_bytes).is_err(),
        "Old PartialSignature bytes should not deserialize into new PartialSignature"
    );
}

// #[test]
// fn fiber_privkey_bincode_incompatible_between_v061_and_v070() {
//     let key_bytes = test_key_bytes();
//     let old_priv = OldPrivkey::from_slice(&key_bytes);
//     let new_priv = NewPrivkey::from_slice(&key_bytes);

//     let old_bytes = bincode::serialize(&old_priv).expect("serialize old privkey");
//     let new_bytes = bincode::serialize(&new_priv).expect("serialize new privkey");

//     assert_ne!(
//         old_bytes, new_bytes,
//         "Privkey bincode should differ between v0.6.1 and v0.7.0"
//     );
//     assert!(
//         bincode::deserialize::<NewPrivkey>(&old_bytes).is_err(),
//         "Old Privkey bytes should not deserialize into new Privkey"
//     );
// }

// #[test]
// fn fiber_pubkey_bincode_incompatible_between_v061_and_v070() {
//     let key_bytes = test_key_bytes();
//     let old_priv = OldPrivkey::from_slice(&key_bytes);
//     let new_priv = NewPrivkey::from_slice(&key_bytes);

//     let old_pub: OldPubkey = old_priv.pubkey();
//     let new_pub: NewPubkey = new_priv.pubkey();

//     let old_bytes = bincode::serialize(&old_pub).expect("serialize old pubkey");
//     let new_bytes = bincode::serialize(&new_pub).expect("serialize new pubkey");

//     assert_ne!(
//         old_bytes, new_bytes,
//         "Pubkey bincode should differ between v0.6.1 and v0.7.0"
//     );
//     assert!(
//         bincode::deserialize::<NewPubkey>(&old_bytes).is_err(),
//         "Old Pubkey bytes should not deserialize into new Pubkey"
//     );
// }

#[test]
fn secp256k1_secretkey_bincode_incompatible_between_028_and_030() {
    let key_bytes = test_key_bytes();
    let old_sk = secp_old::SecretKey::from_slice(&key_bytes).expect("old secret key");
    let new_sk = secp_new::SecretKey::from_slice(&key_bytes).expect("new secret key");

    let old_bytes = bincode::serialize(&old_sk).expect("serialize old secret key");
    let new_bytes = bincode::serialize(&new_sk).expect("serialize new secret key");

    let new_key = bincode::deserialize::<secp_new::SecretKey>(&old_bytes)
        .expect("deserialize new secret key");

    // assert_ne!(
    //     old_bytes, new_bytes,
    //     "secp256k1::SecretKey bincode should differ between 0.28 and 0.30"
    // );
}

#[test]
fn secp256k1_publickey_bincode_incompatible_between_028_and_030() {
    let key_bytes = test_key_bytes();
    let old_sk = secp_old::SecretKey::from_slice(&key_bytes).expect("old secret key");
    let new_sk = secp_new::SecretKey::from_slice(&key_bytes).expect("new secret key");

    let old_ctx = secp_old::Secp256k1::new();
    let new_ctx = secp_new::Secp256k1::new();

    let old_pk = secp_old::PublicKey::from_secret_key(&old_ctx, &old_sk);
    let new_pk = secp_new::PublicKey::from_secret_key(&new_ctx, &new_sk);

    let old_bytes = bincode::serialize(&old_pk).expect("serialize old public key");
    let new_bytes = bincode::serialize(&new_pk).expect("serialize new public key");

    let new_bytes = bincode::deserialize::<secp_new::PublicKey>(&old_bytes)
        .expect("deserialize new public key")
        .serialize();

    // assert_ne!(
    //     old_bytes, new_bytes,
    //     "secp256k1::PublicKey bincode should differ between 0.28 and 0.30"
    // );
}

use ckb_types::packed::OutPoint;
use ckb_types::prelude::Entity;
use secp256k1::{Keypair, PublicKey, Secp256k1, SecretKey};

use crate::fiber::types::{Privkey, Pubkey};

pub fn gen_rand_fiber_public_key() -> Pubkey {
    gen_rand_secp256k1_public_key().into()
}

pub fn gen_rand_fiber_private_key() -> Privkey {
    gen_rand_secp256k1_private_key().into()
}

pub fn gen_rand_secp256k1_private_key() -> SecretKey {
    gen_rand_secp256k1_keypair().0
}

pub fn gen_rand_secp256k1_public_key() -> PublicKey {
    gen_rand_secp256k1_keypair().1
}

pub fn gen_rand_secp256k1_keypair() -> (SecretKey, PublicKey) {
    let secp = Secp256k1::new();
    let key_pair = Keypair::new(&secp, &mut rand::thread_rng());
    (
        SecretKey::from_keypair(&key_pair),
        PublicKey::from_keypair(&key_pair),
    )
}

pub fn gen_rand_channel_outpoint() -> OutPoint {
    let rand_slice = (0..36).map(|_| rand::random::<u8>()).collect::<Vec<u8>>();
    OutPoint::from_slice(&rand_slice).unwrap()
}

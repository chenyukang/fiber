use crate::fiber::channel::ChannelActorState;
use crate::fiber::serde_utils::EntityHex;
use crate::fiber::serde_utils::PubNonceAsBytes;
use crate::store::schema::CHANNEL_ACTOR_STATE_PREFIX;
use crate::{
    fiber::{
        channel::{
            ChannelBasePublicKeys, ChannelState, CommitmentNumbers, DetailedTLCInfo,
            InMemorySigner, PublicChannelInfo, ShutdownInfo, TLCId, TLCIds,
        },
        types::{Hash256, Pubkey},
    },
    store::migration::Migration,
    Error,
};
use ckb_jsonrpc_types::BlockNumber;
use ckb_types::packed::{Script, Transaction};
use indicatif::ProgressBar;
use musig2::PubNonce;
use rocksdb::{prelude::*, DB};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use std::{collections::BTreeMap, sync::Arc, time::SystemTime};

const INIT_DB_VERSION: &str = "20331116135521";

pub struct SampleMigration {
    version: String,
}

impl SampleMigration {
    pub fn new() -> Self {
        Self {
            version: INIT_DB_VERSION.to_string(),
        }
    }
}

#[serde_as]
#[derive(Clone, Serialize, Deserialize)]
pub struct OldChannelActorState {
    pub state: ChannelState,
    // The data below are only relevant if the channel is public.
    pub public_channel_info: Option<PublicChannelInfo>,

    // The local public key used to establish p2p network connection.
    pub local_pubkey: Pubkey,
    // The remote public key used to establish p2p network connection.
    pub remote_pubkey: Pubkey,

    pub id: Hash256,
    #[serde_as(as = "Option<EntityHex>")]
    pub funding_tx: Option<Transaction>,

    pub funding_tx_confirmed_at: Option<(BlockNumber, u32)>,

    #[serde_as(as = "Option<EntityHex>")]
    pub funding_udt_type_script: Option<Script>,

    // Is this channel initially inbound?
    // An inbound channel is one where the counterparty is the funder of the channel.
    pub is_acceptor: bool,

    // TODO: consider transaction fee while building the commitment transaction.

    // The invariant here is that the sum of `to_local_amount` and `to_remote_amount`
    // should be equal to the total amount of the channel.
    // The changes of both `to_local_amount` and `to_remote_amount`
    // will always happen after a revoke_and_ack message is sent/received.
    // This means that while calculating the amounts for commitment transactions,
    // processing add_tlc command and messages, we need to take into account that
    // the amounts are not decremented/incremented yet.

    // The amount of CKB/UDT that we own in the channel.
    // This value will only change after we have resolved a tlc.
    pub to_local_amount: u128,
    // The amount of CKB/UDT that the remote owns in the channel.
    // This value will only change after we have resolved a tlc.
    pub to_remote_amount: u128,

    // these two amounts used to keep the minimal ckb amount for the two parties
    // TLC operations will not affect these two amounts, only used to keep the commitment transactions
    // to be valid, so that any party can close the channel at any time.
    // Note: the values are different for the UDT scenario
    pub local_reserved_ckb_amount: u64,
    pub remote_reserved_ckb_amount: u64,

    // The commitment fee rate is used to calculate the fee for the commitment transactions.
    // The side who want to submit the commitment transaction will pay fee
    pub commitment_fee_rate: u64,

    // The delay time for the commitment transaction, this value is set by the initiator of the channel.
    // It must be a relative EpochNumberWithFraction in u64 format.
    pub commitment_delay_epoch: u64,

    // The fee rate used for funding transaction, the initiator may set it as `funding_fee_rate` option,
    // if it's not set, DEFAULT_FEE_RATE will be used as default value, two sides will use the same fee rate
    pub funding_fee_rate: u64,

    // Signer is used to sign the commitment transactions.
    pub signer: InMemorySigner,

    // Cached channel public keys for easier of access.
    pub local_channel_public_keys: ChannelBasePublicKeys,

    // Commitment numbers that are used to derive keys.
    // This value is guaranteed to be 0 when channel is just created.
    pub commitment_numbers: CommitmentNumbers,

    // The maximum value can be in pending
    pub max_tlc_value_in_flight: u128,

    // The maximum number of tlcs that we can accept.
    pub max_tlc_number_in_flight: u64,

    // Below are fields that are only usable after the channel is funded,
    // (or at some point of the state).

    // The id of next offering/received tlc, must increment by 1 for each new tlc.
    pub tlc_ids: TLCIds,

    // BtreeMap of tlc ids to pending tlcs.
    // serde_as is required for serde to json, as json requires keys to be strings.
    // See https://stackoverflow.com/questions/51276896/how-do-i-use-serde-to-serialize-a-hashmap-with-structs-as-keys-to-json
    #[serde_as(as = "Vec<(_, _)>")]
    pub tlcs: BTreeMap<TLCId, DetailedTLCInfo>,

    // The remote and local lock script for close channel, they are setup during the channel establishment.
    #[serde_as(as = "Option<EntityHex>")]
    pub remote_shutdown_script: Option<Script>,
    #[serde_as(as = "Option<EntityHex>")]
    pub local_shutdown_script: Option<Script>,

    #[serde_as(as = "Option<PubNonceAsBytes>")]
    pub previous_remote_nonce: Option<PubNonce>,
    #[serde_as(as = "Option<PubNonceAsBytes>")]
    pub remote_nonce: Option<PubNonce>,

    // The latest commitment transaction we're holding
    #[serde_as(as = "Option<EntityHex>")]
    pub latest_commitment_transaction: Option<Transaction>,

    // All the commitment point that are sent from the counterparty.
    // We need to save all these points to derive the keys for the commitment transactions.
    pub remote_commitment_points: Vec<Pubkey>,
    pub remote_channel_public_keys: Option<ChannelBasePublicKeys>,

    // The shutdown info for both local and remote, they are setup by the shutdown command or message.
    pub local_shutdown_info: Option<ShutdownInfo>,
    pub remote_shutdown_info: Option<ShutdownInfo>,

    // A flag to indicate whether the channel is reestablishing, we won't process any messages until the channel is reestablished.
    pub reestablishing: bool,

    pub created_at: SystemTime,
}

impl From<OldChannelActorState> for ChannelActorState {
    fn from(old_state: OldChannelActorState) -> Self {
        ChannelActorState {
            state: old_state.state,
            public_channel_info: old_state.public_channel_info,
            local_pubkey: old_state.local_pubkey,
            remote_pubkey: old_state.remote_pubkey,
            id: old_state.id,
            funding_tx: old_state.funding_tx,
            funding_tx_confirmed_at: old_state.funding_tx_confirmed_at,
            funding_udt_type_script: old_state.funding_udt_type_script,
            is_acceptor: old_state.is_acceptor,
            to_local_amount: old_state.to_local_amount,
            to_remote_amount: old_state.to_remote_amount,
            local_reserved_ckb_amount: old_state.local_reserved_ckb_amount,
            remote_reserved_ckb_amount: old_state.remote_reserved_ckb_amount,
            commitment_fee_rate: old_state.commitment_fee_rate,
            commitment_delay_epoch: old_state.commitment_delay_epoch,
            funding_fee_rate: old_state.funding_fee_rate,
            signer: old_state.signer,
            local_channel_public_keys: old_state.local_channel_public_keys,
            commitment_numbers: old_state.commitment_numbers,
            max_tlc_value_in_flight: old_state.max_tlc_value_in_flight,
            max_tlc_number_in_flight: old_state.max_tlc_number_in_flight,
            tlc_ids: old_state.tlc_ids,
            tlcs: old_state.tlcs,
            remote_shutdown_script: old_state.remote_shutdown_script,
            local_shutdown_script: old_state.local_shutdown_script,
            previous_remote_nonce: old_state.previous_remote_nonce,
            remote_nonce: old_state.remote_nonce,
            latest_commitment_transaction: old_state.latest_commitment_transaction,
            remote_commitment_points: old_state.remote_commitment_points,
            remote_channel_public_keys: old_state.remote_channel_public_keys,
            local_shutdown_info: old_state.local_shutdown_info,
            remote_shutdown_info: old_state.remote_shutdown_info,
            reestablishing: old_state.reestablishing,
            created_at: old_state.created_at,
            // new fields
            last_updated_at: Some(SystemTime::now()),
        }
    }
}

impl Migration for SampleMigration {
    fn migrate(
        &self,
        db: Arc<DB>,
        _pb: Arc<dyn Fn(u64) -> ProgressBar + Send + Sync>,
    ) -> Result<Arc<DB>, Error> {
        eprintln!("SampleMigration::migrate ...........");

        let prefix = vec![CHANNEL_ACTOR_STATE_PREFIX];
        let iter = db
            .prefix_iterator(&prefix)
            .take_while(move |(col_key, _)| col_key.starts_with(&prefix));

        let all_states = iter
            .map(|(_, value)| {
                let state: OldChannelActorState = bincode::deserialize(&value).unwrap();
                state
            })
            .collect::<Vec<OldChannelActorState>>();

        for state in all_states {
            eprintln!("state: {:?}", state.id);
            let new = ChannelActorState::from(state);
            let key = [&[CHANNEL_ACTOR_STATE_PREFIX], new.id.as_ref()].concat();
            let value = bincode::serialize(&new).unwrap();
            eprintln!("new state: {:?}", new.id);
            db.put(&key, &value).unwrap();
        }

        Ok(db)
    }

    fn version(&self) -> &str {
        &self.version
    }

    fn expensive(&self) -> bool {
        false
    }
}

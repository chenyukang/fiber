use crate::{
    fiber::{
        channel::{ChannelActorState, ChannelActorStateStore, ChannelState},
        gossip::GossipMessageStore,
        graph::{NetworkGraphStateStore, PaymentSession},
        network::{NetworkActorStateStore, PersistentNetworkActorState},
        types::{
            BroadcastMessage, BroadcastMessageID, BroadcastMessageWithTimestamp,
            ChannelAnnouncement, ChannelUpdate, Cursor, Hash256, Pubkey, CURSOR_SIZE,
        },
    },
    invoice::{CkbInvoice, CkbInvoiceStatus, InvoiceError, InvoiceStore},
    watchtower::{ChannelData, RevocationData, WatchtowerStore},
};
use ckb_types::packed::{OutPoint, Script};
use rocksdb::{prelude::*, DBIterator, IteratorMode, WriteBatch, DB};
use serde_json;
use std::{path::Path, sync::Arc};
use tentacle::secio::PeerId;

const DEFAULT_NUM_OF_BROADCAST_MESSAGES: u16 = 1000;

#[derive(Clone)]
pub struct Store {
    pub(crate) db: Arc<DB>,
}

impl Store {
    pub fn new<P: AsRef<Path>>(path: P) -> Self {
        let db = Arc::new(DB::open_default(path).expect("Failed to open rocksdb"));
        Self { db }
    }

    fn get<K: AsRef<[u8]>>(&self, key: K) -> Option<Vec<u8>> {
        self.db
            .get(key.as_ref())
            .map(|v| v.map(|vi| vi.to_vec()))
            .expect("get should be OK")
    }

    #[allow(dead_code)]
    fn get_range<K: AsRef<[u8]>>(
        &self,
        lower_bound: Option<K>,
        upper_bound: Option<K>,
    ) -> DBIterator {
        assert!(lower_bound.is_some() || upper_bound.is_some());
        let mut read_options = ReadOptions::default();
        if let Some(lower_bound) = lower_bound {
            read_options.set_iterate_lower_bound(lower_bound.as_ref());
        }
        if let Some(upper_bound) = upper_bound {
            read_options.set_iterate_upper_bound(upper_bound.as_ref());
        }
        let mode = IteratorMode::Start;
        self.db.get_iter(&read_options, mode)
    }

    fn batch(&self) -> Batch {
        Batch {
            db: Arc::clone(&self.db),
            wb: WriteBatch::default(),
        }
    }
}

pub struct Batch {
    db: Arc<DB>,
    wb: WriteBatch,
}

impl Batch {
    fn put_kv(&mut self, key_value: KeyValue) {
        match key_value {
            KeyValue::ChannelActorState(id, state) => {
                let key = [&[CHANNEL_ACTOR_STATE_PREFIX], id.as_ref()].concat();
                self.put(
                    key,
                    serde_json::to_vec(&state).expect("serialize ChannelActorState should be OK"),
                );
            }
            KeyValue::CkbInvoice(id, invoice) => {
                let key = [&[CKB_INVOICE_PREFIX], id.as_ref()].concat();
                self.put(
                    key,
                    serde_json::to_vec(&invoice).expect("serialize CkbInvoice should be OK"),
                );
            }
            KeyValue::CkbInvoicePreimage(id, preimage) => {
                let key = [&[CKB_INVOICE_PREIMAGE_PREFIX], id.as_ref()].concat();
                self.put(
                    key,
                    serde_json::to_vec(&preimage).expect("serialize Hash256 should be OK"),
                );
            }
            KeyValue::CkbInvoiceStatus(id, status) => {
                let key = [&[CKB_INVOICE_STATUS_PREFIX], id.as_ref()].concat();
                self.put(
                    key,
                    serde_json::to_vec(&status).expect("serialize CkbInvoiceStatus should be OK"),
                );
            }
            KeyValue::PeerIdChannelId((peer_id, channel_id), state) => {
                let key = [
                    &[PEER_ID_CHANNEL_ID_PREFIX],
                    peer_id.as_bytes(),
                    channel_id.as_ref(),
                ]
                .concat();
                self.put(
                    key,
                    serde_json::to_vec(&state).expect("serialize ChannelState should be OK"),
                );
            }
            KeyValue::PaymentSession(payment_hash, payment_session) => {
                let key = [&[PAYMENT_SESSION_PREFIX], payment_hash.as_ref()].concat();
                self.put(
                    key,
                    serde_json::to_vec(&payment_session)
                        .expect("serialize PaymentSession should be OK"),
                );
            }
            KeyValue::WatchtowerChannel(channel_id, channel_data) => {
                let key = [&[WATCHTOWER_CHANNEL_PREFIX], channel_id.as_ref()].concat();
                self.put(
                    key,
                    serde_json::to_vec(&channel_data).expect("serialize ChannelData should be OK"),
                );
            }
            KeyValue::NetworkActorState(peer_id, persistent_network_actor_state) => {
                let key = [&[PEER_ID_NETWORK_ACTOR_STATE_PREFIX], peer_id.as_bytes()].concat();
                self.put(
                    key,
                    serde_json::to_vec(&persistent_network_actor_state)
                        .expect("serialize PersistentNetworkActorState should be OK"),
                );
            }
        }
    }

    fn put<K: AsRef<[u8]>, V: AsRef<[u8]>>(&mut self, key: K, value: V) {
        self.wb.put(key, value).expect("put should be OK")
    }

    fn delete<K: AsRef<[u8]>>(&mut self, key: K) {
        self.wb.delete(key.as_ref()).expect("delete should be OK")
    }

    fn commit(self) {
        self.db.write(&self.wb).expect("commit should be OK")
    }
}

///
/// +--------------+--------------------+-----------------------------+
/// | KeyPrefix::  | Key::              | Value::                     |
/// +--------------+--------------------+-----------------------------+
/// | 0            | Hash256            | ChannelActorState           |
/// | 16           | PeerId             | PersistentNetworkActorState |
/// | 32           | Hash256            | CkbInvoice                  |
/// | 33           | Payment_hash       | CkbInvoice Preimage         |
/// | 34           | Payment_hash       | CkbInvoice Status           |
/// | 64           | PeerId | Hash256   | ChannelState                |
/// | 96           | ChannelId          | ChannelInfo                 |
/// | 97           | Block | Index      | ChannelId                   |
/// | 98           | Cursor             | BroadcastMessage            |
/// | 99           | BroadcastMessageID | Timestamp                   |
/// | 128          | NodeId             | NodeInfo                    |
/// | 129          | Timestamp          | NodeId                      |
/// | 160          | PeerId             | MultiAddr                   |
/// | 192          | Hash256            | PaymentSession              |
/// | 224          | Hash256            | ChannelData                 |
/// +--------------+--------------------+-----------------------------+
///

const CHANNEL_ACTOR_STATE_PREFIX: u8 = 0;
const PEER_ID_NETWORK_ACTOR_STATE_PREFIX: u8 = 16;
const CKB_INVOICE_PREFIX: u8 = 32;
const CKB_INVOICE_PREIMAGE_PREFIX: u8 = 33;
const CKB_INVOICE_STATUS_PREFIX: u8 = 34;
const PEER_ID_CHANNEL_ID_PREFIX: u8 = 64;
const CHANNEL_INFO_PREFIX: u8 = 96;
const CHANNEL_ANNOUNCEMENT_INDEX_PREFIX: u8 = 97;
// We save all the broadcast messages in a single column family because we need to
// query all broadcast messages after a cursor. We use the cursor date type as the key
// for the broadcast messages. This simplify the implementation of the query logic.
// But this makes it harder to return a list of broadcast messages with the same type
// (e.g. channel_announcement) in a single query.
const BROADCAST_MESSAGE_PREFIX: u8 = 98;
const BROADCAST_MESSAGE_TIMESTAMP_PREFIX: u8 = 99;
const NODE_INFO_PREFIX: u8 = 128;
const NODE_ANNOUNCEMENT_INDEX_PREFIX: u8 = 129;
const PAYMENT_SESSION_PREFIX: u8 = 192;
const WATCHTOWER_CHANNEL_PREFIX: u8 = 224;

enum KeyValue {
    ChannelActorState(Hash256, ChannelActorState),
    CkbInvoice(Hash256, CkbInvoice),
    CkbInvoicePreimage(Hash256, Hash256),
    CkbInvoiceStatus(Hash256, CkbInvoiceStatus),
    PeerIdChannelId((PeerId, Hash256), ChannelState),
    WatchtowerChannel(Hash256, ChannelData),
    PaymentSession(Hash256, PaymentSession),
    NetworkActorState(PeerId, PersistentNetworkActorState),
}

impl NetworkActorStateStore for Store {
    fn get_network_actor_state(&self, id: &PeerId) -> Option<PersistentNetworkActorState> {
        let mut key = Vec::with_capacity(33);
        key.push(PEER_ID_NETWORK_ACTOR_STATE_PREFIX);
        key.extend_from_slice(id.as_bytes());
        let iter = self
            .db
            .prefix_iterator(key.as_ref())
            .find(|(col_key, _)| col_key.starts_with(&key));
        iter.map(|(_key, value)| {
            serde_json::from_slice(value.as_ref())
                .expect("deserialize PersistentNetworkActorState should be OK")
        })
    }

    fn insert_network_actor_state(&self, id: &PeerId, state: PersistentNetworkActorState) {
        let mut batch = self.batch();
        batch.put_kv(KeyValue::NetworkActorState(id.clone(), state));
        batch.commit();
    }
}

impl ChannelActorStateStore for Store {
    fn get_channel_actor_state(&self, id: &Hash256) -> Option<ChannelActorState> {
        let mut key = Vec::with_capacity(33);
        key.extend_from_slice(&[CHANNEL_ACTOR_STATE_PREFIX]);
        key.extend_from_slice(id.as_ref());

        self.get(key).map(|v| {
            serde_json::from_slice(v.as_ref()).expect("deserialize ChannelActorState should be OK")
        })
    }

    fn insert_channel_actor_state(&self, state: ChannelActorState) {
        let mut batch = self.batch();
        batch.put_kv(KeyValue::ChannelActorState(state.id, state.clone()));
        batch.put_kv(KeyValue::PeerIdChannelId(
            (state.get_remote_peer_id(), state.id),
            state.state,
        ));
        batch.commit();
    }

    fn delete_channel_actor_state(&self, id: &Hash256) {
        if let Some(state) = self.get_channel_actor_state(id) {
            let mut batch = self.batch();
            batch.delete([&[CHANNEL_ACTOR_STATE_PREFIX], id.as_ref()].concat());
            batch.delete(
                [
                    &[PEER_ID_CHANNEL_ID_PREFIX],
                    state.get_remote_peer_id().as_bytes(),
                    id.as_ref(),
                ]
                .concat(),
            );
            batch.commit();
        }
    }

    fn get_channel_ids_by_peer(&self, peer_id: &tentacle::secio::PeerId) -> Vec<Hash256> {
        let prefix = [&[PEER_ID_CHANNEL_ID_PREFIX], peer_id.as_bytes()].concat();
        let iter = self
            .db
            .prefix_iterator(prefix.as_ref())
            .take_while(|(key, _)| key.starts_with(&prefix));
        iter.map(|(key, _)| {
            let channel_id: [u8; 32] = key[prefix.len()..]
                .try_into()
                .expect("channel id should be 32 bytes");
            channel_id.into()
        })
        .collect()
    }

    fn get_channel_states(&self, peer_id: Option<PeerId>) -> Vec<(PeerId, Hash256, ChannelState)> {
        let prefix = match peer_id {
            Some(peer_id) => [&[PEER_ID_CHANNEL_ID_PREFIX], peer_id.as_bytes()].concat(),
            None => vec![PEER_ID_CHANNEL_ID_PREFIX],
        };
        let iter = self
            .db
            .prefix_iterator(prefix.as_ref())
            .take_while(|(key, _)| key.starts_with(&prefix));
        iter.map(|(key, value)| {
            let key_len = key.len();
            let peer_id = PeerId::from_bytes(key[1..key_len - 32].into())
                .expect("deserialize peer id should be OK");
            let channel_id: [u8; 32] = key[key_len - 32..]
                .try_into()
                .expect("channel id should be 32 bytes");
            let state = serde_json::from_slice(value.as_ref())
                .expect("deserialize ChannelState should be OK");
            (peer_id, channel_id.into(), state)
        })
        .collect()
    }
}

impl InvoiceStore for Store {
    fn get_invoice(&self, id: &Hash256) -> Option<CkbInvoice> {
        let mut key = Vec::with_capacity(33);
        key.extend_from_slice(&[CKB_INVOICE_PREFIX]);
        key.extend_from_slice(id.as_ref());

        self.get(key).map(|v| {
            serde_json::from_slice(v.as_ref()).expect("deserialize CkbInvoice should be OK")
        })
    }

    fn insert_invoice(
        &self,
        invoice: CkbInvoice,
        preimage: Option<Hash256>,
    ) -> Result<(), InvoiceError> {
        let mut batch = self.batch();
        let hash = invoice.payment_hash();
        if self.get_invoice(hash).is_some() {
            return Err(InvoiceError::DuplicatedInvoice(hash.to_string()));
        }
        if let Some(preimage) = preimage {
            batch.put_kv(KeyValue::CkbInvoicePreimage(*hash, preimage));
        }
        let payment_hash = *invoice.payment_hash();
        batch.put_kv(KeyValue::CkbInvoice(payment_hash, invoice));
        batch.put_kv(KeyValue::CkbInvoiceStatus(
            payment_hash,
            CkbInvoiceStatus::Open,
        ));
        batch.commit();
        return Ok(());
    }

    fn get_invoice_preimage(&self, id: &Hash256) -> Option<Hash256> {
        let mut key = Vec::with_capacity(33);
        key.extend_from_slice(&[CKB_INVOICE_PREIMAGE_PREFIX]);
        key.extend_from_slice(id.as_ref());

        self.get(key)
            .map(|v| serde_json::from_slice(v.as_ref()).expect("deserialize Hash256 should be OK"))
    }

    fn update_invoice_status(
        &self,
        id: &Hash256,
        status: crate::invoice::CkbInvoiceStatus,
    ) -> Result<(), InvoiceError> {
        let _invoice = self.get_invoice(id).ok_or(InvoiceError::InvoiceNotFound)?;
        let mut key = Vec::with_capacity(33);
        key.extend_from_slice(&[CKB_INVOICE_STATUS_PREFIX]);
        key.extend_from_slice(id.as_ref());
        let mut batch = self.batch();
        batch.put_kv(KeyValue::CkbInvoiceStatus(*id, status));
        batch.commit();
        Ok(())
    }

    fn get_invoice_status(&self, id: &Hash256) -> Option<CkbInvoiceStatus> {
        let mut key = Vec::with_capacity(33);
        key.extend_from_slice(&[CKB_INVOICE_STATUS_PREFIX]);
        key.extend_from_slice(id.as_ref());

        self.get(key).map(|v| {
            serde_json::from_slice(v.as_ref()).expect("deserialize CkbInvoiceStatus should be OK")
        })
    }
}

impl GossipMessageStore for Store {
    fn get_broadcast_messages_iter(
        &self,
        after_cursor: &Cursor,
    ) -> impl IntoIterator<Item = BroadcastMessageWithTimestamp> {
        let prefix = [
            &[BROADCAST_MESSAGE_PREFIX],
            after_cursor.to_bytes().as_slice(),
        ]
        .concat();

        self.db
            .prefix_iterator(prefix.as_ref())
            .take_while(move |(key, _)| key.starts_with(&[BROADCAST_MESSAGE_PREFIX]))
            // after_cursor means we should not include key/value with key == cursor
            .skip_while(move |(key, _)| key.as_ref() == &prefix)
            .map(|(key, value)| {
                debug_assert_eq!(key.len(), 1 + CURSOR_SIZE);
                let mut timestamp_bytes = [0u8; 8];
                timestamp_bytes.copy_from_slice(&key[1..9]);
                let timestamp = u64::from_le_bytes(timestamp_bytes);
                let message: BroadcastMessage = serde_json::from_slice(value.as_ref())
                    .expect("deserialize BroadcastMessage should be OK");
                (message, timestamp).into()
            })
    }

    fn get_broadcast_messages(
        &self,
        after_cursor: &Cursor,
        count: Option<u16>,
    ) -> Vec<BroadcastMessageWithTimestamp> {
        let prefix = [
            &[BROADCAST_MESSAGE_PREFIX],
            after_cursor.to_bytes().as_slice(),
        ]
        .concat();
        let count = count.unwrap_or(DEFAULT_NUM_OF_BROADCAST_MESSAGES) as usize;
        let iter = self
            .db
            .prefix_iterator(prefix.as_ref())
            .take_while(|(key, _)| key.starts_with(&prefix));
        iter.take(count)
            .map(|(key, value)| {
                debug_assert_eq!(key.len(), 1 + CURSOR_SIZE);
                let mut timestamp_bytes = [0u8; 8];
                timestamp_bytes.copy_from_slice(&key[1..9]);
                let timestamp = u64::from_le_bytes(timestamp_bytes);
                let message: BroadcastMessage = serde_json::from_slice(value.as_ref())
                    .expect("deserialize BroadcastMessage should be OK");
                (message, timestamp).into()
            })
            .collect()
    }

    fn save_channel_announcement(&self, timestamp: u64, channel_announcement: ChannelAnnouncement) {
        if let Some(_old_timestamp) =
            self.get_latest_channel_announcement_timestamp(&channel_announcement.channel_outpoint)
        {
            // Channel announcement is immutable. If we have already saved one channel announcement,
            // we can early return now.
            return;
        }

        let mut batch = self.batch();
        let cursor = Cursor::new(
            timestamp,
            BroadcastMessageID::ChannelAnnouncement(channel_announcement.channel_outpoint.clone()),
        );

        // Update the timestamps of the channel
        let timestamp_key = [
            &[BROADCAST_MESSAGE_TIMESTAMP_PREFIX],
            cursor.message_id.to_bytes().as_slice(),
        ]
        .concat();
        let mut timestamps = self
            .get(&timestamp_key)
            .map(|v| v.try_into().expect("Invalid timestamp value length"))
            .unwrap_or([0u8; 24]);
        timestamps[..8].copy_from_slice(&timestamp.to_le_bytes());
        batch.put(timestamp_key, timestamps);

        // Save the channel announcement
        let message = BroadcastMessage::ChannelAnnouncement(channel_announcement);
        batch.put(
            [&[BROADCAST_MESSAGE_PREFIX], cursor.to_bytes().as_slice()].concat(),
            serde_json::to_vec(&message).expect("serialize BroadcastMessage should be OK"),
        );
        batch.commit();
    }

    fn save_channel_update(&self, channel_update: ChannelUpdate) {
        let mut batch = self.batch();
        let message_id = BroadcastMessageID::ChannelUpdate(channel_update.channel_outpoint.clone());

        // Remove old channel update if exists
        if let Some(old_timestamp) = self.get_latest_channel_update_timestamp(
            &channel_update.channel_outpoint,
            channel_update.is_update_of_node_1(),
        ) {
            if channel_update.timestamp <= old_timestamp {
                // This is an outdated channel update, early return
                return;
            }
            // Delete old channel update
            batch.delete(
                [
                    &[BROADCAST_MESSAGE_PREFIX],
                    Cursor::new(old_timestamp, message_id.clone())
                        .to_bytes()
                        .as_slice(),
                ]
                .concat(),
            );
        }

        // Update the timestamps of the channel
        let timestamp_key = [
            &[BROADCAST_MESSAGE_TIMESTAMP_PREFIX],
            message_id.to_bytes().as_slice(),
        ]
        .concat();
        let mut timestamps = self
            .get(&timestamp_key)
            .map(|v| v.try_into().expect("Invalid timestamp value length"))
            .unwrap_or([0u8; 24]);
        let start_index = if channel_update.is_update_of_node_1() {
            8
        } else {
            16
        };
        timestamps[start_index..start_index + 8]
            .copy_from_slice(&channel_update.timestamp.to_le_bytes());
        batch.put(timestamp_key, timestamps);

        // Save the channel update
        let cursor = Cursor::new(channel_update.timestamp, message_id);
        let message = BroadcastMessage::ChannelUpdate(channel_update.clone());
        batch.put(
            [&[BROADCAST_MESSAGE_PREFIX], cursor.to_bytes().as_slice()].concat(),
            serde_json::to_vec(&message).expect("serialize BroadcastMessage should be OK"),
        );
        batch.commit();
    }

    fn save_node_announcement(&self, node_announcement: crate::fiber::types::NodeAnnouncement) {
        let mut batch = self.batch();
        let message_id = BroadcastMessageID::NodeAnnouncement(node_announcement.node_id.clone());

        if let Some(old_timestamp) =
            self.get_latest_node_announcement_timestamp(&node_announcement.node_id)
        {
            if node_announcement.timestamp <= old_timestamp {
                // This is an outdated node announcement. Early return.
                return;
            }

            // Delete old node announcement
            batch.delete(
                [
                    &[BROADCAST_MESSAGE_PREFIX],
                    Cursor::new(old_timestamp, message_id.clone())
                        .to_bytes()
                        .as_slice(),
                ]
                .concat(),
            );
        }
        batch.put(
            [
                &[BROADCAST_MESSAGE_TIMESTAMP_PREFIX],
                message_id.to_bytes().as_slice(),
            ]
            .concat(),
            node_announcement.timestamp.to_le_bytes(),
        );

        // Save the channel update
        let cursor = Cursor::new(node_announcement.timestamp, message_id);
        let message = BroadcastMessage::NodeAnnouncement(node_announcement);
        batch.put(
            [&[BROADCAST_MESSAGE_PREFIX], cursor.to_bytes().as_slice()].concat(),
            serde_json::to_vec(&message).expect("serialize BroadcastMessage should be OK"),
        );
        batch.commit();
    }

    fn get_broadcast_message_with_cursor(
        &self,
        cursor: &Cursor,
    ) -> Option<BroadcastMessageWithTimestamp> {
        let timestamp = cursor.timestamp;
        let key = [&[BROADCAST_MESSAGE_PREFIX], cursor.to_bytes().as_slice()].concat();
        self.get(key).map(|v| {
            BroadcastMessageWithTimestamp::from((
                serde_json::from_slice(v.as_ref()).expect("deserialize Hash256 should be OK"),
                timestamp,
            ))
        })
    }

    fn get_latest_broadcast_message_cursor(&self) -> Option<Cursor> {
        let prefix = vec![BROADCAST_MESSAGE_PREFIX];
        let mode = IteratorMode::End;
        self.db
            .iterator(mode)
            .take_while(|(key, _)| key.starts_with(&prefix))
            .last()
            .map(|(key, _)| {
                let last_key = key.to_vec();
                Cursor::from_bytes(&last_key[1..]).expect("deserialize Cursor should be OK")
            })
    }

    fn get_latest_channel_announcement_timestamp(&self, outpoint: &OutPoint) -> Option<u64> {
        let message_id = BroadcastMessageID::ChannelAnnouncement(outpoint.clone());
        let timestamp_key = [
            &[BROADCAST_MESSAGE_TIMESTAMP_PREFIX],
            message_id.to_bytes().as_slice(),
        ]
        .concat();
        self.get(&timestamp_key).map(|v| {
            let v: [u8; 24] = v.try_into().expect("Invalid timestamp value length");
            u64::from_le_bytes(
                v[..8]
                    .try_into()
                    .expect("timestamp length valid, shown above"),
            )
        })
    }

    fn get_latest_channel_update_timestamp(
        &self,
        outpoint: &OutPoint,
        is_node1: bool,
    ) -> Option<u64> {
        let message_id = BroadcastMessageID::ChannelUpdate(outpoint.clone());
        let timestamp_key = [
            &[BROADCAST_MESSAGE_TIMESTAMP_PREFIX],
            message_id.to_bytes().as_slice(),
        ]
        .concat();
        self.get(&timestamp_key).map(|v| {
            let v: [u8; 24] = v.try_into().expect("Invalid timestamp value length");
            let start_index = if is_node1 { 8 } else { 16 };
            u64::from_le_bytes(
                v[start_index..start_index + 8]
                    .try_into()
                    .expect("timestamp length valid, shown above"),
            )
        })
    }

    fn get_latest_node_announcement_timestamp(&self, pk: &Pubkey) -> Option<u64> {
        let message_id = BroadcastMessageID::NodeAnnouncement(pk.clone());
        let timestamp_key = [
            &[BROADCAST_MESSAGE_TIMESTAMP_PREFIX],
            message_id.to_bytes().as_slice(),
        ]
        .concat();
        self.get(&timestamp_key)
            .map(|v| u64::from_le_bytes(v.try_into().expect("Invalid timestamp value length")))
    }
}

impl NetworkGraphStateStore for Store {
    fn get_payment_session(&self, payment_hash: Hash256) -> Option<PaymentSession> {
        let prefix = [&[PAYMENT_SESSION_PREFIX], payment_hash.as_ref()].concat();
        self.get(prefix).map(|v| {
            serde_json::from_slice(v.as_ref()).expect("deserialize PaymentSession should be OK")
        })
    }

    fn insert_payment_session(&self, session: PaymentSession) {
        let mut batch = self.batch();
        batch.put_kv(KeyValue::PaymentSession(session.payment_hash(), session));
        batch.commit();
    }
}

impl WatchtowerStore for Store {
    fn get_watch_channels(&self) -> Vec<ChannelData> {
        let prefix = vec![WATCHTOWER_CHANNEL_PREFIX];
        let iter = self
            .db
            .prefix_iterator(prefix.as_ref())
            .take_while(|(col_key, _)| col_key.starts_with(&prefix));
        iter.map(|(_key, value)| {
            serde_json::from_slice(value.as_ref()).expect("deserialize ChannelData should be OK")
        })
        .collect()
    }

    fn insert_watch_channel(&self, channel_id: Hash256, funding_tx_lock: Script) {
        let mut batch = self.batch();
        let key = [&[WATCHTOWER_CHANNEL_PREFIX], channel_id.as_ref()].concat();
        batch.put(
            key,
            serde_json::to_vec(&ChannelData {
                channel_id,
                funding_tx_lock,
                revocation_data: None,
            })
            .expect("serialize ChannelData should be OK"),
        );
        batch.commit();
    }

    fn remove_watch_channel(&self, channel_id: Hash256) {
        let key = [&[WATCHTOWER_CHANNEL_PREFIX], channel_id.as_ref()].concat();
        self.db.delete(key).expect("delete should be OK");
    }

    fn update_revocation(&self, channel_id: Hash256, revocation_data: RevocationData) {
        let key = [&[WATCHTOWER_CHANNEL_PREFIX], channel_id.as_ref()].concat();
        if let Some(mut channel_data) = self.get(key).map(|v| {
            serde_json::from_slice::<ChannelData>(v.as_ref())
                .expect("deserialize ChannelData should be OK")
        }) {
            channel_data.revocation_data = Some(revocation_data);
            let mut batch = self.batch();
            batch.put_kv(KeyValue::WatchtowerChannel(channel_id, channel_data));
            batch.commit();
        }
    }
}

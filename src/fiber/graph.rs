use super::config::AnnouncedNodeName;
use super::gossip::GossipMessageStore;
use super::network::{get_chain_hash, SendPaymentData, SendPaymentResponse};
use super::path::NodeHeap;
use super::types::{
    BroadcastMessageID, BroadcastMessageWithTimestamp, ChannelAnnouncement, ChannelUpdate, Hash256,
    NodeAnnouncement,
};
use super::types::{Cursor, Pubkey};
use crate::ckb::config::UdtCfgInfos;
use crate::fiber::fee::calculate_tlc_forward_fee;
use crate::fiber::path::{NodeHeapElement, ProbabilityEvaluator};
use crate::fiber::serde_utils::EntityHex;
use crate::fiber::types::PaymentHopData;
use crate::invoice::CkbInvoice;
use ckb_types::packed::{OutPoint, Script};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use std::collections::HashMap;
use tentacle::multiaddr::MultiAddr;
use tentacle::secio::PeerId;
use thiserror::Error;
use tracing::log::error;
use tracing::{debug, info, trace};

const DEFAULT_MIN_PROBABILITY: f64 = 0.01;

#[serde_as]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
/// Details about a node in the network, known from the network announcement.
pub struct NodeInfo {
    pub node_id: Pubkey,
    // The timestamp set by the owner for the node announcement.
    pub timestamp: u64,
    // Tentatively using 64 bits for features. May change the type later while developing.
    // rust-lightning uses a Vec<u8> here.
    pub features: u64,
    // The alias of the node. This is a human-readable string that is meant to be used for labelling nodes in the UI.
    pub alias: AnnouncedNodeName,
    // All the reachable addresses.
    pub addresses: Vec<MultiAddr>,
    // If the other party funding more than this amount, we will automatically accept the channel.
    pub auto_accept_min_ckb_funding_amount: u64,
    // UDT config info
    pub udt_cfg_infos: UdtCfgInfos,
}

impl NodeInfo {
    pub fn cursor(&self) -> Cursor {
        Cursor::new(
            self.timestamp,
            BroadcastMessageID::NodeAnnouncement(self.node_id),
        )
    }
}

impl From<NodeAnnouncement> for NodeInfo {
    fn from(value: NodeAnnouncement) -> Self {
        Self {
            node_id: value.node_id,
            timestamp: value.timestamp,
            features: value.features,
            alias: value.alias,
            addresses: value.addresses,
            auto_accept_min_ckb_funding_amount: value.auto_accept_min_ckb_funding_amount,
            udt_cfg_infos: value.udt_cfg_infos,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct ChannelInfo {
    pub channel_outpoint: OutPoint,
    // The timestamp in the block header of the block that includes the funding transaction of the channel.
    pub timestamp: u64,

    pub features: u64,
    pub node1: Pubkey,
    pub node2: Pubkey,
    // The total capacity of the channel.
    pub capacity: u128,
    // UDT script
    pub udt_type_script: Option<Script>,
    pub update_of_node1: Option<ChannelUpdateInfo>,
    pub update_of_node2: Option<ChannelUpdateInfo>,
}

impl ChannelInfo {
    pub fn cursor(&self) -> Cursor {
        Cursor::new(
            self.timestamp,
            BroadcastMessageID::ChannelAnnouncement(self.channel_outpoint.clone()),
        )
    }

    pub fn out_point(&self) -> &OutPoint {
        &self.channel_outpoint
    }

    pub fn capacity(&self) -> u128 {
        self.capacity
    }

    pub fn node1(&self) -> Pubkey {
        self.node1
    }

    pub fn node2(&self) -> Pubkey {
        self.node2
    }

    pub fn node1_peerid(&self) -> PeerId {
        self.node1.tentacle_peer_id()
    }

    pub fn node2_peerid(&self) -> PeerId {
        self.node2.tentacle_peer_id()
    }

    pub fn udt_type_script(&self) -> &Option<Script> {
        &self.udt_type_script
    }

    // Whether this channel is explicitly disabled in either direction.
    // TODO: we currently deem a channel as disabled if one direction is disabled.
    // Is it possible that one direction is disabled while the other is not?
    pub fn is_explicitly_disabled(&self) -> bool {
        dbg!(self.update_of_node2.as_ref(), self.update_of_node1.as_ref());
        match (&self.update_of_node2, &self.update_of_node1) {
            (Some(update1), _) if !update1.enabled => true,
            (_, Some(update2)) if !update2.enabled => true,
            _ => false,
        }
    }
}

impl From<(u64, ChannelAnnouncement)> for ChannelInfo {
    fn from((timestamp, channel_announcement): (u64, ChannelAnnouncement)) -> Self {
        Self {
            channel_outpoint: channel_announcement.channel_outpoint,
            timestamp,
            features: channel_announcement.features,
            node1: channel_announcement.node1_id,
            node2: channel_announcement.node2_id,
            capacity: channel_announcement.capacity,
            udt_type_script: channel_announcement.udt_type_script,
            update_of_node2: None,
            update_of_node1: None,
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ChannelUpdateInfo {
    // The timestamp is the time when the channel update was received by the node.
    pub timestamp: u64,
    /// Whether the channel can be currently used for payments (in this one direction).
    pub enabled: bool,
    /// The difference in htlc expiry values that you must have when routing through this channel (in milliseconds).
    pub htlc_expiry_delta: u64,
    /// The minimum value, which must be relayed to the next hop via the channel
    pub htlc_minimum_value: u128,
    /// The maximum value which may be relayed to the next hop via the channel.
    pub htlc_maximum_value: u128,
    pub fee_rate: u64,
}

impl From<ChannelUpdate> for ChannelUpdateInfo {
    fn from(update: ChannelUpdate) -> Self {
        Self::from(&update)
    }
}

impl From<&ChannelUpdate> for ChannelUpdateInfo {
    fn from(update: &ChannelUpdate) -> Self {
        Self {
            timestamp: update.timestamp,
            enabled: !update.is_disabled(),
            htlc_expiry_delta: update.tlc_expiry_delta,
            htlc_minimum_value: update.tlc_minimum_value,
            htlc_maximum_value: update.tlc_maximum_value,
            fee_rate: update.tlc_fee_proportional_millionths as u64,
        }
    }
}

#[derive(Clone, Debug)]
pub struct NetworkGraph<S> {
    // The pubkey of the node that is running this instance of the network graph.
    source: Pubkey,
    // All the channels in the network.
    channels: HashMap<OutPoint, ChannelInfo>,
    // All the nodes in the network.
    nodes: HashMap<Pubkey, NodeInfo>,
    // The latest cursor we read from the GossipMessageStore. When we need to refresh our view of the
    // the network, we need to load all the messages starting from this cursor.
    latest_cursor: Cursor,
    // A store is both a persistent storage from which we can fetch all the network messages.
    // and a state store where we can store our local state (e.g. when a node has been unresponsive
    // for a few rounds, we need to mark it as failed, this information needs to be persisted).
    // The formal use of the store is defined as a GossipMessageStore, while the latter is defined
    // as a NetworkGraphStateStore.
    store: S,
}

#[derive(Error, Debug)]
pub enum GraphError {
    #[error("Graph error: {0}")]
    Amount(String),
    #[error("PathFind error: {0}")]
    PathFind(String),
    #[error("Graph other error: {0}")]
    Other(String),
}

#[derive(Clone, Debug)]
pub struct PathEdge {
    pub target: Pubkey,
    pub channel_outpoint: OutPoint,
}

impl<S> NetworkGraph<S>
where
    S: NetworkGraphStateStore + GossipMessageStore + Clone + Send + Sync + 'static,
{
    pub fn new(store: S, source: Pubkey) -> Self {
        let mut network_graph = Self {
            source,
            channels: HashMap::new(),
            nodes: HashMap::new(),
            latest_cursor: Cursor::default(),
            store,
        };
        network_graph.load_from_store();
        network_graph
    }

    fn update_lastest_cursor(&mut self, cursor: Cursor) {
        if cursor > self.latest_cursor {
            self.latest_cursor = cursor;
        }
    }

    // Load all the broadcast messages starting from latest_cursor from the store.
    // Process them and set nodes and channels accordingly.
    pub(crate) fn load_from_store(&mut self) {
        dbg!(&self.channels, &self.nodes);
        loop {
            dbg!(&self.latest_cursor);
            let messages = self.store.get_broadcast_messages(&self.latest_cursor, None);
            dbg!(&messages);
            if messages.is_empty() {
                break;
            }
            for message in messages {
                if message.chain_hash() != get_chain_hash() {
                    continue;
                }
                let cursor = match message {
                    BroadcastMessageWithTimestamp::ChannelAnnouncement(
                        timestamp,
                        channel_announcement,
                    ) => self.process_channel_announcement(timestamp, channel_announcement),
                    BroadcastMessageWithTimestamp::ChannelUpdate(channel_update) => {
                        self.process_channel_update(channel_update)
                    }
                    BroadcastMessageWithTimestamp::NodeAnnouncement(node_announcement) => {
                        self.process_node_announcement(node_announcement)
                    }
                };
                if let Some(cursor) = cursor {
                    self.update_lastest_cursor(cursor);
                }
            }
        }
        dbg!(&self.channels, &self.nodes);
    }

    fn load_channel_updates_from_store(&self, channel_info: &mut ChannelInfo) {
        let channel_update_of_node1 = self
            .store
            .get_latest_channel_update(&channel_info.channel_outpoint, true)
            .map(Into::into);
        let channel_update_of_node2 = self
            .store
            .get_latest_channel_update(&channel_info.channel_outpoint, false)
            .map(Into::into);
        channel_info.update_of_node1 = channel_update_of_node1;
        channel_info.update_of_node2 = channel_update_of_node2;
    }

    fn process_channel_announcement(
        &mut self,
        timestamp: u64,
        channel_announcement: ChannelAnnouncement,
    ) -> Option<Cursor> {
        match self.channels.get(&channel_announcement.channel_outpoint) {
            Some(_channel) => {
                trace!(
                    "Channel already exists, ignoring: {:?}",
                    &channel_announcement
                );
                return None;
            }
            None => {
                let cursor = Cursor::new(
                    timestamp,
                    BroadcastMessageID::ChannelAnnouncement(
                        channel_announcement.channel_outpoint.clone(),
                    ),
                );
                self.channels.insert(
                    channel_announcement.channel_outpoint.clone(),
                    ChannelInfo::from((timestamp, channel_announcement)),
                );
                return Some(cursor);
            }
        }
    }

    fn process_channel_update(&mut self, channel_update: ChannelUpdate) -> Option<Cursor> {
        let channel_outpoint = &channel_update.channel_outpoint;
        // TODO: There is a slim chance that the channel update is received before the channel announcement.
        let channel = self.channels.get_mut(channel_outpoint)?;
        let update_info = if channel_update.is_update_of_node_1() {
            &mut channel.update_of_node1
        } else {
            &mut channel.update_of_node2
        };

        match update_info {
            Some(old_update) if old_update.timestamp > channel_update.timestamp => {
                trace!(
                    "Ignoring outdated channel update {:?} for channel {:?}",
                    &channel_update,
                    &channel
                );
                return None;
            }
            _ => {
                let cursor = Cursor::new(
                    channel_update.timestamp,
                    BroadcastMessageID::ChannelUpdate(channel_update.channel_outpoint.clone()),
                );
                *update_info = Some(ChannelUpdateInfo::from(channel_update));
                return Some(cursor);
            }
        }
    }

    fn process_node_announcement(&mut self, node_announcement: NodeAnnouncement) -> Option<Cursor> {
        let node_info = NodeInfo::from(node_announcement);
        match self.nodes.get(&node_info.node_id) {
            Some(old_node) if old_node.timestamp > node_info.timestamp => {
                trace!(
                    "Ignoring outdated node announcement {:?} for node {:?}",
                    &node_info,
                    &old_node
                );
                return None;
            }
            _ => {
                let cursor = Cursor::new(
                    node_info.timestamp,
                    BroadcastMessageID::NodeAnnouncement(node_info.node_id),
                );
                self.nodes.insert(node_info.node_id, node_info);
                return Some(cursor);
            }
        }
    }

    pub fn nodes(&self) -> impl Iterator<Item = &NodeInfo> {
        self.nodes.values()
    }

    pub fn get_nodes_with_params(&self, limit: usize, after: Option<Cursor>) -> Vec<NodeInfo> {
        let cursor = after.unwrap_or_default();
        self.store
            .get_broadcast_messages_iter(&cursor)
            .into_iter()
            .filter_map(|message| match message {
                BroadcastMessageWithTimestamp::NodeAnnouncement(node_announcement) => {
                    Some(NodeInfo::from(node_announcement))
                }
                _ => None,
            })
            .take(limit)
            .collect()
    }

    pub fn get_node(&self, node_id: Pubkey) -> Option<&NodeInfo> {
        self.nodes.get(&node_id)
    }

    pub fn channels(&self) -> impl Iterator<Item = &ChannelInfo> {
        self.channels.values()
    }

    pub fn get_channel(&self, outpoint: &OutPoint) -> Option<&ChannelInfo> {
        self.channels.get(outpoint)
    }

    pub fn get_channels_with_params(
        &self,
        limit: usize,
        after: Option<Cursor>,
    ) -> Vec<ChannelInfo> {
        let cursor = after.unwrap_or_default();
        self.store
            .get_broadcast_messages_iter(&cursor)
            .into_iter()
            .filter_map(|message| match message {
                BroadcastMessageWithTimestamp::ChannelAnnouncement(
                    timestamp,
                    channel_announcement,
                ) => {
                    let mut channel_info = ChannelInfo::from((timestamp, channel_announcement));
                    self.load_channel_updates_from_store(&mut channel_info);
                    Some(channel_info)
                }
                _ => None,
            })
            .take(limit)
            .collect()
    }

    pub fn get_channels_by_peer(&self, node_id: Pubkey) -> impl Iterator<Item = &ChannelInfo> {
        self.channels
            .values()
            .filter(move |channel| channel.node1() == node_id || channel.node2() == node_id)
    }

    pub fn get_mut_channels_by_peer(
        &mut self,
        node_id: Pubkey,
    ) -> impl Iterator<Item = &mut ChannelInfo> {
        self.channels
            .values_mut()
            .filter(move |channel| channel.node1() == node_id || channel.node2() == node_id)
    }

    pub fn get_node_inbounds(
        &self,
        node_id: Pubkey,
    ) -> impl Iterator<Item = (Pubkey, &ChannelInfo, &ChannelUpdateInfo)> {
        self.channels.values().filter_map(move |channel| {
            if let Some(info) = channel.update_of_node2.as_ref() {
                if info.enabled && channel.node2() == node_id {
                    return Some((channel.node1(), channel, info));
                }
            }

            if let Some(info) = channel.update_of_node1.as_ref() {
                if info.enabled && channel.node1() == node_id {
                    return Some((channel.node2(), channel, info));
                }
            }
            None
        })
    }

    pub fn get_source_pubkey(&self) -> Pubkey {
        self.source
    }

    pub(crate) fn mark_channel_failed(&mut self, channel_outpoint: &OutPoint) {
        if let Some(channel) = self.channels.get_mut(channel_outpoint) {
            if let Some(info) = channel.update_of_node2.as_mut() {
                info.enabled = false;
            }
            if let Some(info) = channel.update_of_node1.as_mut() {
                info.enabled = false;
            }
        }
    }

    pub(crate) fn mark_node_failed(&mut self, node_id: Pubkey) {
        for channel in self.get_mut_channels_by_peer(node_id) {
            if channel.node1() == node_id {
                if let Some(info) = channel.update_of_node2.as_mut() {
                    info.enabled = false;
                }
            } else {
                if let Some(info) = channel.update_of_node1.as_mut() {
                    info.enabled = false;
                }
            }
        }
    }

    /// Returns a list of `PaymentHopData` for all nodes in the route, including the origin and the target node.
    pub fn build_route(
        &self,
        payment_data: &SendPaymentData,
    ) -> Result<Vec<PaymentHopData>, GraphError> {
        let payment_data = payment_data.clone();
        let source = self.get_source_pubkey();
        let target = payment_data.target_pubkey;
        let amount = payment_data.amount;
        let preimage = payment_data.preimage;
        let payment_hash = payment_data.payment_hash;
        let udt_type_script = payment_data.udt_type_script;
        let invoice = payment_data
            .invoice
            .map(|x| x.parse::<CkbInvoice>().expect("parse CKB invoice"));
        let hash_algorithm = invoice
            .as_ref()
            .and_then(|x| x.hash_algorithm().copied())
            .unwrap_or_default();

        info!(
            "build_route source: {:?} target: {:?} amount: {:?}, payment_hash: {:?}",
            source, target, amount, payment_hash
        );

        let allow_self_payment = payment_data.allow_self_payment;
        if source == target && !allow_self_payment {
            return Err(GraphError::PathFind(
                "source and target are the same and allow_self_payment is not enable".to_string(),
            ));
        }

        let route = self.find_route(
            source,
            target,
            amount,
            payment_data.max_fee_amount,
            udt_type_script,
            allow_self_payment,
        )?;
        assert!(!route.is_empty());

        let mut current_amount = amount;
        let mut current_expiry = 0;
        let mut onion_infos = vec![];
        for i in (0..route.len()).rev() {
            let is_last = i == route.len() - 1;
            let (next_hop, next_channel_outpoint) = if is_last {
                (None, None)
            } else {
                (
                    Some(route[i + 1].target),
                    Some(route[i + 1].channel_outpoint.clone()),
                )
            };
            let (fee, expiry) = if is_last {
                (0, 0)
            } else {
                let channel_info = self
                    .get_channel(&route[i + 1].channel_outpoint)
                    .expect("channel not found");
                let channel_update = &if channel_info.node1() == route[i + 1].target {
                    channel_info.update_of_node1.as_ref()
                } else {
                    channel_info.update_of_node2.as_ref()
                }
                .expect("channel_update is none");
                let fee_rate = channel_update.fee_rate;
                let fee = calculate_tlc_forward_fee(current_amount, fee_rate as u128);
                let expiry = channel_update.htlc_expiry_delta;
                (fee, expiry)
            };

            // make sure the final hop's amount is the same as the payment amount
            // the last hop will check the amount from TLC and the amount from the onion packet
            onion_infos.push(PaymentHopData {
                amount: current_amount,
                payment_hash,
                next_hop,
                tlc_hash_algorithm: hash_algorithm,
                expiry: current_expiry,
                channel_outpoint: next_channel_outpoint,
                preimage: if is_last { preimage } else { None },
            });
            current_amount += fee;
            current_expiry += expiry;
        }
        // Add the first hop as the instruction for the current node, so the logic for send HTLC can be reused.
        onion_infos.push(PaymentHopData {
            amount: current_amount,
            payment_hash,
            next_hop: Some(route[0].target),
            tlc_hash_algorithm: hash_algorithm,
            expiry: current_expiry,
            channel_outpoint: Some(route[0].channel_outpoint.clone()),
            preimage: None,
        });
        onion_infos.reverse();
        assert_eq!(onion_infos.len(), route.len() + 1);
        assert_eq!(onion_infos[route.len()].amount, amount);
        Ok(onion_infos)
    }

    // the algorithm works from target-to-source to find the shortest path
    pub fn find_route(
        &self,
        source: Pubkey,
        target: Pubkey,
        amount: u128,
        max_fee_amount: Option<u128>,
        udt_type_script: Option<Script>,
        allow_self: bool,
    ) -> Result<Vec<PathEdge>, GraphError> {
        let started_time = std::time::Instant::now();
        let nodes_len = self.nodes.len();
        let mut result = vec![];
        let mut nodes_visited = 0;
        let mut edges_expanded = 0;
        let mut nodes_heap = NodeHeap::new(nodes_len);
        let mut distances = HashMap::<Pubkey, NodeHeapElement>::new();

        if amount == 0 {
            return Err(GraphError::Amount(
                "Amount must be greater than 0".to_string(),
            ));
        }

        if source == target && !allow_self {
            return Err(GraphError::PathFind(
                "source and target are the same".to_string(),
            ));
        }

        let Some(source_node) = self.nodes.get(&source) else {
            return Err(GraphError::PathFind(format!(
                "source node not found: {:?}",
                &source
            )));
        };
        let Some(_target_node) = self.nodes.get(&target) else {
            return Err(GraphError::PathFind(format!(
                "target node not found: {:?}",
                &target
            )));
        };

        // initialize the target node
        nodes_heap.push(NodeHeapElement {
            node_id: target,
            weight: 0,
            distance: 0,
            amount_received: amount,
            fee_charged: 0,
            probability: 1.0,
            next_hop: None,
            incoming_htlc_expiry: 0,
        });
        let route_to_self = source == target;
        let mut last_hop_channels = HashMap::new();
        while let Some(cur_hop) = nodes_heap.pop() {
            nodes_visited += 1;

            for (from, channel_info, channel_update) in self.get_node_inbounds(cur_hop.node_id) {
                if from == target && !route_to_self {
                    continue;
                }
                if &udt_type_script != channel_info.udt_type_script() {
                    continue;
                }

                // if the channel is already visited in the last hop, skip it
                if last_hop_channels
                    .values()
                    .any(|x| x == &channel_info.out_point())
                {
                    continue;
                }

                edges_expanded += 1;

                let fee_rate = channel_update.fee_rate;
                let next_hop_received_amount = cur_hop.amount_received;
                let fee = calculate_tlc_forward_fee(next_hop_received_amount, fee_rate as u128);
                let amount_to_send = next_hop_received_amount + fee;

                // if the amount to send is greater than the amount we have, skip this edge
                if let Some(max_fee_amount) = max_fee_amount {
                    if amount_to_send > amount + max_fee_amount {
                        debug!(
                            "amount_to_send: {:?} is greater than sum_amount sum_amount: {:?}",
                            amount_to_send,
                            amount + max_fee_amount
                        );
                        continue;
                    }
                }
                // check to make sure the current hop can send the amount
                // if `htlc_maximum_value` equals 0, it means there is no limit
                if amount_to_send > channel_info.capacity()
                    || (channel_update.htlc_maximum_value != 0
                        && amount_to_send > channel_update.htlc_maximum_value)
                {
                    debug!(
                        "amount_to_send is greater than channel capacity: {:?} capacity: {:?}, htlc_max_value: {:?}",
                        amount_to_send,
                        channel_info.capacity(),
                        channel_update.htlc_maximum_value
                    );
                    continue;
                }
                if amount_to_send < channel_update.htlc_minimum_value {
                    debug!(
                        "amount_to_send is less than htlc_minimum_value: {:?} min_value: {:?}",
                        amount_to_send, channel_update.htlc_minimum_value
                    );
                    continue;
                }
                let incoming_htlc_expiry = cur_hop.incoming_htlc_expiry
                    + if from == source {
                        0
                    } else {
                        channel_update.htlc_expiry_delta
                    };

                let probability = cur_hop.probability
                    * ProbabilityEvaluator::evaluate_probability(
                        from,
                        cur_hop.node_id,
                        amount_to_send,
                        channel_info.capacity(),
                    );

                if probability < DEFAULT_MIN_PROBABILITY {
                    debug!("probability is too low: {:?}", probability);
                    continue;
                }
                let agg_weight =
                    self.edge_weight(amount_to_send, fee, channel_update.htlc_expiry_delta);
                let weight = cur_hop.weight + agg_weight;
                let distance = self.calculate_distance_based_probability(probability, weight);

                if let Some(node) = distances.get(&from) {
                    if distance >= node.distance {
                        continue;
                    }
                }
                let node = NodeHeapElement {
                    node_id: from,
                    weight,
                    distance,
                    amount_received: amount_to_send,
                    incoming_htlc_expiry,
                    fee_charged: fee,
                    probability,
                    next_hop: Some((cur_hop.node_id, channel_info.out_point().clone())),
                };
                last_hop_channels.insert(node.node_id, channel_info.out_point());
                distances.insert(node.node_id, node.clone());
                nodes_heap.push_or_fix(node);
            }
        }

        let mut current = source_node.node_id;
        loop {
            if let Some(elem) = distances.get(&current) {
                let next_hop = elem.next_hop.as_ref().expect("next_hop is none");
                result.push(PathEdge {
                    target: next_hop.0,
                    channel_outpoint: next_hop.1.clone(),
                });
                current = next_hop.0;
            } else {
                break;
            }
            if current == target {
                break;
            }
        }

        info!(
            "get_route: nodes visited: {}, edges expanded: {}, time: {:?}, result: {:?}",
            nodes_visited,
            edges_expanded,
            started_time.elapsed(),
            result
        );
        if result.is_empty() || current != target {
            return Err(GraphError::PathFind("no path found".to_string()));
        }
        Ok(result)
    }

    fn edge_weight(&self, amount: u128, fee: u128, htlc_expiry_delta: u64) -> u128 {
        let risk_factor: u128 = 15;
        let time_lock_penalty = amount * htlc_expiry_delta as u128 * (risk_factor / 1000000000);
        fee + time_lock_penalty
    }

    fn calculate_distance_based_probability(&self, probability: f64, weight: u128) -> u128 {
        // FIXME: set this to configurable parameters
        let weight = weight as f64;
        let time_pref = 0.5_f64;
        let default_attemp_cost = 0.1_f64;
        let penalty = default_attemp_cost * (1.0 / (0.5 - time_pref / 2.0) - 1.0);
        weight as u128 + (penalty / probability) as u128
    }
}

pub trait NetworkGraphStateStore {
    fn get_payment_session(&self, payment_hash: Hash256) -> Option<PaymentSession>;
    fn insert_payment_session(&self, session: PaymentSession);
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum PaymentSessionStatus {
    // initial status, payment session is created, no HTLC is sent
    Created,
    // related HTLC is send and waiting for the response
    Inflight,
    // related HTLC is successfully settled
    Success,
    // related HTLC is failed
    Failed,
}

#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PaymentSession {
    pub request: SendPaymentData,
    pub retried_times: u32,
    pub last_error: Option<String>,
    pub try_limit: u32,
    pub status: PaymentSessionStatus,
    pub created_at: u128,
    pub last_updated_at: u128,
    // The channel_outpoint and the tlc_id of the first hop
    #[serde_as(as = "Option<EntityHex>")]
    pub first_hop_channel_outpoint: Option<OutPoint>,
    pub first_hop_tlc_id: Option<u64>,
}

impl PaymentSession {
    pub fn new(request: SendPaymentData, try_limit: u32) -> Self {
        let now = std::time::UNIX_EPOCH
            .elapsed()
            .expect("Duration since unix epoch")
            .as_millis();
        Self {
            request,
            retried_times: 0,
            last_error: None,
            try_limit,
            status: PaymentSessionStatus::Created,
            created_at: now,
            last_updated_at: now,
            first_hop_channel_outpoint: None,
            first_hop_tlc_id: None,
        }
    }

    pub fn payment_hash(&self) -> Hash256 {
        self.request.payment_hash
    }

    pub fn set_status(&mut self, status: PaymentSessionStatus) {
        self.status = status;
        self.last_updated_at = std::time::UNIX_EPOCH
            .elapsed()
            .expect("Duration since unix epoch")
            .as_micros();
    }

    pub fn set_first_hop_info(&mut self, channel_outpoint: OutPoint, tlc_id: u64) {
        self.first_hop_channel_outpoint = Some(channel_outpoint);
        self.first_hop_tlc_id = Some(tlc_id);
    }

    pub fn set_success_status(&mut self) {
        self.set_status(PaymentSessionStatus::Success);
        self.last_error = None;
    }

    pub fn set_failed_status(&mut self, error: &str) {
        self.set_status(PaymentSessionStatus::Failed);
        self.last_error = Some(error.to_string());
    }

    pub fn can_retry(&self) -> bool {
        self.retried_times < self.try_limit
    }
}

impl From<PaymentSession> for SendPaymentResponse {
    fn from(session: PaymentSession) -> Self {
        Self {
            payment_hash: session.request.payment_hash,
            status: session.status,
            failed_error: session.last_error,
            created_at: session.created_at,
            last_updated_at: session.last_updated_at,
        }
    }
}

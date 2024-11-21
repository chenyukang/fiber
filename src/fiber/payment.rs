use super::channel::{ChannelActorStateStore, ChannelCommand};
use super::graph::{NetworkGraphStateStore, SessionRoute};
use super::network::{
    NetworkActorState, NetworkActorStateStore, SendPaymentCommand, SendPaymentResponse,
};
use super::types::{
    Hash256, PaymentHopData, Privkey, Pubkey, RemoveTlcReason, TlcErr, TlcErrData, TlcErrPacket,
    TlcErrorCode,
};
use super::NetworkActor;
use crate::fiber::channel::{AddTlcCommand, AddTlcResponse};
use crate::fiber::graph::{PaymentSession, PaymentSessionStatus};
use crate::fiber::serde_utils::EntityHex;
use crate::fiber::types::PeeledPaymentOnionPacket;
use crate::fiber::KeyPair;
use crate::invoice::{CkbInvoice, InvoiceStore};
use crate::Error;
use ckb_hash::blake2b_256;
use ckb_types::packed::Script;
use ractor::RpcReplyPort;
use rand::Rng;
use secp256k1::Secp256k1;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use std::u64;
use tokio::sync::oneshot;
use tracing::{debug, error, info};
#[derive(Debug)]
pub struct SendOnionPacketCommand {
    pub packet: Vec<u8>,
    pub previous_tlc: Option<(Hash256, u64)>,
}

#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SendPaymentData {
    pub target_pubkey: Pubkey,
    pub amount: u128,
    pub payment_hash: Hash256,
    pub invoice: Option<String>,
    pub final_htlc_expiry_delta: Option<u64>,
    pub timeout: Option<u64>,
    pub max_fee_amount: Option<u128>,
    pub max_parts: Option<u64>,
    pub keysend: bool,
    #[serde_as(as = "Option<EntityHex>")]
    pub udt_type_script: Option<Script>,
    pub preimage: Option<Hash256>,
    pub allow_self_payment: bool,
}

impl SendPaymentData {
    pub fn new(command: SendPaymentCommand, source: Pubkey) -> Result<SendPaymentData, String> {
        let invoice = command
            .invoice
            .as_ref()
            .map(|invoice| invoice.parse::<CkbInvoice>())
            .transpose()
            .map_err(|_| "invoice is invalid".to_string())?;

        if let Some(invoice) = invoice.clone() {
            if invoice.is_expired() {
                return Err("invoice is expired".to_string());
            }
        }

        fn validate_field<T: PartialEq + Clone>(
            field: Option<T>,
            invoice_field: Option<T>,
            field_name: &str,
        ) -> Result<T, String> {
            match (field, invoice_field) {
                (Some(f), Some(i)) => {
                    if f != i {
                        return Err(format!("{} does not match the invoice", field_name));
                    }
                    Ok(f)
                }
                (Some(f), None) => Ok(f),
                (None, Some(i)) => Ok(i),
                (None, None) => Err(format!("{} is missing", field_name)),
            }
        }

        let target = validate_field(
            command.target_pubkey,
            invoice
                .as_ref()
                .and_then(|i| i.payee_pub_key().cloned().map(Pubkey::from)),
            "target_pubkey",
        )?;

        if !command.allow_self_payment && target == source {
            return Err("allow_self_payment is not enable, can not pay self".to_string());
        }

        let amount = validate_field(
            command.amount,
            invoice.as_ref().and_then(|i| i.amount()),
            "amount",
        )?;

        let udt_type_script = match validate_field(
            command.udt_type_script.clone(),
            invoice.as_ref().and_then(|i| i.udt_type_script().cloned()),
            "udt_type_script",
        ) {
            Ok(script) => Some(script),
            Err(e) if e == "udt_type_script is missing" => None,
            Err(e) => return Err(e),
        };

        let keysend = command.keysend.unwrap_or(false);
        let (payment_hash, preimage) = if !keysend {
            (
                validate_field(
                    command.payment_hash,
                    invoice.as_ref().map(|i| *i.payment_hash()),
                    "payment_hash",
                )?,
                None,
            )
        } else {
            if invoice.is_some() {
                return Err("keysend payment should not have invoice".to_string());
            }
            if command.payment_hash.is_some() {
                return Err("keysend payment should not have payment_hash".to_string());
            }
            // generate a random preimage for keysend payment
            let mut rng = rand::thread_rng();
            let mut result = [0u8; 32];
            rng.fill(&mut result[..]);
            let preimage: Hash256 = result.into();
            // use the default payment hash algorithm here for keysend payment
            let payment_hash: Hash256 = blake2b_256(preimage).into();
            (payment_hash, Some(preimage))
        };

        Ok(SendPaymentData {
            target_pubkey: target,
            amount,
            payment_hash,
            invoice: command.invoice,
            final_htlc_expiry_delta: command.final_htlc_expiry_delta,
            timeout: command.timeout,
            max_fee_amount: command.max_fee_amount,
            max_parts: command.max_parts,
            keysend,
            udt_type_script,
            preimage,
            allow_self_payment: command.allow_self_payment,
        })
    }
}

impl<S> NetworkActor<S>
where
    S: NetworkActorStateStore
        + ChannelActorStateStore
        + NetworkGraphStateStore
        + InvoiceStore
        + Clone
        + Send
        + Sync
        + 'static,
{
    pub(crate) async fn handle_send_onion_packet_command(
        &self,
        state: &mut NetworkActorState<S>,
        command: SendOnionPacketCommand,
        reply: RpcReplyPort<Result<u64, TlcErrPacket>>,
    ) {
        let SendOnionPacketCommand {
            packet,
            previous_tlc,
        } = command;

        let invalid_onion_error = |reply: RpcReplyPort<Result<u64, TlcErrPacket>>| {
            let error_detail =
                TlcErr::new_node_fail(TlcErrorCode::InvalidOnionPayload, state.get_public_key());
            reply
                .send(Err(TlcErrPacket::new(error_detail)))
                .expect("send error failed");
        };

        let Ok(peeled_packet) = PeeledPaymentOnionPacket::deserialize(&packet) else {
            info!("onion packet is empty, ignore it");
            return invalid_onion_error(reply);
        };

        let info = peeled_packet.current;
        debug!("Processing onion packet info: {:?}", info);

        let Some(channel_outpoint) = &info.channel_outpoint else {
            return invalid_onion_error(reply);
        };

        let unknown_next_peer = |reply: RpcReplyPort<Result<u64, TlcErrPacket>>| {
            let error_detail = TlcErr::new_channel_fail(
                TlcErrorCode::UnknownNextPeer,
                channel_outpoint.clone(),
                None,
            );
            reply
                .send(Err(TlcErrPacket::new(error_detail)))
                .expect("send add tlc response");
        };

        let channel_id = match state.outpoint_channel_map.get(channel_outpoint) {
            Some(channel_id) => channel_id,
            None => {
                error!(
                        "Channel id not found in outpoint_channel_map with {:?}, are we connected to the peer?",
                        channel_outpoint
                    );
                return unknown_next_peer(reply);
            }
        };
        let (send, recv) = oneshot::channel::<Result<AddTlcResponse, TlcErrPacket>>();
        let rpc_reply = RpcReplyPort::from(send);
        let command = ChannelCommand::AddTlc(
            AddTlcCommand {
                amount: info.amount,
                preimage: None,
                payment_hash: Some(info.payment_hash),
                expiry: info.expiry,
                hash_algorithm: info.tlc_hash_algorithm,
                onion_packet: peeled_packet.next.map(|next| next.data).unwrap_or_default(),
                previous_tlc,
            },
            rpc_reply,
        );

        // we have already checked the channel_id is valid,
        match state.send_command_to_channel(*channel_id, command).await {
            Ok(()) => {}
            Err(Error::ChannelNotFound(_)) => {
                return unknown_next_peer(reply);
            }
            Err(err) => {
                // must be some error from tentacle, set it as temporary node failure
                error!(
                    "Failed to send onion packet to channel: {:?} with err: {:?}",
                    channel_id, err
                );
                let error_detail = TlcErr::new(TlcErrorCode::TemporaryNodeFailure);
                return reply
                    .send(Err(TlcErrPacket::new(error_detail)))
                    .expect("send add tlc response");
            }
        }
        let add_tlc_res = recv.await.expect("recv error").map(|res| res.tlc_id);
        reply.send(add_tlc_res).expect("send error");
    }

    async fn build_payment_route(
        &self,
        payment_session: &mut PaymentSession,
        payment_data: &SendPaymentData,
    ) -> Result<Vec<PaymentHopData>, Error> {
        match self
            .network_graph
            .read()
            .await
            .build_route(payment_data.clone())
        {
            Err(e) => {
                let error = format!("Failed to build route, {}", e);
                self.set_payment_fail_with_error(payment_session, &error);
                return Err(Error::SendPaymentError(error));
            }
            Ok(hops) => {
                assert!(hops[0].channel_outpoint.is_some());
                return Ok(hops);
            }
        };
    }

    async fn send_payment_onion_packet(
        &self,
        state: &mut NetworkActorState<S>,
        payment_session: &mut PaymentSession,
        payment_data: &SendPaymentData,
        hops: Vec<PaymentHopData>,
    ) -> Result<PaymentSession, Error> {
        let session_key = Privkey::from_slice(KeyPair::generate_random_key().as_ref());
        let first_channel_outpoint = hops[0]
            .channel_outpoint
            .clone()
            .expect("first hop channel must exist");

        payment_session.route =
            SessionRoute::new(state.get_public_key(), payment_data.target_pubkey, &hops);

        let (send, recv) = oneshot::channel::<Result<u64, TlcErrPacket>>();
        let rpc_reply = RpcReplyPort::from(send);
        let peeled_packet =
            match PeeledPaymentOnionPacket::create(session_key, hops, &Secp256k1::signing_only()) {
                Ok(packet) => packet,
                Err(e) => {
                    let err = format!(
                        "Failed to create onion packet: {:?}, error: {:?}",
                        payment_data.payment_hash, e
                    );
                    self.set_payment_fail_with_error(payment_session, &err);
                    return Err(Error::SendPaymentError(err));
                }
            };
        let command = SendOnionPacketCommand {
            packet: peeled_packet.serialize(),
            previous_tlc: None,
        };

        self.handle_send_onion_packet_command(state, command, rpc_reply)
            .await;
        match recv.await.expect("msg recv error") {
            Err(e) => {
                if let Some(error_detail) = e.decode() {
                    // This is the error implies we send payment request to the first hop failed
                    // graph or payment history need to update and then have a retry
                    self.update_graph_with_tlc_fail(&error_detail).await;
                    let _ = self
                        .network_graph
                        .write()
                        .await
                        .record_payment_fail(payment_session, error_detail.clone());
                    let err = format!(
                        "Failed to send onion packet with error {}",
                        error_detail.error_code_as_str()
                    );
                    self.set_payment_fail_with_error(payment_session, &err);
                    return Err(Error::SendPaymentFirstHopError(err));
                } else {
                    // This expected never to be happended, to be safe, we will set the payment session to failed
                    let err =
                        "Failed to send onion packet, got malioucious error message".to_string();
                    self.set_payment_fail_with_error(payment_session, &err);
                    return Err(Error::SendPaymentError(err));
                }
            }
            Ok(tlc_id) => {
                payment_session.set_inflight_status(first_channel_outpoint, tlc_id);
                self.store.insert_payment_session(payment_session.clone());
                return Ok(payment_session.clone());
            }
        }
    }

    fn set_payment_fail_with_error(&self, payment_session: &mut PaymentSession, error: &str) {
        payment_session.set_failed_status(error);
        self.store.insert_payment_session(payment_session.clone());
    }

    async fn try_payment_session(
        &self,
        state: &mut NetworkActorState<S>,
        mut payment_session: PaymentSession,
    ) -> Result<PaymentSession, Error> {
        let payment_data = payment_session.request.clone();
        while payment_session.can_retry() {
            payment_session.retried_times += 1;

            let hops_info = self
                .build_payment_route(&mut payment_session, &payment_data)
                .await?;

            match self
                .send_payment_onion_packet(state, &mut payment_session, &payment_data, hops_info)
                .await
            {
                Ok(payment_session) => return Ok(payment_session),
                Err(Error::SendPaymentFirstHopError(_)) => {
                    // we will retry the payment session
                    continue;
                }
                Err(e) => {
                    return Err(e);
                }
            }
        }

        let error = payment_session.last_error.clone().unwrap_or_else(|| {
            format!(
                "Failed to send payment session: {:?}, retried times: {}",
                payment_data.payment_hash, payment_session.retried_times
            )
        });
        return Err(Error::SendPaymentError(error));
    }

    pub(crate) async fn on_send_payment(
        &self,
        state: &mut NetworkActorState<S>,
        payment_request: SendPaymentCommand,
    ) -> Result<SendPaymentResponse, Error> {
        let payment_data = SendPaymentData::new(payment_request.clone(), state.get_public_key())
            .map_err(|e| {
                error!("Failed to validate payment request: {:?}", e);
                Error::InvalidParameter(format!("Failed to validate payment request: {:?}", e))
            })?;

        // initialize the payment session in db and begin the payment process lifecycle
        if let Some(payment_session) = self.store.get_payment_session(payment_data.payment_hash) {
            // we only allow retrying payment session with status failed
            debug!("Payment session already exists: {:?}", payment_session);
            if payment_session.status != PaymentSessionStatus::Failed {
                return Err(Error::InvalidParameter(format!(
                    "Payment session already exists: {} with payment session status: {:?}",
                    payment_data.payment_hash, payment_session.status
                )));
            }
        }

        let payment_session = PaymentSession::new(payment_data.clone(), 5);
        self.store.insert_payment_session(payment_session.clone());
        let session = self.try_payment_session(state, payment_session).await?;
        return Ok(session.into());
    }

    pub(crate) async fn on_remove_tlc_event(
        &self,
        state: &mut NetworkActorState<S>,
        payment_hash: Hash256,
        reason: RemoveTlcReason,
    ) {
        if let Some(mut payment_session) = self.store.get_payment_session(payment_hash) {
            if payment_session.status == PaymentSessionStatus::Inflight {
                match reason {
                    RemoveTlcReason::RemoveTlcFulfill(_) => {
                        self.network_graph
                            .write()
                            .await
                            .record_payment_success(payment_session);
                    }
                    RemoveTlcReason::RemoveTlcFail(reason) => {
                        let error_detail = reason.decode().expect("decoded error");
                        self.update_graph_with_tlc_fail(&error_detail).await;
                        let need_to_retry = self
                            .network_graph
                            .write()
                            .await
                            .record_payment_fail(&payment_session, error_detail.clone());
                        if need_to_retry {
                            let res = self.try_payment_session(state, payment_session).await;
                            if res.is_err() {
                                debug!("Failed to retry payment session: {:?}", res);
                            }
                        } else {
                            self.set_payment_fail_with_error(
                                &mut payment_session,
                                error_detail.error_code.as_ref(),
                            );
                        }
                    }
                }
            }
        }
    }

    async fn update_graph_with_tlc_fail(&self, tcl_error_detail: &TlcErr) {
        let error_code = tcl_error_detail.error_code();
        // https://github.com/lightning/bolts/blob/master/04-onion-routing.md#rationale-6
        // we now still update the graph, maybe we need to remove it later?
        if error_code.is_update() {
            if let Some(extra_data) = &tcl_error_detail.extra_data {
                match extra_data {
                    TlcErrData::ChannelFailed { channel_update, .. } => {
                        if let Some(channel_update) = channel_update {
                            let _ = self
                                .network_graph
                                .write()
                                .await
                                .process_channel_update(channel_update.clone());
                        }
                    }
                    _ => {}
                }
            }
        }
        match tcl_error_detail.error_code() {
            TlcErrorCode::PermanentChannelFailure
            | TlcErrorCode::ChannelDisabled
            | TlcErrorCode::UnknownNextPeer => {
                let channel_outpoint = tcl_error_detail
                    .error_channel_outpoint()
                    .expect("expect channel outpoint");
                debug!("mark channel failed: {:?}", channel_outpoint);
                let mut graph = self.network_graph.write().await;
                graph.mark_channel_failed(&channel_outpoint);
            }
            TlcErrorCode::PermanentNodeFailure => {
                let node_id = tcl_error_detail.error_node_id().expect("expect node id");
                let mut graph = self.network_graph.write().await;
                graph.mark_node_failed(node_id);
            }
            _ => {}
        }
    }

    pub(crate) fn on_get_payment(
        &self,
        payment_hash: &Hash256,
    ) -> Result<SendPaymentResponse, Error> {
        match self.store.get_payment_session(*payment_hash) {
            Some(payment_session) => Ok(payment_session.into()),
            None => Err(Error::InvalidParameter(format!(
                "Payment session not found: {:?}",
                payment_hash
            ))),
        }
    }
}

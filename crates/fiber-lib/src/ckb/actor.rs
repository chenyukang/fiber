use std::collections::{HashMap, HashSet};

use ckb_sdk::RpcError;
use ckb_types::{core::TransactionView, packed, prelude::IntoTransactionView as _};
use ractor::{concurrency::Duration, Actor, ActorProcessingErr, ActorRef, RpcReplyPort};
use strum::AsRefStr;
use tracing::{debug, trace};

use crate::{
    ckb::contracts::{get_script_by_contract, Contract},
    utils::actor::ActorHandleLogGuard,
};
use fiber_types::Hash256;

#[cfg(not(target_arch = "wasm32"))]
use fiber_types::serde_utils::EntityHex;
#[cfg(not(target_arch = "wasm32"))]
use serde::{Deserialize, Serialize};
#[cfg(not(target_arch = "wasm32"))]
use serde_with::serde_as;

use super::{
    funding::{FundingContext, LiveCellsExclusionMap},
    signer::LocalSigner,
    tx_tracing_actor::{
        CkbTxTracer, CkbTxTracingActor, CkbTxTracingArguments, CkbTxTracingMessage,
    },
    CkbConfig, FundingError, FundingRequest, FundingTx,
};

pub struct CkbChainActor {}

const ACTOR_HANDLE_WARN_THRESHOLD_MS: u64 = 15_000;

#[derive(Clone, Debug)]
pub struct CkbChainState {
    config: CkbConfig,
    ckb_tx_tracing_actor: ActorRef<CkbTxTracingMessage>,
    signer: LocalSigner,
    funding_source_lock_script: packed::Script,
    live_cells_exclusion_map: LiveCellsExclusionMap,
    local_funded_inputs_by_tx: HashMap<packed::Byte32, HashSet<packed::OutPoint>>,
}

impl CkbChainState {
    /// Lets the watchtower see this actor's funding inputs (`held_cells`).
    fn publish_held(&self) {
        super::held_cells::hold_funding(
            self.live_cells_exclusion_map.holder(),
            self.live_cells_exclusion_map.input_out_points(),
        );
    }
}

#[derive(Debug, AsRefStr)]
pub enum CkbChainMessage {
    Fund(
        FundingTx,
        FundingRequest,
        RpcReplyPort<Result<FundingTx, FundingError>>,
    ),
    /// Build an unsigned funding transaction for external signing.
    /// The user will sign this transaction with their own wallet.
    BuildUnsignedFundingTx {
        funding_tx: FundingTx,
        request: FundingRequest,
        funding_source_lock_script: packed::Script,
        funding_source_lock_script_cell_deps: Vec<packed::CellDep>,
        funding_cell_lock_script: packed::Script,
        reply: RpcReplyPort<Result<FundingTx, FundingError>>,
    },
    VerifyFundingTx {
        local_tx: packed::Transaction,
        remote_tx: packed::Transaction,
        funding_cell_lock_script: packed::Script,
        funding_udt_type_script: Option<packed::Script>,
        funding_source_lock_script: Option<packed::Script>,
        funding_fee_rate: u64,
        reply: RpcReplyPort<Result<(), FundingError>>,
    },
    /// Query the node's own local funding source lock script, if configured.
    GetFundingSourceLockScript(RpcReplyPort<Option<packed::Script>>),
    /// Add funding tx. This is used to reestablish a channel that is not ready yet.
    /// Adding a funding tx will add its used input cells to the exclusion list.
    AddFundingTx(FundingTx),
    /// Remove a funding tx to release the used live cells.
    /// RemoveFundingTx(tx_hash)
    RemoveFundingTx(Hash256),
    /// Notify that the funding tx has been committed and the used live cells will become dead soon.
    /// CommitFundingTx(tx_hash, commit_block_number),
    CommitFundingTx(Hash256, u64),
    Sign(FundingTx, RpcReplyPort<Result<FundingTx, FundingError>>),
    SendTx(TransactionView, RpcReplyPort<Result<(), RpcError>>),
    CreateTxTracer(CkbTxTracer),
    RemoveTxTracers(Hash256),
    ReportSendTxError(Hash256, RpcError),

    Stop,
}

#[async_trait::async_trait]
impl Actor for CkbChainActor {
    type Msg = CkbChainMessage;
    type State = CkbChainState;
    type Arguments = CkbConfig;
    async fn pre_start(
        &self,
        myself: ActorRef<Self::Msg>,
        config: Self::Arguments,
    ) -> Result<Self::State, ActorProcessingErr> {
        let secret_key = config.read_secret_key()?;
        let signer = LocalSigner::new(secret_key);
        let funding_source_lock_script =
            get_script_by_contract(Contract::Secp256k1Lock, signer.pubkey_hash());
        let ckb_tx_tracing_actor = Actor::spawn_linked(
            Some(format!(
                "{}/ckb-tx-tracing",
                myself.get_name().as_deref().unwrap_or_default()
            )),
            CkbTxTracingActor::new(),
            CkbTxTracingArguments {
                rpc_url: config.rpc_url.clone(),
                polling_interval: Duration::from_millis(config.tx_tracing_polling_interval_ms),
            },
            myself.into(),
        )
        .await?
        .0;
        Ok(CkbChainState {
            config,
            signer,
            funding_source_lock_script,
            ckb_tx_tracing_actor,
            live_cells_exclusion_map: Default::default(),
            local_funded_inputs_by_tx: Default::default(),
        })
    }

    async fn post_stop(
        &self,
        _myself: ActorRef<Self::Msg>,
        state: &mut Self::State,
    ) -> Result<(), ActorProcessingErr> {
        super::held_cells::hold_funding(state.live_cells_exclusion_map.holder(), vec![]);
        Ok(())
    }

    async fn handle(
        &self,
        myself: ActorRef<Self::Msg>,
        message: Self::Msg,
        state: &mut Self::State,
    ) -> Result<(), ActorProcessingErr> {
        let _handle_log_guard = ActorHandleLogGuard::new(
            "CkbChainActor",
            message.as_ref().to_string(),
            "fiber.ckb_chain_actor",
            ACTOR_HANDLE_WARN_THRESHOLD_MS,
        );
        match message {
            CkbChainMessage::Fund(tx, request, reply_port) => {
                debug!(
                    "[{}] Funding request received: local_amount={}, remote_amount={}, local_reserved_ckb={}, remote_reserved_ckb={}, fee_rate={}, has_udt={}, has_existing_tx={}",
                    myself.get_name().unwrap_or_default(),
                    request.local_amount,
                    request.remote_amount,
                    request.local_reserved_ckb_amount,
                    request.remote_reserved_ckb_amount,
                    request.funding_fee_rate,
                    request.udt_type_script.is_some(),
                    tx.as_ref().is_some(),
                );
                let prev_tx_hash = tx.as_ref().map(|t| t.hash());
                let prev_inputs: HashSet<packed::OutPoint> = tx
                    .as_ref()
                    .map(|t| t.input_pts_iter().collect())
                    .unwrap_or_default();
                let mut local_inputs = prev_tx_hash
                    .as_ref()
                    .and_then(|hash| state.local_funded_inputs_by_tx.get(hash).cloned())
                    .unwrap_or_default();
                let context = state.build_funding_context(
                    request.script.clone(),
                    request.udt_type_script.clone(),
                    None,
                );
                let result = match state.config.funding_tx_shell_builder_as_deref() {
                    None => {
                        tx.fulfill(request, context, &mut state.live_cells_exclusion_map)
                            .await
                    }
                    Some(shell_script) => fund_via_shell(shell_script, tx, request, context).await,
                };
                state.publish_held();
                match &result {
                    Ok(funding_tx) => {
                        if let Some(inner) = funding_tx.as_ref() {
                            local_inputs.extend(
                                inner
                                    .input_pts_iter()
                                    .filter(|out_point| !prev_inputs.contains(out_point)),
                            );
                            state
                                .local_funded_inputs_by_tx
                                .insert(inner.hash(), local_inputs);
                        }
                        debug!(
                            "[{}] Funding request succeeded: tx_hash={:?}",
                            myself.get_name().unwrap_or_default(),
                            funding_tx.as_ref().map(|t| t.hash()),
                        );
                    }
                    Err(err) => debug!(
                        "[{}] Funding request failed: {}",
                        myself.get_name().unwrap_or_default(),
                        err,
                    ),
                }
                let _ = reply_port.send(result);
            }
            CkbChainMessage::BuildUnsignedFundingTx {
                funding_tx,
                request,
                funding_source_lock_script,
                funding_source_lock_script_cell_deps,
                funding_cell_lock_script,
                reply,
            } => {
                debug!(
                    "[{}] BuildUnsignedFundingTx: local_amount={}, remote_amount={}, fee_rate={}, has_udt={}, funding_source_lock_hash={}",
                    myself.get_name().unwrap_or_default(),
                    request.local_amount,
                    request.remote_amount,
                    request.funding_fee_rate,
                    request.udt_type_script.is_some(),
                    funding_source_lock_script.calc_script_hash(),
                );
                if funding_source_lock_script == state.funding_source_lock_script {
                    let _ = reply.send(Err(FundingError::ExternalFundingUsesLocalLock));
                    return Ok(());
                }
                let context = FundingContext {
                    rpc_url: state.config.rpc_url.clone(),
                    funding_source_lock_script,
                    funding_source_lock_script_cell_deps,
                    funding_cell_lock_script,
                    funding_udt_type_script: request.udt_type_script.clone(),
                };
                let result = funding_tx
                    .build_unsigned_for_external_funding(
                        request,
                        context,
                        &mut state.live_cells_exclusion_map,
                    )
                    .await;
                state.publish_held();
                if let Err(ref err) = result {
                    debug!(
                        "[{}] BuildUnsignedFundingTx failed: {}",
                        myself.get_name().unwrap_or_default(),
                        err,
                    );
                }
                let _ = reply.send(result);
            }
            CkbChainMessage::VerifyFundingTx {
                local_tx,
                remote_tx,
                funding_cell_lock_script,
                funding_udt_type_script,
                funding_source_lock_script,
                funding_fee_rate,
                reply,
            } => {
                let local_tx_hash = local_tx.calc_tx_hash();
                let remote_tx_hash = remote_tx.calc_tx_hash();
                debug!(
                    "[{}] VerifyFundingTx: local_tx_hash={}, remote_tx_hash={}",
                    myself.get_name().unwrap_or_default(),
                    local_tx_hash,
                    remote_tx_hash,
                );
                let mut funding_tx: FundingTx = local_tx.into();
                let context = state.build_funding_context(
                    funding_cell_lock_script,
                    funding_udt_type_script,
                    funding_source_lock_script,
                );
                let result = funding_tx
                    .update_for_peer(remote_tx.into_view(), context, funding_fee_rate)
                    .await;
                match &result {
                    Ok(()) => {
                        // The channel will replace its funding tx with the verified peer tx, so the
                        // reserved inputs must follow the new hash. Otherwise the old local hash
                        // leaks in the exclusion map and keeps wallet cells locked forever.
                        state
                            .live_cells_exclusion_map
                            .migrate_funding_tx(&local_tx_hash, &funding_tx);
                        if let Some(new_tx) = funding_tx.as_ref() {
                            // Merge into what is already recorded for the new tx. A hosted tenant
                            // shares its LSP's chain actor, so the LSP's own `Fund` may have
                            // recorded its inputs for this tx already; replacing that record made
                            // the LSP refuse to sign its own cell.
                            let local_inputs = state
                                .local_funded_inputs_by_tx
                                .remove(&local_tx_hash)
                                .unwrap_or_default();
                            state
                                .local_funded_inputs_by_tx
                                .entry(new_tx.hash())
                                .or_default()
                                .extend(local_inputs);
                        }
                        state.publish_held();
                    }
                    Err(err) => {
                        debug!(
                            "[{}] VerifyFundingTx failed for remote_tx_hash={}: {}",
                            myself.get_name().unwrap_or_default(),
                            remote_tx_hash,
                            err,
                        );
                    }
                }
                let _ = reply.send(result);
            }
            CkbChainMessage::GetFundingSourceLockScript(reply) => {
                let _ = reply.send(Some(state.funding_source_lock_script.clone()));
            }
            CkbChainMessage::AddFundingTx(tx) => {
                state.live_cells_exclusion_map.add_funding_tx(&tx);
                state.publish_held();
            }
            CkbChainMessage::RemoveFundingTx(tx_hash) => {
                let tx_hash: packed::Byte32 = tx_hash.into();
                state.live_cells_exclusion_map.remove(&tx_hash);
                state.local_funded_inputs_by_tx.remove(&tx_hash);
                state.publish_held();
            }
            CkbChainMessage::CommitFundingTx(tx_hash, commit_block_number) => {
                let tx_hash: packed::Byte32 = tx_hash.into();
                state
                    .live_cells_exclusion_map
                    .commit(&tx_hash, commit_block_number);
                state.local_funded_inputs_by_tx.remove(&tx_hash);
            }
            CkbChainMessage::Sign(tx, reply_port) => {
                if !reply_port.is_closed() {
                    let tx_hash = tx.as_ref().map(|t| t.hash());
                    let allowed_local_inputs = tx_hash
                        .as_ref()
                        .and_then(|hash| state.local_funded_inputs_by_tx.get(hash).cloned());
                    debug!(
                        "[{}] Signing funding tx: tx_hash={:?}",
                        myself.get_name().unwrap_or_default(),
                        tx_hash,
                    );
                    let rpc_url = state.config.rpc_url.clone();
                    let result = state
                        .signer
                        .sign_funding_tx(
                            tx,
                            rpc_url,
                            &state.funding_source_lock_script,
                            allowed_local_inputs.as_ref(),
                        )
                        .await;
                    match &result {
                        Ok(signed) => debug!(
                            "[{}] Funding tx signed: tx_hash={:?}",
                            myself.get_name().unwrap_or_default(),
                            signed.as_ref().map(|t| t.hash()),
                        ),
                        Err(err) => debug!(
                            "[{}] Funding tx signing failed for {:?}: {}",
                            myself.get_name().unwrap_or_default(),
                            tx_hash,
                            err,
                        ),
                    }
                    if !reply_port.is_closed() {
                        // ignore error
                        let _ = reply_port.send(result);
                    }
                }
            }
            CkbChainMessage::SendTx(tx, reply_port) => {
                let ckb_client = state.config.ckb_rpc_client();
                trace!(
                    "[{}] Sending tx {} to CKB node",
                    myself.get_name().unwrap_or_default(),
                    tx.hash(),
                );
                let result = match ckb_client.send_transaction(tx.data().into(), None).await {
                    Ok(_) => {
                        debug!(
                            "[{}] Tx {} accepted by CKB node",
                            myself.get_name().unwrap_or_default(),
                            tx.hash(),
                        );
                        Ok(())
                    }
                    Err(err) => {
                        //FIXME(yukang): RBF or duplicated transaction handling
                        match err {
                            RpcError::Rpc(e) if e.code.code() == -1107 => {
                                tracing::warn!(
                                    "[{}] transaction { } already in pool",
                                    myself.get_name().unwrap_or_default(),
                                    tx.hash(),
                                );
                                Ok(())
                            }
                            // PoolRejectedRBF: another transaction in the pool spends an input of
                            // this one, and this one cannot replace it. It was taken for "already
                            // in pool", so a funding that lost its input waited for its own
                            // timeout (LSP2, 2026-10-28).
                            RpcError::Rpc(ref e) if super::is_pool_conflict_code(e.code.code()) => {
                                tracing::error!(
                                    "[{}] transaction {} conflicts with one in the pool: {:?}",
                                    myself.get_name().unwrap_or_default(),
                                    tx.hash(),
                                    err
                                );
                                Err(err)
                            }
                            _ => {
                                tracing::error!(
                                    "[{}] send transaction {} failed: {:?}",
                                    myself.get_name().unwrap_or_default(),
                                    tx.hash(),
                                    err
                                );
                                Err(err)
                            }
                        }
                    }
                };
                if !reply_port.is_closed() {
                    // ignore error
                    let _ = reply_port.send(result);
                }
            }

            CkbChainMessage::CreateTxTracer(tracer) => {
                debug!(
                    "[{}] trace transaction {} with {} confs",
                    myself.get_name().unwrap_or_default(),
                    tracer.tx_hash,
                    tracer.confirmations
                );
                state
                    .ckb_tx_tracing_actor
                    .send_message(CkbTxTracingMessage::CreateTracer(tracer))?;
            }
            CkbChainMessage::RemoveTxTracers(tx_hash) => {
                state
                    .ckb_tx_tracing_actor
                    .send_message(CkbTxTracingMessage::RemoveTracers(tx_hash))?;
            }
            CkbChainMessage::ReportSendTxError(tx_hash, err) => {
                state
                    .ckb_tx_tracing_actor
                    .send_message(CkbTxTracingMessage::ReportSendTxError(tx_hash, err))?;
            }

            CkbChainMessage::Stop => {
                myself.stop(Some("stop received".to_string()));
            }
        }

        Ok(())
    }
}

impl CkbChainState {
    fn build_funding_context(
        &self,
        funding_cell_lock_script: packed::Script,
        funding_udt_type_script: Option<packed::Script>,
        funding_source_lock_script: Option<packed::Script>,
    ) -> FundingContext {
        FundingContext {
            rpc_url: self.config.rpc_url.clone(),
            funding_source_lock_script: funding_source_lock_script
                .unwrap_or_else(|| self.funding_source_lock_script.clone()),
            funding_source_lock_script_cell_deps: Vec::new(),
            funding_cell_lock_script,
            funding_udt_type_script,
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[serde_as]
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct FundingTxShellBuilderInput {
    tx: ckb_jsonrpc_types::Transaction,
    request: FundingRequest,
    rpc_url: String,
    #[serde_as(as = "EntityHex")]
    funding_source_lock_script: packed::Script,
}

#[cfg(not(target_arch = "wasm32"))]
async fn fund_via_shell(
    shell_script: &str,
    mut tx: FundingTx,
    request: FundingRequest,
    context: FundingContext,
) -> Result<FundingTx, FundingError> {
    use std::process::Stdio;
    use tokio::{io::AsyncWriteExt, process::Command};
    let (executable, arg) = if cfg!(target_os = "windows") {
        ("cmd", "/C")
    } else {
        ("sh", "-c")
    };
    let mut child = Command::new(executable)
        .arg(arg)
        .arg(shell_script)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    let input = FundingTxShellBuilderInput {
        tx: tx.take().map(|tx| tx.data().into()).unwrap_or_default(),
        request,
        rpc_url: context.rpc_url,
        funding_source_lock_script: context.funding_source_lock_script,
    };
    let mut stdin = child.stdin.take().expect("failed to get stdin");
    let input_json = serde_json::to_string(&input)?;
    stdin.write_all(input_json.as_bytes()).await?;

    let output = child.wait_with_output().await?;
    if output.status.success() {
        let out_tx_json = String::from_utf8(output.stdout)?;
        let tx: ckb_jsonrpc_types::Transaction = serde_json::from_str(&out_tx_json)?;
        let tx: packed::Transaction = tx.into();
        let tx: FundingTx = tx.into_view().into();
        Ok(tx)
    } else {
        let err = String::from_utf8(output.stderr)?;
        Err(FundingError::CkbTxBuilderError(
            ckb_sdk::tx_builder::TxBuilderError::Other(anyhow::anyhow!(err)),
        ))
    }
}

#[cfg(target_arch = "wasm32")]
async fn fund_via_shell(
    _shell_script: &str,
    _tx: FundingTx,
    _request: FundingRequest,
    _context: FundingContext,
) -> Result<FundingTx, FundingError> {
    // Never called in WASM
    unreachable!();
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use ractor::call_t;
    use secp256k1::SecretKey;
    use tempfile::tempdir;

    /// The chain actor with its own key, and the locally funded inputs it starts with (what
    /// earlier `Fund` calls would have recorded).
    struct TestCkbChainActor(
        SecretKey,
        HashMap<packed::Byte32, HashSet<packed::OutPoint>>,
    );

    #[async_trait::async_trait]
    impl Actor for TestCkbChainActor {
        type Msg = CkbChainMessage;
        type State = CkbChainState;
        type Arguments = CkbConfig;

        async fn pre_start(
            &self,
            myself: ActorRef<Self::Msg>,
            config: Self::Arguments,
        ) -> Result<Self::State, ActorProcessingErr> {
            let signer = LocalSigner::new(self.0);
            let funding_source_lock_script =
                get_script_by_contract(Contract::Secp256k1Lock, signer.pubkey_hash());
            let ckb_tx_tracing_actor = Actor::spawn_linked(
                None,
                CkbTxTracingActor::new(),
                CkbTxTracingArguments {
                    rpc_url: config.rpc_url.clone(),
                    polling_interval: Duration::from_millis(config.tx_tracing_polling_interval_ms),
                },
                myself.into(),
            )
            .await?
            .0;
            Ok(CkbChainState {
                config,
                signer,
                funding_source_lock_script,
                ckb_tx_tracing_actor,
                live_cells_exclusion_map: Default::default(),
                local_funded_inputs_by_tx: self.1.clone(),
            })
        }

        async fn handle(
            &self,
            myself: ActorRef<Self::Msg>,
            message: Self::Msg,
            state: &mut Self::State,
        ) -> Result<(), ActorProcessingErr> {
            CkbChainActor {}.handle(myself, message, state).await
        }
    }

    #[tokio::test]
    async fn test_build_unsigned_funding_tx_rejects_local_funding_lock() {
        let dir = tempdir().expect("create tempdir");
        let config = CkbConfig {
            base_dir: Some(dir.path().to_path_buf()),
            rpc_url: "http://127.0.0.1:8114".to_string(),
            tx_tracing_polling_interval_ms: 4_000,
            udt_whitelist: None,
            funding_tx_shell_builder: None,
        };
        let secret_key = SecretKey::from_slice(&[9u8; 32]).expect("valid secret key");
        let (actor, _handle) =
            Actor::spawn(None, TestCkbChainActor(secret_key, HashMap::new()), config)
                .await
                .expect("spawn TestCkbChainActor");

        let local_lock = call_t!(actor, CkbChainMessage::GetFundingSourceLockScript, 5_000)
            .expect("rpc call ok")
            .expect("local funding lock script present");

        let err = call_t!(
            actor,
            |reply| CkbChainMessage::BuildUnsignedFundingTx {
                funding_tx: FundingTx::new(),
                request: FundingRequest {
                    script: local_lock.clone(),
                    udt_type_script: None,
                    local_amount: 100_000_000_000,
                    funding_fee_rate: 1000,
                    remote_amount: 0,
                    local_reserved_ckb_amount: 0,
                    remote_reserved_ckb_amount: 0,
                },
                funding_source_lock_script: local_lock.clone(),
                funding_source_lock_script_cell_deps: Vec::new(),
                funding_cell_lock_script: local_lock,
                reply,
            },
            5_000
        )
        .expect("rpc call ok")
        .expect_err("BuildUnsignedFundingTx must reject local funding lock");

        assert!(
            matches!(err, FundingError::ExternalFundingUsesLocalLock),
            "expected ExternalFundingUsesLocalLock, got {err:?}"
        );
    }

    /// A CKB RPC that answers `get_live_cell` for the given cells and nothing else.
    async fn serve_live_cells(
        cells: Vec<(packed::OutPoint, packed::CellOutput)>,
    ) -> (String, tokio::task::JoinHandle<()>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let cells: HashMap<packed::OutPoint, ckb_jsonrpc_types::CellOutput> = cells
            .into_iter()
            .map(|(out_point, output)| (out_point, output.into()))
            .collect();
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let server = tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                let cells = cells.clone();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 16384];
                    let n = match socket.read(&mut buf).await {
                        Ok(n) if n > 0 => n,
                        _ => return,
                    };
                    let req = String::from_utf8_lossy(&buf[..n]);
                    let body_start = req.find("\r\n\r\n").map(|i| i + 4).unwrap_or(0);
                    let json: serde_json::Value =
                        serde_json::from_str(&req[body_start..]).unwrap_or_default();
                    let id = json.get("id").cloned().unwrap_or(serde_json::Value::Null);
                    let method = json.get("method").and_then(|m| m.as_str()).unwrap_or("");
                    let result = if method == "get_live_cell" {
                        let out_point: Option<ckb_jsonrpc_types::OutPoint> = json
                            .get("params")
                            .and_then(|params| params.get(0))
                            .and_then(|param| serde_json::from_value(param.clone()).ok());
                        match out_point
                            .map(packed::OutPoint::from)
                            .and_then(|out_point| cells.get(&out_point).cloned())
                        {
                            Some(output) => serde_json::json!({
                                "cell": {
                                    "data": {
                                        "content": "0x",
                                        "hash": format!("{:#x}", ckb_types::H256([0u8; 32])),
                                    },
                                    "output": output,
                                },
                                "status": "live",
                            }),
                            None => serde_json::json!({ "cell": null, "status": "unknown" }),
                        }
                    } else {
                        serde_json::Value::Null
                    };
                    let body = serde_json::json!({ "jsonrpc": "2.0", "id": id, "result": result })
                        .to_string();
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = socket.write_all(resp.as_bytes()).await;
                });
            }
        });
        (format!("http://{addr}"), server)
    }

    /// A hosted tenant shares its LSP's chain actor. The tenant's wallet builds funding tx R,
    /// the LSP's `Fund` adds its own cell and gets F, and the tenant then verifies R -> F. When
    /// that verify lands before the LSP's `RemoveFundingTx(R)`, it must not replace what the
    /// LSP recorded for F, or the LSP refuses to sign its own cell in F.
    #[tokio::test]
    async fn test_verify_funding_tx_keeps_local_inputs_recorded_for_the_new_tx() {
        use ckb_types::{
            bytes::Bytes,
            core::{ScriptHashType, TransactionBuilder},
            prelude::{Builder, Entity, Pack},
            H256,
        };

        const CKB: u64 = 100_000_000;
        fn script(code_hash: u8, args: Vec<u8>) -> packed::Script {
            let code_hash: packed::Byte32 = H256([code_hash; 32]).pack();
            let args: packed::Bytes = Bytes::from(args).pack();
            let hash_type: packed::Byte = ScriptHashType::Data.into();
            packed::Script::new_builder()
                .code_hash(code_hash)
                .hash_type(hash_type)
                .args(args)
                .build()
        }
        fn output(capacity: u64, lock: &packed::Script) -> packed::CellOutput {
            let capacity: packed::Uint64 = capacity.pack();
            packed::CellOutput::new_builder()
                .capacity(capacity)
                .lock(lock.clone())
                .build()
        }

        let secret_key = SecretKey::from_slice(&[9u8; 32]).expect("valid secret key");
        let lsp_lock = get_script_by_contract(
            Contract::Secp256k1Lock,
            LocalSigner::new(secret_key).pubkey_hash(),
        );
        let wallet_lock = script(0x77, vec![1u8; 20]);
        let funding_cell_lock = script(0x66, vec![2u8; 32]);

        // W: the tenant's wallet cell. X: the LSP's own cell.
        let wallet_cell = packed::OutPoint::new(H256([0x11; 32]).pack(), 0);
        let lsp_cell = packed::OutPoint::new(H256([0x22; 32]).pack(), 0);
        let (rpc_url, server) = serve_live_cells(vec![
            (wallet_cell.clone(), output(1_000 * CKB, &wallet_lock)),
            (lsp_cell.clone(), output(2_000 * CKB, &lsp_lock)),
        ])
        .await;

        // R: built by the tenant's wallet alone.
        let tx_r = TransactionBuilder::default()
            .input(packed::CellInput::new(wallet_cell.clone(), 0))
            .output(output(1_000 * CKB - CKB / 100, &funding_cell_lock))
            .output_data(Bytes::new().pack())
            .build();
        // F: R plus the LSP's cell and the LSP's change.
        let tx_f = TransactionBuilder::default()
            .input(packed::CellInput::new(wallet_cell.clone(), 0))
            .input(packed::CellInput::new(lsp_cell.clone(), 0))
            .output(output(1_500 * CKB - CKB / 100, &funding_cell_lock))
            .output(output(1_500 * CKB - CKB / 100, &lsp_lock))
            .output_data(Bytes::new().pack())
            .output_data(Bytes::new().pack())
            .build();

        // What the LSP's `Fund(R) -> F` recorded: X is the LSP's own input of F.
        let mut funded = HashMap::new();
        funded.insert(tx_f.hash(), HashSet::from([lsp_cell.clone()]));

        let dir = tempdir().expect("create tempdir");
        let config = CkbConfig {
            base_dir: Some(dir.path().to_path_buf()),
            rpc_url,
            tx_tracing_polling_interval_ms: 60_000,
            udt_whitelist: None,
            funding_tx_shell_builder: None,
        };
        let (actor, _handle) = Actor::spawn(None, TestCkbChainActor(secret_key, funded), config)
            .await
            .expect("spawn TestCkbChainActor");
        assert_eq!(
            call_t!(actor, CkbChainMessage::GetFundingSourceLockScript, 5_000)
                .expect("rpc call ok"),
            Some(lsp_lock.clone())
        );

        // The LSP accepts the tenant's R: R gets an (empty) record of its own.
        call_t!(
            actor,
            |reply| CkbChainMessage::VerifyFundingTx {
                local_tx: packed::Transaction::default(),
                remote_tx: tx_r.data(),
                funding_cell_lock_script: funding_cell_lock.clone(),
                funding_udt_type_script: None,
                funding_source_lock_script: None,
                funding_fee_rate: 1_000,
                reply,
            },
            5_000
        )
        .expect("rpc call ok")
        .expect("the LSP verifies R");

        // The tenant verifies R -> F before the LSP's RemoveFundingTx(R) is handled.
        call_t!(
            actor,
            |reply| CkbChainMessage::VerifyFundingTx {
                local_tx: tx_r.data(),
                remote_tx: tx_f.data(),
                funding_cell_lock_script: funding_cell_lock.clone(),
                funding_udt_type_script: None,
                funding_source_lock_script: Some(wallet_lock.clone()),
                funding_fee_rate: 1_000,
                reply,
            },
            5_000
        )
        .expect("rpc call ok")
        .expect("the tenant verifies R -> F");
        actor
            .send_message(CkbChainMessage::RemoveFundingTx(tx_r.hash().into()))
            .expect("chain actor alive");

        // The LSP signs F, with its own cell as input #1.
        let signed = call_t!(
            actor,
            |reply| CkbChainMessage::Sign(FundingTx::from(tx_f.clone()), reply),
            5_000
        )
        .expect("rpc call ok")
        .expect("the LSP signs its own input of F");
        // Under the test contracts the lock is not the sighash type id, so no witness is
        // written here; what the bug broke is the local-input check before signing.
        let signed = signed.into_inner().expect("signed tx");
        assert_eq!(signed.hash(), tx_f.hash());

        actor.stop(None);
        server.abort();
    }
}

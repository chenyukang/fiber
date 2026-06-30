use crate::rpc::utils::rpc_error;
use jsonrpsee::proc_macros::rpc;
use jsonrpsee::types::ErrorObjectOwned;

pub use fiber_json_types::{PprofParams, PprofResult};

const DEFAULT_PPROF_DURATION_SECS: u64 = 10;
const MAX_PPROF_DURATION_SECS: u64 = 60;

/// RPC module for profiling
/// This module require build with pprof feature and debug symbol.
#[rpc(server)]
trait ProfRpc {
    /// Collects a temporary CPU profile and writes a flamegraph SVG to disk.
    #[method(name = "pprof")]
    async fn pprof(&self, params: PprofParams) -> Result<PprofResult, ErrorObjectOwned>;
}

#[derive(Default)]
pub struct ProfRpcServerImpl;

impl ProfRpcServerImpl {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait::async_trait]
impl ProfRpcServer for ProfRpcServerImpl {
    async fn pprof(&self, params: PprofParams) -> Result<PprofResult, ErrorObjectOwned> {
        self.pprof(params).await
    }
}

impl ProfRpcServerImpl {
    pub async fn pprof(&self, params: PprofParams) -> Result<PprofResult, ErrorObjectOwned> {
        let duration = validate_pprof_duration_secs(params.duration_secs)?;

        match crate::fiber::profiling::collect_flamegraph(duration).await {
            Ok(path) => Ok(PprofResult {
                path: path.to_string_lossy().into_owned(),
            }),
            Err(err) => Err(rpc_error(err.to_string())),
        }
    }
}

fn validate_pprof_duration_secs(duration_secs: Option<u64>) -> Result<u64, ErrorObjectOwned> {
    let duration = duration_secs.unwrap_or(DEFAULT_PPROF_DURATION_SECS);
    if duration == 0 {
        return Err(rpc_error("duration_secs must be at least 1 second"));
    }
    if duration > MAX_PPROF_DURATION_SECS {
        return Err(rpc_error(format!(
            "duration_secs must not exceed {} seconds",
            MAX_PPROF_DURATION_SECS
        )));
    }
    Ok(duration)
}

#[cfg(test)]
mod tests {
    use super::{
        validate_pprof_duration_secs, DEFAULT_PPROF_DURATION_SECS, MAX_PPROF_DURATION_SECS,
    };

    #[test]
    fn pprof_duration_defaults_and_allows_bounded_values() {
        assert_eq!(
            validate_pprof_duration_secs(None).unwrap(),
            DEFAULT_PPROF_DURATION_SECS
        );
        assert_eq!(validate_pprof_duration_secs(Some(1)).unwrap(), 1);
        assert_eq!(
            validate_pprof_duration_secs(Some(MAX_PPROF_DURATION_SECS)).unwrap(),
            MAX_PPROF_DURATION_SECS
        );
    }

    #[test]
    fn pprof_duration_rejects_zero_and_oversized_values() {
        let zero = validate_pprof_duration_secs(Some(0)).unwrap_err();
        assert!(zero.message().contains("at least 1 second"));

        let oversized =
            validate_pprof_duration_secs(Some(MAX_PPROF_DURATION_SECS + 1)).unwrap_err();
        assert!(oversized.message().contains("must not exceed"));
    }
}

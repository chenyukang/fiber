mod config;
pub use config::Config;

pub mod ckb_chain;

pub mod ldk;
pub use ldk::{start_ldk, LdkConfig};
pub mod ckb;
pub use ckb::{start_ckb, CkbConfig, NetworkServiceEvent};
pub mod cch;
pub use cch::{start_cch, CchConfig};

pub mod rpc;
pub use rpc::{start_rpc, RpcConfig};
pub mod invoice;
pub mod store;

mod errors;
pub use errors::{Error, Result};

pub mod actors;

pub mod tasks;

fn get_prefix() -> &'static str {
    static INSTANCE: once_cell::sync::OnceCell<String> = once_cell::sync::OnceCell::new();
    INSTANCE.get_or_init(|| {
        let node_env = std::env::var("LOG_PREFIX").unwrap_or_else(|_| "".to_string());
        node_env
    })
}
/// Logs a debug message with a "[node1]" prefix.
pub fn node_debug(args: std::fmt::Arguments) {
    tracing::debug!("{}{}", get_prefix(), args);
}

pub fn node_warn(args: std::fmt::Arguments) {
    tracing::warn!("{}{}", get_prefix(), args);
}

pub fn node_error(args: std::fmt::Arguments) {
    tracing::error!("{}{}", get_prefix(), args);
}

pub fn node_info(args: std::fmt::Arguments) {
    tracing::info!("{}{}", get_prefix(), args);
}

pub mod macros {
    #[macro_export]
    macro_rules! unwrap_or_return {
        ($expr:expr, $msg:expr) => {
            match $expr {
                Ok(val) => val,
                Err(err) => {
                    error!("{}: {:?}", $msg, err);
                    return;
                }
            }
        };
        ($expr:expr) => {
            match $expr {
                Ok(val) => val,
                Err(err) => {
                    error!("{:?}", err);
                    return;
                }
            }
        };
    }

    /// A macro to simplify the usage of `debug_with_node_prefix` function.
    #[macro_export]
    macro_rules! debug {
        ($($arg:tt)*) => {
            $crate::node_debug(format_args!($($arg)*))
        };
    }

    #[macro_export]
    macro_rules! warn {
        ($($arg:tt)*) => {
            $crate::node_warn(format_args!($($arg)*))
        };
    }

    #[macro_export]
    macro_rules! error {
        ($($arg:tt)*) => {
            $crate::node_error(format_args!($($arg)*))
        };
    }

    #[macro_export]
    macro_rules! info {
        ($($arg:tt)*) => {
            $crate::node_info(format_args!($($arg)*))
        };
    }
}

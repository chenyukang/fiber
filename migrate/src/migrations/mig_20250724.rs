use fiber::{
    fiber::channel::{ChannelActorStateStore, ChannelState, RetryableTlcOperation},
    store::migration::Migration,
    Error,
};
use indicatif::ProgressBar;
use std::sync::Arc;

// Remember to update the version number here
const MIGRATION_DB_VERSION: &str = "20300724111111";

pub struct MigrationObj {
    version: String,
}

impl MigrationObj {
    pub fn new() -> Self {
        Self {
            version: MIGRATION_DB_VERSION.to_string(),
        }
    }
}

impl Migration for MigrationObj {
    fn migrate<'a>(
        &self,
        db: &'a fiber::store::Store,
        _pb: Arc<dyn Fn(u64) -> ProgressBar + Send + Sync>,
    ) -> Result<&'a fiber::store::Store, Error> {
        eprintln!(
            "MigrationObj::migrate .....{}.... now ",
            MIGRATION_DB_VERSION
        );
        let res = db.get_channel_states(None);
        eprintln!("channel count: {}", res.len());
        let mut task_count = 0;
        let mut forward_tlc_op = 0;
        let mut relay_remove_tlc = 0;
        let mut remove_tlc = 0;
        for (_peer_id, channel_id, channel_state) in db.get_channel_states(None) {
            eprintln!(
                "now check channel_id: {}, state: {:?}",
                channel_id, channel_state
            );
            if matches!(channel_state, ChannelState::ChannelReady) {
                if let Some(actor_state) = db.get_channel_actor_state(&channel_id) {
                    eprintln!("now will process channel actor state: {:?}", channel_id);
                    let task = actor_state.tlc_state.retryable_tlc_operations;
                    if task.len() > 0 {
                        for task in task.iter() {
                            eprintln!(
                                "now channel actor state: {:?}, task: {:?}",
                                channel_id, task
                            );
                            match task {
                                RetryableTlcOperation::ForwardTlc(..) => {
                                    forward_tlc_op += 1;
                                }
                                RetryableTlcOperation::RelayRemoveTlc(..) => {
                                    relay_remove_tlc += 1;
                                }
                                RetryableTlcOperation::RemoveTlc(..) => {
                                    remove_tlc += 1;
                                }
                            }
                        }
                    }
                    task_count += task.len();
                    // eprintln!(
                    //     "now channel actor state: {:?}, task count: {}",
                    //     channel_id, task_count
                    // );
                }
            }
        }

        eprintln!("Total tasks to process: {}", task_count);
        eprintln!(
            "Forward Tlc: {}, Relay Remove Tlc: {}, RemoveTlc: {}",
            forward_tlc_op, relay_remove_tlc, remove_tlc
        );

        Err(Error::InvalidPeerMessage(
            "This migration is not implemented yet".to_string(),
        ))
    }

    fn version(&self) -> &str {
        &self.version
    }

    fn is_break_change(&self) -> bool {
        false
    }
}

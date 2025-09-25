use fiber::fiber::channel::ChannelActorState;
use fiber::{store::migration::Migration, Error};
use indicatif::ProgressBar;
use std::sync::Arc;

// Remember to update the version number here
const MIGRATION_DB_VERSION: &str = "20250924111111";

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
        eprintln!("MigrationObj::migrate .....{}....", MIGRATION_DB_VERSION);
        const CHANNEL_ACTOR_STATE_PREFIX: u8 = 0;
        let prefix = vec![CHANNEL_ACTOR_STATE_PREFIX];

        for (_k, v) in db
            .prefix_iterator(prefix.clone().as_slice())
            .take_while(move |(col_key, _)| col_key.starts_with(prefix.as_slice()))
        {
            if let Ok(channel_actor_state) = bincode::deserialize::<ChannelActorState>(&v) {
                // eprintln!(
                //     "channel_id: {:?} actor_state: {:?}",
                //     channel_actor_state.id, channel_actor_state.state
                // );
                channel_actor_state.debug_size();
            }
        }
        return Err(Error::DBInternalError(
            "This migration is a debug code".to_string(),
        ));
    }

    fn version(&self) -> &str {
        &self.version
    }

    fn is_break_change(&self) -> bool {
        // This migration is a breaking change for MPP and security updates
        false
    }
}

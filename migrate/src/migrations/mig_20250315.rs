pub use fiber::fiber::channel::ChannelActorState as ChannelActorStateV041;
use fiber::fiber::channel::ChannelActorStateStore;
use fiber::store::Store;
use fiber::{store::migration::Migration, Error};
use indicatif::ProgressBar;
use rocksdb::ops::{Delete, Get, Iterate, Put};
use rocksdb::DB;
use std::sync::Arc;
use tracing::info;

const MIGRATION_DB_VERSION: &str = "20250315000623";

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
    fn migrate(
        &self,
        db: Arc<DB>,
        _pb: Arc<dyn Fn(u64) -> ProgressBar + Send + Sync>,
    ) -> Result<Arc<DB>, Error> {
        info!(
            "MigrationObj::migrate to {} ...........",
            MIGRATION_DB_VERSION
        );

        const CHANNEL_ACTOR_STATE_PREFIX: u8 = 0;
        let prefix = vec![CHANNEL_ACTOR_STATE_PREFIX];

        let store = Store::new_with_db(db.clone());
        for (k, v) in db
            .prefix_iterator(prefix.as_slice())
            .take_while(move |(col_key, _)| col_key.starts_with(prefix.as_slice()))
        {
            if let Ok(channel_state) = bincode::deserialize::<ChannelActorStateV041>(&v) {
                // if we can deserialize the data correctly with new version, just skip it.
                eprintln!(
                    "channel id: {:?} state: {:?}",
                    channel_state.id, channel_state.state
                );
                let channel_state = store
                    .get_channel_actor_state(&channel_state.id)
                    .expect("get channel state");
                eprintln!("got channel state: {:?}", channel_state.id);
                continue;
            } else {
                eprintln!("failed : {:?}", k);
            }
        }
        panic!("finished checking ....");
        Ok(db)
    }

    fn version(&self) -> &str {
        &self.version
    }
}

use crate::util::convert;

use fiber::{
    fiber::channel::ChannelActorState,
    store::{migration::Migration, Store},
    Error,
};
use indicatif::ProgressBar;
use std::sync::Arc;
use tracing::info;

// Remember to update the version number here, sample `20311116135521`
const MIGRATION_DB_VERSION: &str = "20260203152333";

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
        db: &'a Store,
        _pb: Arc<dyn Fn(u64) -> ProgressBar + Send + Sync>,
    ) -> Result<&'a Store, Error> {
        info!(
            "MigrationObj::migrate to {} ...........",
            MIGRATION_DB_VERSION
        );

        info!("migrate ChannelActorState ...");
        const CHANNEL_ACTOR_STATE_PREFIX: u8 = 0;
        let prefix = vec![CHANNEL_ACTOR_STATE_PREFIX];
        for (k, v) in db
            .prefix_iterator(prefix.as_slice())
            .take_while(|(col_key, _)| col_key.starts_with(prefix.as_slice()))
        {
            let res = bincode::deserialize::<ChannelActorState>(&v)
                .expect("deserialize to channel state");
            let id = res.local_pubkey;
            eprintln!("migrating channel actor state id: {:?}", id);
        }

        panic!("now debug");
        Ok(db)
    }

    fn version(&self) -> &str {
        &self.version
    }
}

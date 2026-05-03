//! Standalone message-expiry binary's TOML config.
//!
//! Only the `[database]` section is consumed — the binary needs Redis
//! connection settings to construct a `RedisStore`. The trait-based
//! sweep loop has no other tunables.

use affinidi_messaging_mediator_common::database::config::DatabaseConfig;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct Config {
    pub database: DatabaseConfig,
}

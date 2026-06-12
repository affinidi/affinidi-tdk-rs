use serde::{Deserialize, Serialize};

use crate::errors::MediatorError;

/// Database Struct contains database and storage of messages related configuration details
///
/// `database_pool_size` was removed in favour of the multiplexed
/// connection; `#[serde(default, skip_serializing)]` on an ignored
/// field silently drops pre-0.14 config files that still set it
/// rather than hard-failing on an unknown key.
#[derive(Debug, Serialize, Deserialize)]
pub struct DatabaseConfigRaw {
    pub functions_file: String,
    pub database_url: String,
    pub database_timeout: String,
    pub scripts_path: Option<String>,
    /// Silently absorbed — pre-0.14 config files set this; the
    /// multiplexed Redis connection doesn't use a pool. The field
    /// stays in the raw struct so deserialisation doesn't error on
    /// unknown keys; it's not round-tripped on serialise.
    #[serde(default, skip_serializing, rename = "database_pool_size")]
    _ignored_pool_size: Option<serde_json::Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DatabaseConfig {
    pub functions_file: Option<String>,
    pub database_url: String,
    pub database_timeout: u32,
    /// Number of consecutive failures before the circuit breaker opens
    pub circuit_breaker_threshold: u32,
    /// Seconds to wait before probing Redis after circuit opens
    pub circuit_breaker_recovery_secs: u64,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        DatabaseConfig {
            functions_file: Some("./conf/atm-functions.lua".into()),
            database_url: "redis://127.0.0.1/".into(),
            database_timeout: 2,
            circuit_breaker_threshold: 5,
            circuit_breaker_recovery_secs: 10,
        }
    }
}

impl std::convert::TryFrom<DatabaseConfigRaw> for DatabaseConfig {
    type Error = MediatorError;

    fn try_from(raw: DatabaseConfigRaw) -> Result<Self, Self::Error> {
        Ok(DatabaseConfig {
            functions_file: Some(raw.functions_file),
            database_url: raw.database_url,
            database_timeout: raw.database_timeout.parse().unwrap_or(2),
            circuit_breaker_threshold: 5,
            circuit_breaker_recovery_secs: 10,
        })
    }
}

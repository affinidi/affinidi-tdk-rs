use serde::{Deserialize, Serialize};

use crate::errors::MediatorError;

/// Database Struct contains database and storage of messages related configuration details
#[derive(Debug, Serialize, Deserialize)]
pub struct DatabaseConfigRaw {
    pub functions_file: String,
    pub database_url: String,
    pub database_pool_size: String,
    pub database_timeout: String,
    pub scripts_path: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DatabaseConfig {
    pub functions_file: Option<String>,
    pub database_url: String,
    pub database_pool_size: usize,
    pub database_timeout: u32,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        DatabaseConfig {
            functions_file: Some("./conf/atm-functions.lua".into()),
            database_url: "redis://127.0.0.1/".into(),
            database_pool_size: 10,
            database_timeout: 2,
        }
    }
}

impl std::convert::TryFrom<DatabaseConfigRaw> for DatabaseConfig {
    type Error = MediatorError;

    fn try_from(raw: DatabaseConfigRaw) -> Result<Self, Self::Error> {
        Ok(DatabaseConfig {
            functions_file: Some(raw.functions_file),
            database_url: raw.database_url,
            database_pool_size: raw.database_pool_size.parse().unwrap_or(10),
            database_timeout: raw.database_timeout.parse().unwrap_or(2),
        })
    }
}

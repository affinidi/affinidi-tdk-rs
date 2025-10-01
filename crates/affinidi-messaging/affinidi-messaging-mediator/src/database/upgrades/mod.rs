/*!
 * Handles upgrades from one version to another for the database schema
 */

use super::Database;
use affinidi_messaging_mediator_common::errors::MediatorError;

pub(crate) mod v0_10_0;
pub(crate) mod v0_11_0;

impl Database {
    pub(crate) async fn upgrade_change_schema_version(
        &self,
        version: &str,
    ) -> Result<(), MediatorError> {
        let mut con = self.0.get_async_connection().await?;
        deadpool_redis::redis::Cmd::hset("GLOBAL", "SCHEMA_VERSION", version)
            .exec_async(&mut con)
            .await
            .map_err(|e| {
                MediatorError::DatabaseError(
                    13,
                    "NA".into(),
                    format!("Couldn't set database SCHEMA_VERSION: {}", e),
                )
            })
    }
}

/*!
 * Upgrades to the current version.
 *
 * Sets the schema version to the current mediator version without performing any migrations.
 */
use crate::database::Database;
use affinidi_messaging_mediator_common::errors::MediatorError;

impl Database {
    pub(crate) async fn upgrade_to_current_version(
        &self,
        current_version: &str,
    ) -> Result<(), MediatorError> {
        self.upgrade_change_schema_version(current_version).await
    }
}

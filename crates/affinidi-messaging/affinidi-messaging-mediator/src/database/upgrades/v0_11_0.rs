/*!
 * Upgrades to version 0.11
 *
 * Adds ACL Flag to set queue limits. Sets this flag based on the mediator configuration
 */
use crate::database::Database;
use affinidi_messaging_mediator_common::errors::MediatorError;

impl Database {
    pub(crate) async fn upgrade_0_11_1(&self) -> Result<(), MediatorError> {
        self.upgrade_change_schema_version("0.11.1").await
    }
}

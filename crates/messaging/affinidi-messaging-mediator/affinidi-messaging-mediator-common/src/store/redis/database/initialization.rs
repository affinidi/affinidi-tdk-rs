/*!
 * Handles the initial setup of the database when the Mediator starts
 */

use super::migrations::run_pending_migrations;
use crate::errors::MediatorError;
use crate::store::redis::RedisStore;
use crate::store::redis::init::RedisInitConfig;
use crate::types::{accounts::AccountType, acls::MediatorACLSet};
use sha256::digest;

impl RedisStore {
    /// Run schema migrations and seed the mediator + root-admin
    /// accounts. Called once at startup before the trait's
    /// [`initialize`](crate::store::MediatorStore::initialize)
    /// hook (which loads Lua functions). Named `initialize_redis` to
    /// avoid colliding with the trait method.
    pub async fn initialize_redis(&self, config: &RedisInitConfig) -> Result<(), MediatorError> {
        // Run any pending schema migrations
        run_pending_migrations(self, config).await?;

        // Setup the mediator account if it doesn't exist
        // Set the ACL for the mediator account to deny_all by default
        let mediator_acl =
            MediatorACLSet::from_string_ruleset("DENY_ALL,LOCAL,BLOCKED").map_err(|e| {
                MediatorError::ConfigError(
                    12, // CONFIG_ERROR — mirrors mediator::common::error_codes::CONFIG_ERROR
                    "NA".into(),
                    format!("Hardcoded mediator ACL ruleset is invalid: {e}"),
                )
            })?;

        self.setup_admin_account(
            &config.mediator_did_hash,
            AccountType::Mediator,
            &mediator_acl,
        )
        .await?;

        // Set up the administration account if it doesn't exist
        self.setup_admin_account(
            &digest(&config.admin_did),
            AccountType::RootAdmin,
            &config.global_acl_default,
        )
        .await?;
        Ok(())
    }
}

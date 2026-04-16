/*!
 * Handles the initial setup of the database when the Mediator starts
 */

use super::Database;
use super::migrations::run_pending_migrations;
use crate::common::config::Config;
use affinidi_messaging_mediator_common::errors::MediatorError;
use affinidi_messaging_sdk::protocols::mediator::{accounts::AccountType, acls::MediatorACLSet};
use sha256::digest;

impl Database {
    /// Initializes the database and ensures minimal configuration required is in place.
    pub(crate) async fn initialize(&self, config: &Config) -> Result<(), MediatorError> {
        // Run any pending schema migrations
        run_pending_migrations(self, config).await?;

        // Setup the mediator account if it doesn't exist
        // Set the ACL for the mediator account to deny_all by default
        self.setup_admin_account(
            &config.mediator_did_hash,
            AccountType::Mediator,
            &MediatorACLSet::from_string_ruleset("DENY_ALL,LOCAL,BLOCKED")
                .expect("hardcoded ACL ruleset is valid"),
        )
        .await
        .expect("Could not setup mediator account! exiting...");

        // Set up the administration account if it doesn't exist
        self.setup_admin_account(
            &digest(&config.admin_did),
            AccountType::RootAdmin,
            &config.security.global_acl_default,
        )
        .await
        .expect("Could not setup admin account! exiting...");
        Ok(())
    }
}

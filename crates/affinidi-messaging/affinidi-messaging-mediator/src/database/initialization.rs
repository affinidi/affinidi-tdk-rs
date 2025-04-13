/*!
 * Handles the initial setup of the database when the Mediator starts
 */

use super::Database;
use crate::common::config::Config;
use affinidi_messaging_mediator_common::errors::MediatorError;
use affinidi_messaging_sdk::protocols::mediator::{accounts::AccountType, acls::MediatorACLSet};
use semver::Version;
use sha256::digest;
use tracing::{info, warn};

impl Database {
    /// Initializes the database and ensures minimal configuration required is in place.
    pub(crate) async fn initialize(&self, config: &Config) -> Result<(), MediatorError> {
        // Check the schema version and update if necessary
        // TODO: Update is not implemented yet
        self._check_schema_version(config).await?;

        // Setup the mediator account if it doesn't exist
        // Set the ACL for the mediator account to deny_all by default
        self.setup_admin_account(
            &config.mediator_did_hash,
            AccountType::Mediator,
            &MediatorACLSet::from_string_ruleset("DENY_ALL,LOCAL,BLOCKED").unwrap(),
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

    async fn _check_schema_version(&self, config: &Config) -> Result<(), MediatorError> {
        let mut conn = self.0.get_async_connection().await?;

        let schema_version: Option<String> =
            deadpool_redis::redis::Cmd::hget("GLOBAL", "SCHEMA_VERSION")
                .query_async(&mut conn)
                .await
                .map_err(|e| {
                    MediatorError::DatabaseError(
                        14,
                        "NA".into(),
                        format!("Couldn't get database SCHEMA_VERSION: {}", e),
                    )
                })?;

        if let Some(schema_version) = schema_version {
            let mediator_version = Version::parse(env!("CARGO_PKG_VERSION")).map_err(|e| {
                MediatorError::InternalError(
                    17,
                    "NA".into(),
                    format!(
                        "Couldn't parse mediator package version ({}). Reason: {}",
                        schema_version, e
                    ),
                )
            })?;
            let schema_version = Version::parse(&schema_version).map_err(|e| {
                MediatorError::InternalError(
                    17,
                    "NA".into(),
                    format!(
                        "Couldn't parse database SCHEMA_VERSION ({}). Reason: {}",
                        schema_version, e
                    ),
                )
            })?;

            if mediator_version == schema_version {
                info!("Database schema version ({}) is good", schema_version);
            } else {
                // The schema version doesn't match the mediator version
                warn!(
                    "Database schema version ({}) doesn't match mediator version ({}).",
                    schema_version, mediator_version
                );
                if schema_version < Version::parse("0.10.0").unwrap() {
                    // Upgrade the database schema to 0.10.0
                    self.upgrade_0_10_0(&config.security.global_acl_default)
                        .await?;
                    info!("Database schema version updated to ({})", mediator_version);
                } else if schema_version < Version::parse("0.10.2").unwrap() {
                    self.upgrade_0_10_2().await?;
                } else if schema_version < Version::parse("0.10.3").unwrap() {
                    self.upgrade_0_10_3().await?;
                }
                info!("Database schema version updated to ({})", mediator_version);
            }
        } else {
            warn!(
                "Unknown database schema version. Setting to ({})",
                env!("CARGO_PKG_VERSION")
            );
            // Set the schema version
            self.upgrade_change_schema_version(env!("CARGO_PKG_VERSION"))
                .await?;
        }
        Ok(())
    }
}

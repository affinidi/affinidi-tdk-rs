/*!
 * Handles the initial setup of the database when the Mediator starts
 */

use super::Database;
use crate::common::config::Config;
use affinidi_messaging_mediator_common::errors::MediatorError;
use affinidi_messaging_sdk::protocols::mediator::{accounts::AccountType, acls::MediatorACLSet};
use semver::Version;
use sha256::digest;
use tracing::{error, info, warn};

impl Database {
    /// Initializes the database and ensures minimal configuration required is in place.
    pub(crate) async fn initialize(&self, config: &Config) -> Result<(), MediatorError> {
        // Check the schema version and update if necessary
        self._check_schema_version(config).await?;

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

    /// Check the database schema version and run migrations if needed.
    ///
    /// Migration chain: each step upgrades to a specific version and falls through
    /// to check for further upgrades. This ensures databases at any previous version
    /// are brought up to current in order.
    async fn _check_schema_version(&self, config: &Config) -> Result<(), MediatorError> {
        let mut conn = self.get_connection().await?;

        let schema_version: Option<String> = redis::Cmd::hget("GLOBAL", "SCHEMA_VERSION")
            .query_async(&mut conn)
            .await
            .map_err(|e| {
                MediatorError::DatabaseError(
                    14,
                    "NA".into(),
                    format!("Couldn't get database SCHEMA_VERSION: {e}"),
                )
            })?;

        if let Some(schema_version_str) = schema_version {
            let mediator_version = Version::parse(env!("CARGO_PKG_VERSION")).map_err(|e| {
                MediatorError::InternalError(
                    17,
                    "NA".into(),
                    format!("Couldn't parse mediator package version. Reason: {e}"),
                )
            })?;
            let schema_version = Version::parse(&schema_version_str).map_err(|e| {
                MediatorError::InternalError(
                    17,
                    "NA".into(),
                    format!(
                        "Couldn't parse database SCHEMA_VERSION ({schema_version_str}). Reason: {e}"
                    ),
                )
            })?;

            if mediator_version == schema_version {
                info!("Database schema version ({}) is good", schema_version);
                return Ok(());
            }

            if schema_version > mediator_version {
                error!(
                    "Database schema version ({}) is newer than mediator version ({}). \
                     This mediator binary cannot run against a newer database schema. \
                     Please upgrade the mediator binary.",
                    schema_version, mediator_version
                );
                return Err(MediatorError::InternalError(
                    17,
                    "NA".into(),
                    format!(
                        "Database schema version ({schema_version}) is newer than mediator version ({mediator_version}). Please upgrade the mediator."
                    ),
                ));
            }

            // Database is older than mediator — run migrations in order
            warn!(
                "Database schema version ({}) is behind mediator version ({}). Running migrations...",
                schema_version, mediator_version
            );

            // Migration: < 0.10.0 → 0.10.0 (ACL queue limit flags)
            if schema_version < Version::parse("0.10.0").expect("hardcoded version string is valid")
            {
                self.upgrade_0_10_0(&config.security.global_acl_default)
                    .await?;
            }

            // Migration: < 0.14.0 → 0.14.0 (Lua script optimizations, no data changes)
            if schema_version < Version::parse("0.14.0").expect("hardcoded version string is valid")
            {
                self.upgrade_0_14_0().await?;
            }

            // Bump to current version if we're between the last migration and current
            self.upgrade_to_current_version(mediator_version.to_string().as_str())
                .await?;
            info!(
                "Database schema migration complete. Version: {}",
                mediator_version
            );
        } else {
            warn!(
                "Unknown database schema version. Setting to ({})",
                env!("CARGO_PKG_VERSION")
            );
            // Fresh database — set the schema version
            self.upgrade_change_schema_version(env!("CARGO_PKG_VERSION"))
                .await?;
        }
        Ok(())
    }
}

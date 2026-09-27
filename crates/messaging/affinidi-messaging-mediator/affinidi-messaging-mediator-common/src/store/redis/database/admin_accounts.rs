//! Database routines to add/remove/list admin accounts
use crate::errors::MediatorError;
use crate::types::{accounts::AccountType, acls::MediatorACLSet};
use tracing::{Instrument, Level, debug, info, span};

use super::Database;

// Redis-backend implementation behind `RedisStore`.
impl Database {
    /// Ensures that the mediator admin account is correctly configured and set up.
    /// It does not do any cleanup or maintenance of other admin accounts.
    /// Updates both the DID role type and the global ADMIN Set in Redis.
    pub(crate) async fn setup_admin_account(
        &self,
        admin_did_hash: &str,
        admin_type: AccountType,
        acls: &MediatorACLSet,
    ) -> Result<(), MediatorError> {
        // Check if the admin account already exists
        if !self.account_exists(admin_did_hash).await? {
            debug!("Admin account doesn't exist, creating: {}", admin_did_hash);
            self.account_add(admin_did_hash, acls, None).await?;
        }
        let mut con = self.get_connection().await?;

        debug!(
            "Admin DID ({}) == hash ({})",
            admin_did_hash, admin_did_hash
        );

        redis::pipe()
            .atomic()
            .cmd("SADD")
            .arg("ADMINS")
            .arg(admin_did_hash)
            .ignore()
            .cmd("HSET")
            .arg(["DID:", admin_did_hash].concat())
            .arg("ROLE_TYPE")
            .arg::<String>(admin_type.into())
            .ignore()
            .exec_async(&mut con)
            .await
            .map_err(|err| {
                MediatorError::DatabaseError(
                    14,
                    "NA".to_string(),
                    format!("Failed to set up admin account for ({admin_did_hash}). Reason: {err}"),
                )
            })?;

        info!("Admin account successfully setup: {}", admin_did_hash);
        Ok(())
    }

    /// Checks if the provided DID is an admin level account
    /// Returns true if the DID is an admin account, false otherwise
    pub(crate) async fn check_admin_account(&self, did_hash: &str) -> Result<bool, MediatorError> {
        let mut con = self.get_connection().await?;

        let (exists, role_type): (u32, u32) = redis::pipe()
            .atomic()
            .cmd("SISMEMBER")
            .arg("ADMINS")
            .arg(did_hash)
            .cmd("HGET")
            .arg(["DID:", did_hash].concat())
            .arg("ROLE_TYPE")
            .query_async(&mut con)
            .await
            .map_err(|err| {
                MediatorError::DatabaseError(
                    14,
                    "NA".to_string(),
                    format!("Failed to check admin account for ({did_hash}). Reason: {err}"),
                )
            })?;

        if exists == 1 {
            match role_type.into() {
                AccountType::RootAdmin => Ok(true),
                AccountType::Admin => Ok(true),
                _ => Ok(false),
            }
        } else {
            Ok(false)
        }
    }

    /// Adds up to 100 admin accounts to the mediator
    /// - `accounts` - The list of accounts to add
    ///
    /// Superseded by [`MediatorStore::add_admin_accounts`] (default
    /// impl loops over [`setup_admin_account`]); kept as a Redis-
    /// specific helper for operator tooling that may want a single
    /// pipelined batch.
    ///
    /// [`MediatorStore::add_admin_accounts`]: crate::store::MediatorStore::add_admin_accounts
    /// [`setup_admin_account`]: crate::store::MediatorStore::setup_admin_account
    #[allow(dead_code)]
    pub(crate) async fn add_admin_accounts(
        &self,
        accounts: Vec<String>,
        acls: &MediatorACLSet,
    ) -> Result<usize, MediatorError> {
        let _span = span!(
            Level::DEBUG,
            "add_admin_accounts",
            "#_accounts" = accounts.len(),
        );

        async move {
            debug!("Adding Admin accounts to the mediator");
            if accounts.len() > 100 {
                return Err(MediatorError::DatabaseError(
                    15,
                    "NA".to_string(),
                    "Number of admin accounts being added exceeds 100".to_string(),
                ));
            }

            for account in &accounts {
                debug!("Adding Admin account: {}", account);
                self.setup_admin_account(account, AccountType::Admin, acls)
                    .await?;
            }

            Ok(accounts.len())
        }
        .instrument(_span)
        .await
    }

    /// Strips up to 100 admin accounts from the mediator
    /// - `accounts` - The list of DID hashes to strip admin rights from
    pub(crate) async fn strip_admin_accounts(
        &self,
        accounts: Vec<String>,
    ) -> Result<i32, MediatorError> {
        let _span = span!(
            Level::DEBUG,
            "remove_admin_accounts",
            "#_accounts" = accounts.len(),
        );

        async move {
            debug!("Removing Admin accounts from the mediator");
            if accounts.len() > 100 {
                return Err(MediatorError::DatabaseError(
                    16,
                    "NA".to_string(),
                    "Number of admin accounts being removed exceeds 100".to_string(),
                ));
            }

            let mut con = self.get_connection().await?;

            let mut tx = redis::pipe();
            let mut tx = tx.atomic().cmd("SREM").arg("ADMINS");

            // Remove from the ADMINS Set
            for account in &accounts {
                debug!("Removing Admin account: {}", account);
                tx = tx.arg(account);
            }

            // Remove admin field on each DID
            for account in &accounts {
                tx = tx
                    .cmd("HSET")
                    .arg(["DID:", account].concat())
                    .arg("ROLE_TYPE")
                    .arg::<String>(AccountType::Standard.into());
            }

            let result: Vec<i32> = tx.query_async(&mut con).await.map_err(|err| {
                MediatorError::DatabaseError(
                    14,
                    "NA".to_string(),
                    format!("Failed to remove admin account. Reason: {err}"),
                )
            })?;
            debug!("Admin accounts removed successfully: {:?}", result);

            Ok(result.first().unwrap_or(&0).to_owned())
        }
        .instrument(_span)
        .await
    }
}

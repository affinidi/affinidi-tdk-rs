//! Handles scanning, adding and removing DID accounts from the mediator
use super::Database;
use crate::errors::MediatorError;
use crate::store::types::Session;
use affinidi_messaging_sdk::{
    messages::Folder,
    protocols::mediator::{
        accounts::{Account, AccountType, MediatorAccountList},
        acls::MediatorACLSet,
    },
};
use ahash::AHashMap as HashMap;
use redis::Pipeline;
use tokio::join;
use tracing::{Instrument, Level, debug, span};

// Private helper function to translate HashMap into an Account
fn _to_account(map: HashMap<String, String>, access_list_count: u32) -> Account {
    let mut account = Account {
        access_list_count,
        ..Default::default()
    };

    for (key, value) in &map {
        match key.as_str() {
            "ROLE_TYPE" => account._type = AccountType::from(value.as_str()),
            "ACLS" => account.acls = u64::from_str_radix(value, 16).unwrap_or(0_u64),
            "SEND_QUEUE_LIMIT" => account.queue_send_limit = value.parse().ok(),
            "RECEIVE_QUEUE_LIMIT" => account.queue_receive_limit = value.parse().ok(),
            "SEND_QUEUE_BYTES" => account.send_queue_bytes = value.parse().unwrap_or(0),
            "SEND_QUEUE_COUNT" => account.send_queue_count = value.parse().unwrap_or(0),
            "RECEIVE_QUEUE_BYTES" => account.receive_queue_bytes = value.parse().unwrap_or(0),
            "RECEIVE_QUEUE_COUNT" => account.receive_queue_count = value.parse().unwrap_or(0),
            _ => {}
        }
    }

    account
}

// These methods are the Redis-backend implementation behind
// `RedisStore`. On `memory-backend` / `fjall-backend` builds the Redis
// path is gated out and the compiler reports them as dead, but they
// remain part of the build matrix that the `redis-backend` feature
// activates — silence the warning rather than gating each method.
#[allow(dead_code)]
impl Database {
    /// Quick and efficient check if an account exists locally in the mediator
    pub(crate) async fn account_exists(&self, did_hash: &str) -> Result<bool, MediatorError> {
        let mut con = self.get_connection().await?;

        redis::cmd("EXISTS")
            .arg(["DID:", did_hash].concat())
            .query_async(&mut con)
            .await
            .map_err(|err| {
                MediatorError::DatabaseError(
                    14,
                    "NA".to_string(),
                    format!("Failed to check account existence. Reason: {err}"),
                )
            })
    }

    /// Grab Account information
    /// Returns Ok<Some<Account>> if the account exists
    /// Returns Ok<None> if the account does not exist
    /// Returns Err if there is an error
    pub(crate) async fn account_get(
        &self,
        did_hash: &str,
    ) -> Result<Option<Account>, MediatorError> {
        let mut con = self.get_connection().await?;

        let (details, access_list_count): (HashMap<String, String>, u32) = redis::pipe()
            .atomic()
            .hgetall(["DID:", did_hash].concat())
            .scard(["ACCESS_LIST:", did_hash].concat())
            .query_async(&mut con)
            .await
            .map_err(|err| {
                MediatorError::DatabaseError(
                    14,
                    "NA".to_string(),
                    format!("Failed to get account details. Reason: {err}"),
                )
            })?;

        if details.is_empty() {
            debug!("Account {} does not exist", did_hash);
            return Ok(None);
        }
        let mut account = _to_account(details, access_list_count);
        account.did_hash = did_hash.to_string();
        Ok(Some(account))
    }

    /// Add a DID account to the mediator
    /// - `did_hash` - SHA256 hash of the DID
    /// - `acls` - ACLs to apply to the account
    /// - `queue_limit` - Optional queue limit for the account
    pub(crate) async fn account_add(
        &self,
        did_hash: &str,
        acls: &MediatorACLSet,
        queue_limit: Option<u32>,
    ) -> Result<Account, MediatorError> {
        let _span = span!(Level::DEBUG, "add_account", "did_hash" = did_hash,);

        async move {
            debug!("Adding account to the mediator");

            let mut con = self.get_connection().await?;

            let mut cmd = redis::pipe();
            let mut cmd = cmd
                .atomic()
                .cmd("SADD")
                .arg("KNOWN_DIDS")
                .arg(did_hash)
                .cmd("HSET")
                .arg(["DID:", did_hash].concat())
                .arg("SEND_QUEUE_BYTES")
                .arg(0)
                .arg("SEND_QUEUE_COUNT")
                .arg(0)
                .arg("RECEIVE_QUEUE_BYTES")
                .arg(0)
                .arg("RECEIVE_QUEUE_COUNT")
                .arg(0)
                .arg("ROLE_TYPE")
                .arg::<String>(AccountType::Standard.into())
                .arg("ACLS")
                .arg(acls.to_hex_string());

            if let Some(queue_limit) = queue_limit {
                cmd = cmd.arg("QUEUE_LIMIT").arg(queue_limit);
            }

            cmd.exec_async(&mut con).await.map_err(|err| {
                MediatorError::DatabaseError(
                    14,
                    "NA".to_string(),
                    format!("Failed to add account. Reason: {err}"),
                )
            })?;
            debug!("Account added successfully");

            Ok(Account {
                did_hash: did_hash.to_string(),
                acls: acls.to_u64(),
                ..Default::default()
            })
        }
        .instrument(_span)
        .await
    }

    /// Removes an account from the mediator.
    /// - `did_hash` — SHA256 hash of the DID to remove.
    ///
    /// Drops the outbox stream key (without purging downstream copies
    /// already delivered), purges the inbox, strips admin privileges,
    /// removes the DID record. Forwarded messages already queued on
    /// FORWARD_Q are intentionally left alone — letting them flush is
    /// preferable to a full queue scan, and the protocol exposes no
    /// option to override.
    pub(crate) async fn account_remove(
        &self,
        session: &Session,
        did_hash: &str,
    ) -> Result<bool, MediatorError> {
        let _span = span!(Level::DEBUG, "account_remove", "did_hash" = did_hash,);

        async move {
            debug!("Removing account from the mediator");

            let current = self.account_get(did_hash).await?;
            debug!("retrieving existing account: {:?}", current);

            if let Some(current) = &current {
                if current._type == AccountType::Mediator {
                    return Err(MediatorError::InternalError(
                        18,
                        "NA".to_string(),
                        "Cannot remove the mediator account".to_string(),
                    ));
                } else if current._type == AccountType::RootAdmin {
                    return Err(MediatorError::InternalError(
                        18,
                        "NA".to_string(),
                        "Cannot remove the root admin account".to_string(),
                    ));
                }
            }

            // Step 1 - block access to this account
            let mut blocked_acl = MediatorACLSet::from_u64(0);
            blocked_acl.set_blocked(true);
            self.set_did_acl(did_hash, &blocked_acl).await?;

            // Step 2 - Drop the outbox stream key. We don't purge
            // downstream copies — letting already-queued messages
            // deliver normally is the documented intent.
            self.delete_folder_stream(session, did_hash, &Folder::Outbox)
                .await?;

            // Step 3 - Purge the inbox so future fetches return nothing.
            self.purge_messages(session, did_hash, Folder::Inbox)
                .await?;

            // If DID is an admin account then remove from the admin list
            if let Some(current) = current
                && current._type.is_admin()
            {
                self.strip_admin_accounts(vec![did_hash.to_string()])
                    .await?;
            }

            // Remove from Known DIDs
            // Remove DID Record
            // Remove ACCESS_LIST Set
            let mut con = self.get_connection().await?;
            redis::pipe()
                .atomic()
                .cmd("SREM")
                .arg("KNOWN_DIDS")
                .arg(did_hash)
                .cmd("DEL")
                .arg(["DID:", did_hash].concat())
                .cmd("DEL")
                .arg(["ACCESS_LIST:", did_hash].concat())
                .exec_async(&mut con)
                .await
                .map_err(|err| {
                    MediatorError::DatabaseError(
                        14,
                        "NA".to_string(),
                        format!("Failed to remove DID ({did_hash}) records. Reason: {err}"),
                    )
                })?;

            Ok(true)
        }
        .instrument(_span)
        .await
    }

    /// Retrieves up to 100 accounts from the mediator
    /// - `cursor` - The offset to start from (0 is the start)
    /// - `limit` - The maximum number of accounts to return (max 100)
    ///   NOTE: `limit` may return more than what is specified. This is a peculiarity of Redis
    pub(crate) async fn account_list(
        &self,
        cursor: u32,
        limit: u32,
    ) -> Result<MediatorAccountList, MediatorError> {
        let _span = span!(Level::DEBUG, "account_list", cursor = cursor, limit = limit);

        async move {
            debug!("Requesting list of accounts from mediator");
            let limit = if limit > 100 { 100 } else { limit };

            let mut con = self.get_connection().await?;

            let (new_cursor, dids): (u32, Vec<String>) = redis::cmd("SSCAN")
                .arg("KNOWN_DIDS")
                .arg(cursor)
                .arg("COUNT")
                .arg(limit)
                .query_async(&mut con)
                .await
                .map_err(|err| {
                    MediatorError::DatabaseError(
                        14,
                        "NA".to_string(),
                        format!("Failed to scan access list at cursor ({cursor}). Reason: {err}"),
                    )
                })?;

            // For each DID, fetch their access_list count and DID Details
            let mut did_query = Pipeline::new();
            let did_query = did_query.atomic();
            let mut access_list_query = Pipeline::new();
            let access_list_query = access_list_query.atomic();
            for did in &dids {
                did_query.add_command(redis::Cmd::hgetall(["DID:", did].concat()));
                access_list_query.add_command(redis::Cmd::scard(["ACCESS_LIST:", did].concat()));
            }

            let did_results: Vec<HashMap<String, String>> =
                did_query.query_async(&mut con).await.map_err(|err| {
                    MediatorError::DatabaseError(
                        14,
                        "NA".to_string(),
                        format!("Failed to get DID details. Reason: {err}"),
                    )
                })?;

            let access_list_results: Vec<u32> = access_list_query
                .query_async(&mut con)
                .await
                .map_err(|err| {
                    MediatorError::DatabaseError(
                        14,
                        "NA".to_string(),
                        format!("Failed to get DID access list count. Reason: {err}"),
                    )
                })?;

            let mut accounts = Vec::new();
            for (i, map) in did_results.iter().enumerate() {
                let mut account = _to_account(map.to_owned(), access_list_results[i]);
                account.did_hash = dids[i].clone();
                accounts.push(account);
            }

            Ok(MediatorAccountList {
                accounts,
                cursor: new_cursor,
            })
        }
        .instrument(_span)
        .await
    }

    /// Changes the type of an account to the new type
    /// - `did_hash` - SHA256 hash of the DID
    /// - `_type` - AccountType to change to
    ///
    /// Superseded by [`MediatorStore::account_set_role`]; kept here as
    /// a Redis-specific helper in case operator tooling needs the
    /// legacy entry point.
    ///
    /// [`MediatorStore::account_set_role`]: crate::store::MediatorStore::account_set_role
    #[allow(dead_code)]
    pub(crate) async fn account_change_type(
        &self,
        did_hash: &str,
        _type: &AccountType,
    ) -> Result<(), MediatorError> {
        let _span = span!(
            Level::DEBUG,
            "account_change_type",
            "did_hash" = did_hash,
            "new_type" = _type.to_string()
        );

        async move {
            debug!("Changing account type");

            let mut con = self.get_connection().await?;

            redis::cmd("HSET")
                .arg(["DID:", did_hash].concat())
                .arg("ROLE_TYPE")
                .arg::<String>(_type.to_owned().into())
                .exec_async(&mut con)
                .await
                .map_err(|err| {
                    MediatorError::DatabaseError(
                        14,
                        "NA".to_string(),
                        format!("Failed to change account type. Reason: {err}"),
                    )
                })?;
            debug!("Account type changed successfully");

            Ok(())
        }
        .instrument(_span)
        .await
    }

    /// Changes the queue limits of an account
    /// Assumes that all checks have been done prior to this call
    /// - `did_hash` - SHA256 hash of the DID
    /// - `send_queue_limit` - New send queue limit
    /// - `receive_queue_limit` - New receive queue limit
    ///
    /// NOTE: queue_limit values:
    ///       - None: No change to the queue limit
    ///       - Some(-1): Unlimited
    ///       - Some(-2): Reset to soft limit
    ///       - Some(n): set to n
    pub(crate) async fn account_change_queue_limits(
        &self,
        did_hash: &str,
        send_queue_limit: Option<i32>,
        receive_queue_limit: Option<i32>,
    ) -> Result<(), MediatorError> {
        let _span = span!(
            Level::DEBUG,
            "account_change_queue_limit",
            "did_hash" = did_hash,
            "send_queue_limit" = send_queue_limit,
            "receive_queue_limit" = receive_queue_limit
        );

        async move {
            debug!("Changing account queue_limits");
            let (send, receive) = join!(
                self._change_queue_limit(did_hash, send_queue_limit, "SEND_QUEUE_LIMIT"),
                self._change_queue_limit(did_hash, receive_queue_limit, "RECEIVE_QUEUE_LIMIT")
            );

            send?;
            receive?;

            Ok(())
        }
        .instrument(_span)
        .await
    }

    async fn _change_queue_limit(
        &self,
        did_hash: &str,
        queue_limit: Option<i32>,
        queue_name: &str,
    ) -> Result<(), MediatorError> {
        let mut con = self.get_connection().await?;

        match queue_limit {
            None => return Ok(()),
            Some(-2) => {
                redis::cmd("HDEL")
                    .arg(["DID:", did_hash].concat())
                    .arg(queue_name)
                    .exec_async(&mut con)
                    .await
                    .map_err(|err| {
                        MediatorError::DatabaseError(
                            14,
                            "NA".to_string(),
                            format!("Failed to change queue limit ({queue_name}). Reason: {err}"),
                        )
                    })?;
            }
            Some(n) => {
                redis::cmd("HSET")
                    .arg(["DID:", did_hash].concat())
                    .arg(queue_name)
                    .arg(n)
                    .exec_async(&mut con)
                    .await
                    .map_err(|err| {
                        MediatorError::DatabaseError(
                            23,
                            "NA".to_string(),
                            format!("Failed to change queue limit ({queue_name}). Reason: {err}"),
                        )
                    })?;
            }
        }
        debug!(
            "Account queue_limit ({}) set to ({:?}) changed successfully",
            queue_name, queue_limit
        );
        Ok(())
    }
}

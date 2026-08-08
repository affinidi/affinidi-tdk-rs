//! DIDComm v1 routing-key index.
//!
//! DIDComm v1 addresses a forward's destination by **base58 Ed25519 verkey**,
//! while every routing, ACL, and storage decision in this mediator is keyed by
//! DID hash. This index is the bridge. See
//! [`MediatorStore::v1_routing_key_bind`](crate::store::MediatorStore::v1_routing_key_bind)
//! for the security contract it has to uphold.
//!
//! Two keys per binding, mirroring how `ACCESS_LIST:` pairs with `KNOWN_DIDS`:
//!
//! | Key | Type | Purpose |
//! |---|---|---|
//! | `V1_KEY:<verkey>` | string → DID | forward ingress: verkey → account |
//! | `V1_KEYS:<did_hash>` | set of verkeys | keylist-query and account removal |

use redis::Pipeline;
use tracing::{Instrument, Level, span};

use crate::{errors::MediatorError, store::redis::RedisStore};

/// The verkey → DID-hash key.
pub(crate) fn key_owner(verkey: &str) -> String {
    ["V1_KEY:", verkey].concat()
}

/// The DID-hash → verkey-set key.
pub(crate) fn key_owned(did_hash: &str) -> String {
    ["V1_KEYS:", did_hash].concat()
}

impl RedisStore {
    /// Bind a routing verkey to an account, refusing to steal one already
    /// bound elsewhere.
    ///
    /// `SETNX` is what makes this safe under concurrency: the claim either
    /// wins atomically or loses, and a loser only succeeds if the existing
    /// owner is already this same account. A read-then-write would let two
    /// simultaneous binds both observe "unbound" and the second silently take
    /// over the first account's inbound v1 traffic.
    pub(crate) async fn v1_routing_key_bind(
        &self,
        verkey: &str,
        did: &str,
    ) -> Result<(), MediatorError> {
        let did_hash = sha256::digest(did.as_bytes());
        let _span = span!(Level::DEBUG, "v1_routing_key_bind", verkey, did_hash);
        async move {
            let mut con = self.get_connection().await?;

            let claimed: bool = redis::cmd("SETNX")
                .arg(key_owner(verkey))
                .arg(did)
                .query_async(&mut con)
                .await
                .map_err(|err| {
                    MediatorError::DatabaseError(
                        14,
                        "NA".to_string(),
                        format!("Failed to claim v1 routing key. Reason: {err}"),
                    )
                })?;

            if !claimed {
                let owner: Option<String> = redis::cmd("GET")
                    .arg(key_owner(verkey))
                    .query_async(&mut con)
                    .await
                    .map_err(|err| {
                        MediatorError::DatabaseError(
                            14,
                            "NA".to_string(),
                            format!("Failed to read v1 routing key owner. Reason: {err}"),
                        )
                    })?;

                // A binding that vanished between SETNX and GET (expired or
                // concurrently unbound) is not ours to assume; report it as a
                // conflict rather than silently taking it.
                if owner.as_deref() != Some(did) {
                    return Err(MediatorError::ConfigError(
                        12,
                        "NA".to_string(),
                        "routing verkey is already bound to a different account".to_string(),
                    ));
                }
            }

            // Idempotent either way: the reverse index is a set.
            redis::cmd("SADD")
                .arg(key_owned(&did_hash))
                .arg(verkey)
                .exec_async(&mut con)
                .await
                .map_err(|err| {
                    MediatorError::DatabaseError(
                        14,
                        "NA".to_string(),
                        format!("Failed to index v1 routing key. Reason: {err}"),
                    )
                })?;

            Ok(())
        }
        .instrument(_span)
        .await
    }

    /// The DID bound to `verkey`, if any.
    pub(crate) async fn v1_routing_key_lookup(
        &self,
        verkey: &str,
    ) -> Result<Option<String>, MediatorError> {
        let mut con = self.get_connection().await?;
        redis::cmd("GET")
            .arg(key_owner(verkey))
            .query_async(&mut con)
            .await
            .map_err(|err| {
                MediatorError::DatabaseError(
                    14,
                    "NA".to_string(),
                    format!("Failed to look up v1 routing key. Reason: {err}"),
                )
            })
    }

    /// Drop a binding, returning whether one existed.
    pub(crate) async fn v1_routing_key_unbind(&self, verkey: &str) -> Result<bool, MediatorError> {
        let mut con = self.get_connection().await?;

        let owner: Option<String> = redis::cmd("GET")
            .arg(key_owner(verkey))
            .query_async(&mut con)
            .await
            .map_err(|err| {
                MediatorError::DatabaseError(
                    14,
                    "NA".to_string(),
                    format!("Failed to read v1 routing key owner. Reason: {err}"),
                )
            })?;

        let Some(owner) = owner else {
            return Ok(false);
        };

        let mut pipe = Pipeline::new();
        pipe.atomic()
            .cmd("DEL")
            .arg(key_owner(verkey))
            .cmd("SREM")
            .arg(key_owned(&sha256::digest(owner.as_bytes())))
            .arg(verkey);
        pipe.exec_async(&mut con).await.map_err(|err| {
            MediatorError::DatabaseError(
                14,
                "NA".to_string(),
                format!("Failed to unbind v1 routing key. Reason: {err}"),
            )
        })?;

        Ok(true)
    }

    /// Every routing verkey bound to `did_hash`.
    pub(crate) async fn v1_routing_keys_for(
        &self,
        did_hash: &str,
    ) -> Result<Vec<String>, MediatorError> {
        let mut con = self.get_connection().await?;
        let mut keys: Vec<String> = redis::cmd("SMEMBERS")
            .arg(key_owned(did_hash))
            .query_async(&mut con)
            .await
            .map_err(|err| {
                MediatorError::DatabaseError(
                    14,
                    "NA".to_string(),
                    format!("Failed to list v1 routing keys. Reason: {err}"),
                )
            })?;
        // Redis set order is unspecified; sort so callers see a stable list.
        keys.sort();
        Ok(keys)
    }

    /// Remove every v1 routing key owned by `did_hash`.
    ///
    /// Called from `account_remove`: without it a removed account's verkeys
    /// keep resolving, and inbound v1 traffic keeps being accepted for a
    /// mailbox that no longer exists.
    pub(crate) async fn v1_routing_keys_purge(&self, did_hash: &str) -> Result<(), MediatorError> {
        let verkeys = self.v1_routing_keys_for(did_hash).await?;
        if verkeys.is_empty() {
            return Ok(());
        }

        let mut con = self.get_connection().await?;
        let mut pipe = Pipeline::new();
        pipe.atomic();
        for verkey in &verkeys {
            pipe.cmd("DEL").arg(key_owner(verkey));
        }
        pipe.cmd("DEL").arg(key_owned(did_hash));
        pipe.exec_async(&mut con).await.map_err(|err| {
            MediatorError::DatabaseError(
                14,
                "NA".to_string(),
                format!("Failed to purge v1 routing keys for ({did_hash}). Reason: {err}"),
            )
        })?;

        Ok(())
    }
}

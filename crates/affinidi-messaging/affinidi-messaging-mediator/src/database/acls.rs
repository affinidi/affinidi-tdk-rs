use super::Database;
use affinidi_messaging_mediator_common::errors::MediatorError;
use affinidi_messaging_sdk::protocols::mediator::{
    acls::{AccessListModeType, MediatorACLSet},
    acls_handler::{
        MediatorACLExpanded, MediatorACLGetResponse, MediatorAccessListAddResponse,
        MediatorAccessListGetResponse, MediatorAccessListListResponse,
    },
};
use redis::{Cmd, Pipeline, Value, from_redis_value};
use tracing::{Instrument, Level, debug, span, warn};

impl Database {
    /// Replace the ACL for a given DID
    /// Assumes that the checks on can you change the ACL have already been done
    pub(crate) async fn set_did_acl(
        &self,
        did_hash: &str,
        acls: &MediatorACLSet,
    ) -> Result<MediatorACLSet, MediatorError> {
        let _span = span!(Level::DEBUG, "set_acl");

        async move {
            debug!("Setting ACL for ({}) DID in mediator", did_hash);

            let mut con = self.0.get_async_connection().await?;

            deadpool_redis::redis::Cmd::hset(
                format!("DID:{}", did_hash),
                "ACLS",
                acls.to_hex_string(),
            )
            .exec_async(&mut con)
            .await
            .map_err(|err| {
                MediatorError::DatabaseError(
                    14,
                    "NA".to_string(),
                    format!("set_acl failed. Reason: {}", err),
                )
            })?;

            Ok(acls.to_owned())
        }
        .instrument(_span)
        .await
    }

    /// Get ACL for a given DID
    /// Returns the ACL for the given DID, or None if DID isn't found
    pub(crate) async fn get_did_acl(
        &self,
        did_hash: &str,
    ) -> Result<Option<MediatorACLSet>, MediatorError> {
        let _span = span!(Level::DEBUG, "get_did_acl");

        async move {
            debug!("Requesting ACL for ({}) DID from mediator", did_hash);

            let mut con = self.0.get_async_connection().await?;

            let acl: Option<String> =
                deadpool_redis::redis::Cmd::hget(format!("DID:{}", did_hash), "ACLS")
                    .query_async(&mut con)
                    .await
                    .map_err(|err| {
                        MediatorError::DatabaseError(
                            14,
                            "NA".to_string(),
                            format!("get_did_acls failed. Reason: {}", err),
                        )
                    })?;

            if let Some(acl) = acl {
                Ok(Some(MediatorACLSet::from_hex_string(&acl).map_err(
                    |e| MediatorError::InternalError(26, did_hash.into(), e.to_string()),
                )?))
            } else {
                Ok(None)
            }
        }
        .instrument(_span)
        .await
    }

    /// Retrieves a list of ACLs for given DIDS
    /// - `dids` - List of DIDs (hashes) to retrieve ACLs for (limit 100)
    /// - Returns a list of ACLs for the given DIDs
    pub(crate) async fn get_did_acls(
        &self,
        dids: &[String],
        mediator_acl_mode: AccessListModeType,
    ) -> Result<MediatorACLGetResponse, MediatorError> {
        let _span = span!(Level::DEBUG, "get_did_acls");

        async move {
            debug!("Requesting ACLs for ({}) DIDs from mediator", dids.len());
            if dids.len() > 100 {
                return Err(MediatorError::DatabaseError(
                    27,
                    "NA".to_string(),
                    "# of DIDs cannot exceed 100".to_string(),
                ));
            }

            let mut con = self.0.get_async_connection().await?;

            let mut query = Pipeline::new();
            query.atomic();

            for did in dids {
                query.add_command(Cmd::hget(format!("DID:{}", did), "ACLS"));
            }

            let result: Vec<Value> = query.query_async(&mut con).await.map_err(|err| {
                MediatorError::DatabaseError(
                    14,
                    "NA".to_string(),
                    format!("get_did_acls failed. Reason: {}", err),
                )
            })?;

            let mut acl_response: MediatorACLGetResponse = MediatorACLGetResponse {
                acl_response: vec![],
                mediator_acl_mode,
            };
            for (index, item) in result.iter().enumerate() {
                if let Ok(acls_hex) = from_redis_value::<String>(item) {
                    let acls = MediatorACLSet::from_hex_string(&acls_hex).map_err(|e| {
                        MediatorError::InternalError(26, dids[index].clone(), e.to_string())
                    })?;
                    acl_response.acl_response.push(MediatorACLExpanded {
                        did_hash: dids[index].clone(),
                        acl_value: acls.to_hex_string(),
                        acls,
                    });
                }
            }
            Ok(acl_response)
        }
        .instrument(_span)
        .await
    }

    /// Checks if the `check_hash` is allowed in the access list for the given `key_hash`
    /// - `to_hash` - Hash of the DID we are checking against (typically the TO address)
    /// - `from_hash` - Hash of the DID we are checking for (typically the FROM address)
    ///
    /// Returns true if it exists, false otherwise
    pub async fn access_list_allowed(&self, to_hash: &str, from_hash: Option<&str>) -> bool {
        let Ok(mut con) = self.0.get_async_connection().await else {
            warn!("Failed to get database connection");
            return false;
        };

        if let Some(from_hash) = from_hash {
            let (exists, acl): (bool, Option<String>) = match deadpool_redis::redis::pipe()
                .atomic()
                .cmd("SISMEMBER")
                .arg(["ACCESS_LIST:", to_hash].concat())
                .arg(from_hash)
                .cmd("HGET")
                .arg(["DID:", to_hash].concat())
                .arg("ACLS")
                .query_async(&mut con)
                .await
                .map_err(|err| {
                    MediatorError::DatabaseError(
                        14,
                        "NA".to_string(),
                        format!("access_list_allowed failed. Reason: {}", err),
                    )
                }) {
                Ok(result) => result,
                Err(err) => {
                    warn!("access_list_allowed failed. Reason: {}", err);
                    return false;
                }
            };

            let acl = if let Some(acl) = acl {
                if let Ok(acls) = MediatorACLSet::from_hex_string(&acl) {
                    acls
                } else {
                    warn!("Failed to parse ACL for to_hash({})", to_hash);
                    return false;
                }
            } else {
                debug!("ACL not found for DID: {}", to_hash);
                return false;
            };

            if acl.get_access_list_mode().0 == AccessListModeType::ExplicitAllow {
                debug!(
                    "access_list_allowed == true for to_hash({}), from_hash({})",
                    to_hash, from_hash
                );
                exists
            } else {
                debug!(
                    "access_list_allowed == false for to_hash({}), from_hash({})",
                    to_hash, from_hash
                );
                !exists
            }
        } else {
            // Anonymous Message
            match self.get_did_acl(to_hash).await {
                Ok(Some(acl)) => acl.get_anon_receive().0,
                _ => false,
            }
        }
    }

    /// Retrieves DID hashes from the Access List
    /// - `did_hash` - DID Hash to retrieve the Access List for
    /// - `cursor` - Cursor for pagination ("0" for beginning )
    ///
    /// - Returns a list of ACLs for the given DID
    pub(crate) async fn access_list_list(
        &self,
        did_hash: &str,
        cursor: u64,
    ) -> Result<MediatorAccessListListResponse, MediatorError> {
        let _span = span!(
            Level::DEBUG,
            "access_list_list",
            did_hash = did_hash,
            cursor = cursor
        );

        async move {
            debug!("Requesting Access List");

            let mut con = self.0.get_async_connection().await?;
            let (new_cursor, hashes): (u64, Vec<String>) = deadpool_redis::redis::cmd("SSCAN")
                .arg(["ACCESS_LIST:", did_hash].concat())
                .arg(cursor)
                .arg("COUNT")
                .arg(100)
                .query_async(&mut con)
                .await
                .map_err(|err| {
                    MediatorError::DatabaseError(
                        14,
                        "NA".to_string(),
                        format!("access_list_list failed. Reason: {}", err),
                    )
                })?;

            Ok(MediatorAccessListListResponse {
                cursor: Some(new_cursor),
                did_hashes: hashes,
            })
        }
        .instrument(_span)
        .await
    }

    /// Retrieves count of Access List members for given DID
    /// - `did_hash` - DID Hash to retrieve the Access List for
    ///
    /// - Returns number of members in the Access List
    pub(crate) async fn access_list_count(&self, did_hash: &str) -> Result<usize, MediatorError> {
        let _span = span!(Level::DEBUG, "access_list_count", did_hash = did_hash,);

        async move {
            debug!("Requesting Access List Count");

            let mut con = self.0.get_async_connection().await?;
            deadpool_redis::redis::cmd("SCARD")
                .arg(["ACCESS_LIST:", did_hash].concat())
                .query_async(&mut con)
                .await
                .map_err(|err| {
                    MediatorError::DatabaseError(
                        14,
                        "NA".to_string(),
                        format!("access_list_count failed. Reason: {}", err),
                    )
                })
        }
        .instrument(_span)
        .await
    }

    /// Adds a number of DID hashes to the Access List
    /// - `did_hash` - DID Hash to add to
    /// - `hashes` - Hashes to add
    ///
    /// - Whether the list was truncated and a list of hashes added
    pub(crate) async fn access_list_add(
        &self,
        access_list_limit: usize,
        did_hash: &str,
        hashes: &Vec<String>,
    ) -> Result<MediatorAccessListAddResponse, MediatorError> {
        let _span = span!(
            Level::DEBUG,
            "access_list_add",
            did_hash = did_hash,
            add_count = hashes.len()
        );

        async move {
            debug!("Adding to Access List");

            let count = self.access_list_count(did_hash).await?;
            let mut truncated = false;

            let hashes = if hashes.len() + count > access_list_limit {
                truncated = true;
                &hashes[0..(hashes.len() - (access_list_limit - count))]
            } else {
                hashes
            };

            let mut con = self.0.get_async_connection().await?;
            let mut query = deadpool_redis::redis::cmd("SADD");
            let mut query = query.arg(["ACCESS_LIST:", did_hash].concat());

            for hash in hashes {
                query = query.arg(hash);
            }

            query.exec_async(&mut con).await.map_err(|err| {
                MediatorError::DatabaseError(
                    14,
                    "NA".to_string(),
                    format!("access_list_add failed. Reason: {}", err),
                )
            })?;

            Ok(MediatorAccessListAddResponse {
                did_hashes: hashes.to_vec(),
                truncated,
            })
        }
        .instrument(_span)
        .await
    }

    /// Removes a number of DID hashes from the Access List
    /// - `did_hash` - DID Hash to remove from
    /// - `hashes` - Hashes to be removed
    ///
    /// - Returns count of hashes removed
    pub(crate) async fn access_list_remove(
        &self,
        did_hash: &str,
        hashes: &Vec<String>,
    ) -> Result<usize, MediatorError> {
        let _span = span!(
            Level::DEBUG,
            "access_list_remove",
            did_hash = did_hash,
            remove_count = hashes.len()
        );

        async move {
            debug!("Removing from Access List");

            let mut con = self.0.get_async_connection().await?;
            let mut query = deadpool_redis::redis::cmd("SREM");
            let mut query = query.arg(["ACCESS_LIST:", did_hash].concat());

            for hash in hashes {
                query = query.arg(hash);
            }

            query.query_async(&mut con).await.map_err(|err| {
                MediatorError::DatabaseError(
                    14,
                    "NA".to_string(),
                    format!("access_list_remove failed. Reason: {}", err),
                )
            })
        }
        .instrument(_span)
        .await
    }

    /// Clears the Access List for a given DID
    /// - `did_hash` - DID Hash to clear
    ///
    /// - Returns success (nothing) or Error
    pub(crate) async fn access_list_clear(&self, did_hash: &str) -> Result<(), MediatorError> {
        let _span = span!(Level::DEBUG, "access_list_clear", did_hash = did_hash,);

        async move {
            debug!("Clearing Access List");

            let mut con = self.0.get_async_connection().await?;
            deadpool_redis::redis::cmd("DEL")
                .arg(["ACCESS_LIST:", did_hash].concat())
                .exec_async(&mut con)
                .await
                .map_err(|err| {
                    MediatorError::DatabaseError(
                        14,
                        "NA".to_string(),
                        format!("access_list_clear failed. Reason: {}", err),
                    )
                })
        }
        .instrument(_span)
        .await
    }

    /// Check if a number of DID hashes exist in an Access List
    /// - `did_hash` - DID Hash to get from
    /// - `hashes` - Hashes to be checked
    ///
    /// - Returns array of Hashes that exist in the Access List
    pub(crate) async fn access_list_get(
        &self,
        did_hash: &str,
        hashes: &Vec<String>,
    ) -> Result<MediatorAccessListGetResponse, MediatorError> {
        let _span = span!(
            Level::DEBUG,
            "access_list_get",
            did_hash = did_hash,
            get_count = hashes.len()
        );

        async move {
            debug!("Getting from Access List");

            let mut con = self.0.get_async_connection().await?;
            let mut query = deadpool_redis::redis::cmd("SMISMEMBER");
            let mut query = query.arg(["ACCESS_LIST:", did_hash].concat());

            for hash in hashes {
                query = query.arg(hash);
            }

            let results: Vec<u8> = query.query_async(&mut con).await.map_err(|err| {
                MediatorError::DatabaseError(
                    14,
                    "NA".to_string(),
                    format!("access_list_get failed. Reason: {}", err),
                )
            })?;

            Ok(MediatorAccessListGetResponse {
                did_hashes: hashes
                    .iter()
                    .zip(results.iter())
                    .filter_map(|(hash, result)| {
                        if *result == 1 {
                            Some(hash.clone())
                        } else {
                            None
                        }
                    })
                    .collect(),
            })
        }
        .instrument(_span)
        .await
    }
}

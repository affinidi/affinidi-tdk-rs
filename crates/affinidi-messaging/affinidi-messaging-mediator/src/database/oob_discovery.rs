/*!
 Database operations relating to the storage, retrieval and deletion of OOB Discovery records

 Uses a REDIS Hash to store the OOB Discovery Invitation information

 HASH KEY : OOB_INVITES

 OOB_INVITES Field Naming = OOB_ID
   OOB_ID = SHA256 Hash of the Invite Message
*/

use super::Database;
use affinidi_messaging_didcomm::Message;
use affinidi_messaging_mediator_common::errors::MediatorError;
use base64::prelude::*;
use sha256::digest;
use std::time::SystemTime;
use tracing::{Instrument, Level, debug, error, info, span};

// const HASH_KEY: &str = "OOB_INVITES";
const HASH_KEY_PREFIX: &str = "OOB_INVITES";

impl Database {
    /// Stores an OOB Discovery Invitation
    /// `did_hash` - The hash of the DID that is creating the OOB Discovery Invitation
    /// `invite` - The OOB Discovery Invitation Message
    /// `oob_invite_ttl` - The time to live for the OOB Discovery Invitation
    pub async fn oob_discovery_store(
        &self,
        did_hash: &str,
        invite: &Message,
        oob_invite_ttl: u64,
    ) -> Result<String, MediatorError> {
        let _span = span!(Level::DEBUG, "oob_discovery_store", did_hash = did_hash);

        async move {
            let mut conn = self.0.get_async_connection().await?;

            let now = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs();

            // Setup the expiry in the database
            let expire_at = if let Some(expiry) = invite.expires_time {
                if expiry > now + oob_invite_ttl {
                    now + oob_invite_ttl
                } else {
                    expiry
                }
            } else {
                now + oob_invite_ttl
            };

            let base64_invite = match serde_json::to_string(invite) {
                Ok(msg) => {
                    debug!("invite_str:\n{}", msg);
                    BASE64_URL_SAFE_NO_PAD.encode(msg)
                }
                Err(err) => {
                    error!("serializing error on Message. {}", err);
                    return Err(MediatorError::InternalError(
                        19,
                        "NA".into(),
                        format!("serializing error on Message. {}", err),
                    ));
                }
            };

            let invite_hash = digest(&base64_invite);
            let key = Database::to_cache_key(&invite_hash);

            match deadpool_redis::redis::pipe()
                .atomic()
                .cmd("HMSET")
                .arg(&key)
                .arg("INVITE")
                .arg(&base64_invite)
                .arg("DID")
                .arg(did_hash)
                .cmd("EXPIREAT")
                .arg(&key)
                .arg(expire_at)
                .cmd("HINCRBY")
                .arg("GLOBAL")
                .arg("OOB_INVITES_CREATED")
                .arg(1)
                .exec_async(&mut conn)
                .await
            {
                Ok(_) => {
                    info!("OOB Invitation ID({}) created", invite_hash);
                    Ok(invite_hash)
                }
                Err(err) => {
                    error!("Database Error: {}", err);
                    Err(MediatorError::DatabaseError(
                        14,
                        "NA".into(),
                        format!("database store error: {}", err),
                    ))
                }
            }
        }
        .instrument(_span)
        .await
    }

    /// Retrieve an OOB Discovery Invitation if it exists
    pub async fn oob_discovery_get(
        &self,
        oob_id: &str,
    ) -> Result<Option<(String, String)>, MediatorError> {
        let _span = span!(Level::DEBUG, "oob_discovery_get", oob_id = oob_id);

        async move {
            let mut conn = self.0.get_async_connection().await?;

            let key = Database::to_cache_key(oob_id);
            let invitation: Option<(String, String)> = match deadpool_redis::redis::pipe()
                .atomic()
                .cmd("HMGET")
                .arg(key)
                .arg("INVITE")
                .arg("DID")
                .cmd("HINCRBY")
                .arg("GLOBAL")
                .arg("OOB_INVITES_CLAIMED")
                .arg(1)
                .query_async::<(Vec<String>, String)>(&mut conn)
                .await
            {
                Ok((oob, _)) => {
                    if oob.len() != 2 {
                        None
                    } else {
                        Some((oob[0].clone(), oob[1].clone()))
                    }
                }
                Err(err) => {
                    error!("Database Error: {}", err);
                    return Err(MediatorError::DatabaseError(
                        14,
                        "NA".into(),
                        format!("database fetch error: {}", err),
                    ));
                }
            };

            debug!("OOB Discovery Invitation: {:?}", invitation);

            Ok(invitation)
        }
        .instrument(_span)
        .await
    }

    /// Deletes an OOB Discovery Invitation
    pub async fn oob_discovery_delete(&self, oob_id: &str) -> Result<bool, MediatorError> {
        let _span = span!(Level::DEBUG, "oob_discovery_delete", oob_id = oob_id);

        async move {
            let mut conn = self.0.get_async_connection().await?;

            let key = Database::to_cache_key(oob_id);
            let result: bool = match deadpool_redis::redis::cmd("DEL")
                .arg(key)
                .query_async::<bool>(&mut conn)
                .await
            {
                Ok(result) => result,
                Err(err) => {
                    error!("Database Error: {}", err);
                    return Err(MediatorError::DatabaseError(
                        14,
                        "NA".into(),
                        format!("database fetch error: {}", err),
                    ));
                }
            };

            debug!("Delete status: {:?}", result);

            Ok(result)
        }
        .instrument(_span)
        .await
    }

    /// Creates the OOB Invite Hash Key (OOB_INVITES:HASH)
    fn to_cache_key(id: &str) -> String {
        [HASH_KEY_PREFIX, ":", id].concat()
    }
}

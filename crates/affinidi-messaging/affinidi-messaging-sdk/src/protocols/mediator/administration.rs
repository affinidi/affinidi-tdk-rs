//! Handles mediator configuration and administration tasks
//! Admin account management
//! Global ACL management

use crate::{ATM, errors::ATMError, profiles::ATMProfile, transports::SendMessageResponse};
use affinidi_messaging_didcomm::{Message, PackEncryptedOptions};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha256::digest;
use std::{sync::Arc, time::SystemTime};
use tracing::{Instrument, Level, debug, span};
use uuid::Uuid;

use super::accounts::AccountType;

#[derive(Default)]
pub struct Mediator {}

#[derive(Serialize, Deserialize)]
pub enum MediatorAdminRequest {
    #[serde(rename = "admin_add")]
    AdminAdd(Vec<String>),
    #[serde(rename = "admin_strip")]
    AdminStrip(Vec<String>),
    #[serde(rename = "admin_list")]
    AdminList {
        cursor: u32,
        limit: u32,
    },
    Configuration(Value),
}

/// A list of admins in the mediator
/// - `accounts` - The list of admins (SHA256 Hashed DIDs)
/// - `cursor` - The offset to use for the next request
#[derive(Serialize, Deserialize)]
pub struct MediatorAdminList {
    pub accounts: Vec<AdminAccount>,
    pub cursor: u32,
}

#[derive(Serialize, Deserialize)]
pub struct AdminAccount {
    pub did_hash: String,
    #[serde(rename = "type")]
    pub _type: AccountType,
}

impl Mediator {
    pub async fn get_config(
        &self,
        atm: &ATM,
        profile: &Arc<ATMProfile>,
    ) -> Result<Value, ATMError> {
        let _span = span!(Level::DEBUG, "get_config");

        async move {
            let (profile_did, mediator_did) = profile.dids()?;

            let now = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs();

            let msg = Message::build(
                Uuid::new_v4().into(),
                "https://didcomm.org/mediator/1.0/admin-management".to_owned(),
                json!({"Configuration": {}}),
            )
            .to(mediator_did.into())
            .from(profile_did.into())
            .created_time(now)
            .expires_time(now + 10)
            .finalize();

            let msg_id = msg.id.clone();

            // Pack the message
            let (msg, _) = msg
                .pack_encrypted(
                    mediator_did,
                    Some(profile_did),
                    Some(profile_did),
                    &atm.inner.tdk_common.did_resolver,
                    &atm.inner.tdk_common.secrets_resolver,
                    &PackEncryptedOptions::default(),
                )
                .await
                .map_err(|e| ATMError::MsgSendError(format!("Error packing message: {e}")))?;

            match atm.send_message(profile, &msg, &msg_id, true, true).await? {
                SendMessageResponse::Message(message) => Ok(message.body),
                _ => Err(ATMError::MsgReceiveError(
                    "No response from mediator".to_owned(),
                )),
            }
        }
        .instrument(_span)
        .await
    }

    /// Parses the response from the mediator for Adding admins
    fn _parse_add_admins_response(&self, message: &Message) -> Result<i32, ATMError> {
        serde_json::from_value(message.body.clone()).map_err(|err| {
            ATMError::MsgReceiveError(format!(
                "Mediator Admin Add response could not be parsed. Reason: {err}"
            ))
        })
    }

    /// Adds a number of admins to the mediator
    /// - `atm` - The ATM client to use
    /// - `admins` - Array of Strings representing the DIDs of the admins to add (can be SHA256 or raw DID)
    ///   NOTE: `admins` is limited to 100 elements
    /// # Returns
    /// Success: Number of admins added to the mediator
    /// Error: An error message
    pub async fn add_admins(
        &self,
        atm: &ATM,
        profile: &Arc<ATMProfile>,
        admins: &[String],
    ) -> Result<i32, ATMError> {
        let _span = span!(Level::DEBUG, "add_admins");

        async move {
            debug!(
                "Adding admin accounts to mediator: count {:?}",
                admins.len()
            );

            if admins.len() > 100 {
                return Err(ATMError::ConfigError(
                    "You can only add up to 100 admins at a time!".to_owned(),
                ));
            }

            let (profile_did, mediator_did) = profile.dids()?;

            let mut digests: Vec<String> = Vec::new();
            let re = Regex::new(r"[0-9a-f]{64}").unwrap();
            for admin in admins {
                if re.is_match(admin) {
                    digests.push(admin.clone());
                } else if admin.starts_with("did:") {
                    digests.push(digest(admin));
                } else {
                    return Err(ATMError::ConfigError(
                        format!("Admins ({admin}) doesn't seem to be a SHA256 hash or a DID!")
                            .to_owned(),
                    ));
                }
            }

            let now = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs();

            let msg = Message::build(
                Uuid::new_v4().into(),
                "https://didcomm.org/mediator/1.0/admin-management".to_owned(),
                json!({"admin_add": digests}),
            )
            .to(mediator_did.into())
            .from(profile_did.into())
            .created_time(now)
            .expires_time(now + 10)
            .finalize();

            let msg_id = msg.id.clone();

            // Pack the message
            let (msg, _) = msg
                .pack_encrypted(
                    mediator_did,
                    Some(profile_did),
                    Some(profile_did),
                    &atm.inner.tdk_common.did_resolver,
                    &atm.inner.tdk_common.secrets_resolver,
                    &PackEncryptedOptions::default(),
                )
                .await
                .map_err(|e| ATMError::MsgSendError(format!("Error packing message: {e}")))?;

            match atm.send_message(profile, &msg, &msg_id, true, true).await? {
                SendMessageResponse::Message(message) => self._parse_add_admins_response(&message),
                _ => Err(ATMError::MsgReceiveError(
                    "No response from mediator".to_owned(),
                )),
            }
        }
        .instrument(_span)
        .await
    }

    /// Parses the response from the mediator for Stripping admins
    fn _parse_strip_admins_response(&self, message: &Message) -> Result<i32, ATMError> {
        serde_json::from_value(message.body.clone()).map_err(|err| {
            ATMError::MsgReceiveError(format!(
                "Mediator Admin Strip response could not be parsed. Reason: {err}"
            ))
        })
    }

    /// Strips admin rights from a number of accounts from the mediator
    /// - `atm` - The ATM client to use
    /// - `admins` - Array of Strings representing the SHA256 Hashed DIDs of the admins to strip
    ///   NOTE: `admins` is limited to 100 elements
    /// # Returns
    /// Success: Number of admins stripped from the mediator
    /// Error: An error message
    pub async fn strip_admins(
        &self,
        atm: &ATM,
        profile: &Arc<ATMProfile>,
        admins: &[String],
    ) -> Result<i32, ATMError> {
        let _span = span!(Level::DEBUG, "strip_admins");

        async move {
            debug!(
                "Stripping admin accounts from mediator: count {:?}",
                admins.len()
            );

            if admins.len() > 100 {
                return Err(ATMError::ConfigError(
                    "You can only strip up to 100 admins at a time!".to_owned(),
                ));
            }

            let (profile_did, mediator_did) = profile.dids()?;

            // Check that these are digests
            let re = Regex::new(r"[0-9a-f]{64}").unwrap();
            for admin in admins {
                if !re.is_match(admin) {
                    return Err(ATMError::ConfigError(
                        "Admins must be SHA256 Hashed DIDs!".to_owned(),
                    ));
                }
            }

            let now = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs();

            let msg = Message::build(
                Uuid::new_v4().into(),
                "https://didcomm.org/mediator/1.0/admin-management".to_owned(),
                json!({"admin_strip": admins}),
            )
            .to(mediator_did.into())
            .from(profile_did.into())
            .created_time(now)
            .expires_time(now + 10)
            .finalize();

            let msg_id = msg.id.clone();

            // Pack the message
            let (msg, _) = msg
                .pack_encrypted(
                    mediator_did,
                    Some(profile_did),
                    Some(profile_did),
                    &atm.inner.tdk_common.did_resolver,
                    &atm.inner.tdk_common.secrets_resolver,
                    &PackEncryptedOptions::default(),
                )
                .await
                .map_err(|e| ATMError::MsgSendError(format!("Error packing message: {e}")))?;

            match atm.send_message(profile, &msg, &msg_id, true, true).await? {
                SendMessageResponse::Message(message) => {
                    self._parse_strip_admins_response(&message)
                }
                _ => Err(ATMError::MsgReceiveError(
                    "No response from mediator".to_owned(),
                )),
            }
        }
        .instrument(_span)
        .await
    }

    /// Parses the response from the mediator for a list of admins
    fn _parse_list_admins_response(
        &self,
        message: &Message,
    ) -> Result<MediatorAdminList, ATMError> {
        serde_json::from_value(message.body.clone()).map_err(|err| {
            ATMError::MsgReceiveError(format!(
                "Mediator Admin List response could not be parsed. Reason: {err}"
            ))
        })
    }

    /// Lists all the admins in the mediator
    /// - `atm` - The ATM client to use
    /// - `cursor` - The cursor to start from (Defaults to 0 if not provided)
    /// - `limit` - The maximum number of admins to return (Defaults to 100 if not provided)
    /// # Returns
    /// A list of admins in the mediator
    pub async fn list_admins(
        &self,
        atm: &ATM,
        profile: &Arc<ATMProfile>,
        cursor: Option<u32>,
        limit: Option<u32>,
    ) -> Result<MediatorAdminList, ATMError> {
        let _span = span!(Level::DEBUG, "list_admins");

        async move {
            debug!(
                "Requesting list of Admin accounts from mediator. Cursor: {} Limit: {}",
                cursor.unwrap_or(0),
                limit.unwrap_or(100)
            );

            let (profile_did, mediator_did) = profile.dids()?;

            let now = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs();

            let msg = Message::build(
                Uuid::new_v4().into(),
                "https://didcomm.org/mediator/1.0/admin-management".to_owned(),
                json!({"admin_list": {"cursor": cursor.unwrap_or(0), "limit": limit.unwrap_or(100)}}),
            )
            .to(mediator_did.into())
            .from(profile_did.into())
            .created_time(now)
            .expires_time(now + 10)
            .finalize();

            let msg_id = msg.id.clone();

            // Pack the message
            let (msg, _) = msg
                .pack_encrypted(
                    mediator_did,
                    Some(profile_did),
                    Some(profile_did),
                    &atm.inner.tdk_common.did_resolver,
                    &atm.inner.tdk_common.secrets_resolver,
                    &PackEncryptedOptions::default(),
                )
                .await
                .map_err(|e| ATMError::MsgSendError(format!("Error packing message: {e}")))?;

                match atm
                .send_message(profile, &msg, &msg_id, true, true)
                .await? { SendMessageResponse::Message(message) => {
                self._parse_list_admins_response(&message)
                } _ => {
                    Err(ATMError::MsgReceiveError(
                        "No response from mediator".to_owned(),
                    ))
                }}
        }
        .instrument(_span)
        .await
    }
}

/// Wrapper struct that holds a reference to ATM, enabling the `atm.mediator().method()` pattern
pub struct MediatorOps<'a> {
    pub(crate) atm: &'a ATM,
}

impl<'a> MediatorOps<'a> {
    /// Get mediator configuration
    /// See [`Mediator::get_config`] for full documentation
    pub async fn get_config(
        &self,
        profile: &Arc<ATMProfile>,
    ) -> Result<Value, ATMError> {
        Mediator::default()
            .get_config(self.atm, profile)
            .await
    }

    /// Adds a number of admins to the mediator
    /// See [`Mediator::add_admins`] for full documentation
    pub async fn add_admins(
        &self,
        profile: &Arc<ATMProfile>,
        admins: &[String],
    ) -> Result<i32, ATMError> {
        Mediator::default()
            .add_admins(self.atm, profile, admins)
            .await
    }

    /// Strips admin rights from a number of accounts from the mediator
    /// See [`Mediator::strip_admins`] for full documentation
    pub async fn strip_admins(
        &self,
        profile: &Arc<ATMProfile>,
        admins: &[String],
    ) -> Result<i32, ATMError> {
        Mediator::default()
            .strip_admins(self.atm, profile, admins)
            .await
    }

    /// Lists all the admins in the mediator
    /// See [`Mediator::list_admins`] for full documentation
    pub async fn list_admins(
        &self,
        profile: &Arc<ATMProfile>,
        cursor: Option<u32>,
        limit: Option<u32>,
    ) -> Result<MediatorAdminList, ATMError> {
        Mediator::default()
            .list_admins(self.atm, profile, cursor, limit)
            .await
    }
}

use affinidi_messaging_didcomm::message::Message;
use serde_json::json;
use sha256::digest;
use tracing::{Instrument, Level, debug, span};
use uuid::Uuid;

use super::{
    acls::MediatorACLSet,
    administration::{Mediator, MediatorOps},
};
use crate::{ATM, errors::ATMError, profiles::ATMProfile, transports::SendMessageResponse};
use std::{sync::Arc, time::SystemTime};

// Account-management vocabulary types live in
// `affinidi-messaging-mediator-common::types::accounts` so the
// mediator's storage trait can describe its API without depending
// on the SDK. Re-exported here so existing call sites resolve.
pub use affinidi_messaging_mediator_common::types::accounts::{
    Account, AccountChangeQueueLimitsResponse, AccountType, MediatorAccountList,
    MediatorAccountRequest,
};

impl Mediator {
    /// Fetch an account information from the mediator
    /// - `atm` - The ATM client to use
    /// - `profile` - The profile to use
    /// - `did_hash` - The DID hash to fetch (Defaults to the profile DID hash if not provided)
    pub async fn account_get(
        &self,
        atm: &ATM,
        profile: &Arc<ATMProfile>,
        did_hash: Option<String>,
    ) -> Result<Option<Account>, ATMError> {
        let _span = span!(Level::DEBUG, "account_get");

        async move {
            let did_hash = did_hash.unwrap_or_else(|| digest(&profile.inner.did));
            debug!("Requesting account ({}) from mediator.", did_hash);

            let (profile_did, mediator_did) = profile.dids()?;

            let now = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs();

            let msg = Message::build(
                Uuid::new_v4().to_string(),
                "https://didcomm.org/mediator/1.0/account-management".to_owned(),
                json!({"account_get":  did_hash}),
            )
            .to(mediator_did.into())
            .from(profile_did.into())
            .created_time(now)
            .expires_time(now + 10)
            .finalize();

            let msg_id = msg.id.clone();

            // Pack the message
            let (msg, _) = atm
                .inner
                .pack_encrypted(&msg, mediator_did, Some(profile_did))
                .await
                .map_err(|e| ATMError::MsgSendError(format!("Error packing message: {e}")))?;

            // send the message
            match atm.send_message(profile, &msg, &msg_id, true, true).await? {
                SendMessageResponse::Message(message) => self._parse_account_get_response(&message),
                _ => Err(ATMError::MsgReceiveError(
                    "No response from mediator".to_owned(),
                )),
            }
        }
        .instrument(_span)
        .await
    }

    /// Parses the response from the mediator for account_get
    fn _parse_account_get_response(&self, message: &Message) -> Result<Option<Account>, ATMError> {
        serde_json::from_value(message.body.clone()).map_err(|err| {
            ATMError::MsgReceiveError(format!(
                "Mediator Account Get response could not be parsed. Reason: {err}"
            ))
        })
    }

    /// Create a new account on the Mediator for a given DID
    /// - `atm` - The ATM client to use
    /// - `profile` - The profile to use
    /// - `did_hash` - The DID hash to create
    /// - `acls` - The ACLs to set for the account (Defaults to None if not provided)
    ///   - NOTE: If not an admin account, the mediator will default this to the default ACL
    ///
    /// NOTE: If the mediator is running in explicit_allow mode, then only admin level accounts can add new accounts
    /// # Returns
    /// The account created on the mediator, or the existing account if it already exists
    pub async fn account_add(
        &self,
        atm: &ATM,
        profile: &Arc<ATMProfile>,
        did_hash: &str,
        acls: Option<MediatorACLSet>,
    ) -> Result<Account, ATMError> {
        let _span = span!(Level::DEBUG, "account_add");

        async move {
            debug!("Adding account ({}) to mediator.", did_hash);

            let (profile_did, mediator_did) = profile.dids()?;

            let now = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs();

            let msg = Message::build(
                Uuid::new_v4().to_string(),
                "https://didcomm.org/mediator/1.0/account-management".to_owned(),
                json!({"account_add": {"did_hash": did_hash, "acls": acls.map(|a| a.to_u64())}}),
            )
            .to(mediator_did.into())
            .from(profile_did.into())
            .created_time(now)
            .expires_time(now + 10)
            .finalize();

            let msg_id = msg.id.clone();

            // Pack the message
            let (msg, _) = atm
                .inner
                .pack_encrypted(&msg, mediator_did, Some(profile_did))
                .await
                .map_err(|e| ATMError::MsgSendError(format!("Error packing message: {e}")))?;

            match atm.send_message(profile, &msg, &msg_id, true, true).await? {
                SendMessageResponse::Message(message) => self._parse_account_add_response(&message),
                _ => Err(ATMError::MsgReceiveError(
                    "No response from mediator".to_owned(),
                )),
            }
        }
        .instrument(_span)
        .await
    }

    /// Parses the response from the mediator for account_add
    fn _parse_account_add_response(&self, message: &Message) -> Result<Account, ATMError> {
        serde_json::from_value(message.body.clone()).map_err(|err| {
            ATMError::MsgReceiveError(format!(
                "Mediator Account Add response could not be parsed. Reason: {err}"
            ))
        })
    }

    /// Removes an account from the mediator
    /// - `atm` - The ATM client to use
    /// - `profile` - The profile to use
    /// - `did_hash` - The DID hash to remove (Defaults to the profile DID hash if not provided)
    pub async fn account_remove(
        &self,
        atm: &ATM,
        profile: &Arc<ATMProfile>,
        did_hash: Option<String>,
    ) -> Result<bool, ATMError> {
        let _span = span!(Level::DEBUG, "account_remove");

        async move {
            let did_hash = did_hash.unwrap_or_else(|| digest(&profile.inner.did));
            debug!("Removing account ({}) from mediator.", did_hash);

            let (profile_did, mediator_did) = profile.dids()?;

            let now = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs();

            let msg = Message::build(
                Uuid::new_v4().to_string(),
                "https://didcomm.org/mediator/1.0/account-management".to_owned(),
                json!({"account_remove":  did_hash}),
            )
            .to(mediator_did.into())
            .from(profile_did.into())
            .created_time(now)
            .expires_time(now + 10)
            .finalize();

            let msg_id = msg.id.clone();

            // Pack the message
            let (msg, _) = atm
                .inner
                .pack_encrypted(&msg, mediator_did, Some(profile_did))
                .await
                .map_err(|e| ATMError::MsgSendError(format!("Error packing message: {e}")))?;

            match atm.send_message(profile, &msg, &msg_id, true, true).await? {
                SendMessageResponse::Message(message) => {
                    self._parse_account_remove_response(&message)
                }
                _ => Err(ATMError::MsgReceiveError(
                    "No response from mediator".to_owned(),
                )),
            }
        }
        .instrument(_span)
        .await
    }

    /// Parses the response from the mediator for account_remove
    fn _parse_account_remove_response(&self, message: &Message) -> Result<bool, ATMError> {
        serde_json::from_value(message.body.clone()).map_err(|err| {
            ATMError::MsgReceiveError(format!(
                "Mediator Account Remove response could not be parsed. Reason: {err}"
            ))
        })
    }

    /// Lists known DID accounts in the mediator
    /// - `atm` - The ATM client to use
    /// - `cursor` - The cursor to start from (Defaults to 0 if not provided)
    /// - `limit` - The maximum number of accounts to return (Defaults to 100 if not provided)
    /// # Returns
    /// A list of DID Accounts in the mediator
    /// NOTE: This will also include the admin accounts
    /// NOTE: `limit` may return more than `limit`
    pub async fn accounts_list(
        &self,
        atm: &ATM,
        profile: &Arc<ATMProfile>,
        cursor: Option<u32>,
        limit: Option<u32>,
    ) -> Result<MediatorAccountList, ATMError> {
        let _span = span!(Level::DEBUG, "accounts_list");

        async move {
            debug!(
                "Requesting list of accounts from mediator. Cursor: {} Limit: {}",
                cursor.unwrap_or(0),
                limit.unwrap_or(100)
            );

            let (profile_did, mediator_did) = profile.dids()?;

            let now = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs();

            let msg = Message::build(
                Uuid::new_v4().to_string(),
                "https://didcomm.org/mediator/1.0/account-management".to_owned(),
                json!({"account_list": {"cursor": cursor.unwrap_or(0), "limit": limit.unwrap_or(100)}}),
            )
            .to(mediator_did.into())
            .from(profile_did.into())
            .created_time(now)
            .expires_time(now + 10)
            .finalize();

            let msg_id = msg.id.clone();

            // Pack the message
            let (msg, _) = atm
                .inner
                .pack_encrypted(&msg, mediator_did, Some(profile_did))
                .await
                .map_err(|e| ATMError::MsgSendError(format!("Error packing message: {e}")))?;

                match atm
                .send_message(profile, &msg, &msg_id, true, true)
                .await? { SendMessageResponse::Message(message) => {
                self._parse_accounts_list_response(&message)
                } _ => {
                    Err(ATMError::MsgReceiveError(
                        "No response from mediator".to_owned(),
                    ))
                }}
        }
        .instrument(_span)
        .await
    }

    /// Parses the response from the mediator for a list of accounts
    fn _parse_accounts_list_response(
        &self,
        message: &Message,
    ) -> Result<MediatorAccountList, ATMError> {
        serde_json::from_value(message.body.clone()).map_err(|err| {
            ATMError::MsgReceiveError(format!(
                "Mediator Account List response could not be parsed. Reason: {err}"
            ))
        })
    }

    /// Change the Account Type for a DID
    /// - `atm` - The ATM client to use
    /// - `profile` - The profile to use
    /// - `did_hash` - The DID hash to change the type for
    /// - `new_type` - New `AccountType` to set for the account
    ///   - NOTE: You must be an admin to run this command
    ///
    /// # Returns
    /// true or false if the account was changed
    pub async fn account_change_type(
        &self,
        atm: &ATM,
        profile: &Arc<ATMProfile>,
        did_hash: &str,
        new_type: AccountType,
    ) -> Result<bool, ATMError> {
        let _span = span!(Level::DEBUG, "account_change_type");

        async move {
            debug!("Changing account ({}) to type ({}).", did_hash, new_type);

            let (profile_did, mediator_did) = profile.dids()?;

            let now = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs();

            let msg = Message::build(
                Uuid::new_v4().to_string(),
                "https://didcomm.org/mediator/1.0/account-management".to_owned(),
                json!({"account_change_type": {"did_hash": did_hash, "type": new_type}}),
            )
            .to(mediator_did.into())
            .from(profile_did.into())
            .created_time(now)
            .expires_time(now + 10)
            .finalize();

            let msg_id = msg.id.clone();

            // Pack the message
            let (msg, _) = atm
                .inner
                .pack_encrypted(&msg, mediator_did, Some(profile_did))
                .await
                .map_err(|e| ATMError::MsgSendError(format!("Error packing message: {e}")))?;

            match atm.send_message(profile, &msg, &msg_id, true, true).await? {
                SendMessageResponse::Message(message) => {
                    self._parse_account_change_type_response(&message)
                }
                _ => Err(ATMError::MsgReceiveError(
                    "No response from mediator".to_owned(),
                )),
            }
        }
        .instrument(_span)
        .await
    }

    /// Parses the response from the mediator for account_change_type
    fn _parse_account_change_type_response(&self, message: &Message) -> Result<bool, ATMError> {
        serde_json::from_value(message.body.clone()).map_err(|err| {
            ATMError::MsgReceiveError(format!(
                "Mediator Account Change Type response could not be parsed. Reason: {err}"
            ))
        })
    }

    /// Change the Queue Limits for a DID
    /// - `atm` - The ATM client to use
    /// - `profile` - The profile to use
    /// - `did_hash` - The DID hash to change the type for
    /// - `send_queue_limit`
    /// - `receive_queue_limit`
    ///
    /// NOTE: queue_limit values
    ///       - None: No change
    ///       - Some(-1): Unlimited
    ///       - Some(-2): Reset to soft_limit
    ///       - Some(n): Set to n
    ///
    /// # Returns
    /// true or false if the account was changed
    pub async fn account_change_queue_limits(
        &self,
        atm: &ATM,
        profile: &Arc<ATMProfile>,
        did_hash: &str,
        send_queue_limit: Option<i32>,
        receive_queue_limit: Option<i32>,
    ) -> Result<AccountChangeQueueLimitsResponse, ATMError> {
        let _span = span!(Level::DEBUG, "account_change_queue_limit");

        async move {
            debug!(
                "Changing account ({}) queue_limits to send({:?}) receive({:?}).",
                did_hash, send_queue_limit, receive_queue_limit
            );

            let (profile_did, mediator_did) = profile.dids()?;

            let now = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs();

            let msg = Message::build(
                Uuid::new_v4().to_string(),
                "https://didcomm.org/mediator/1.0/account-management".to_owned(),
                json!({"account_change_queue_limits": {"did_hash": did_hash, "send_queue_limit": send_queue_limit, "receive_queue_limit": receive_queue_limit}}),
            )
            .to(mediator_did.into())
            .from(profile_did.into())
            .created_time(now)
            .expires_time(now + 10)
            .finalize();

            let msg_id = msg.id.clone();

            // Pack the message
            let (msg, _) = atm
                .inner
                .pack_encrypted(&msg, mediator_did, Some(profile_did))
                .await
                .map_err(|e| ATMError::MsgSendError(format!("Error packing message: {e}")))?;

            match atm.send_message(profile, &msg, &msg_id, true, true).await? {
                SendMessageResponse::Message(message) => {
                    self._parse_account_change_queue_limit_response(&message)
                }
                _ => Err(ATMError::MsgReceiveError(
                    "No response from mediator".to_owned(),
                )),
            }
        }
        .instrument(_span)
        .await
    }

    /// Parses the response from the mediator for account_change_queue_limit
    fn _parse_account_change_queue_limit_response(
        &self,
        message: &Message,
    ) -> Result<AccountChangeQueueLimitsResponse, ATMError> {
        serde_json::from_value(message.body.clone()).map_err(|err| {
            ATMError::MsgReceiveError(format!(
                "Mediator Account Change Queue Limit response could not be parsed. Reason: {err}"
            ))
        })
    }
}

impl<'a> MediatorOps<'a> {
    /// Fetch an account information from the mediator
    /// See [`Mediator::account_get`] for full documentation
    pub async fn account_get(
        &self,
        profile: &Arc<ATMProfile>,
        did_hash: Option<String>,
    ) -> Result<Option<Account>, ATMError> {
        Mediator::default()
            .account_get(self.atm, profile, did_hash)
            .await
    }

    /// Create a new account on the Mediator for a given DID
    /// See [`Mediator::account_add`] for full documentation
    pub async fn account_add(
        &self,
        profile: &Arc<ATMProfile>,
        did_hash: &str,
        acls: Option<MediatorACLSet>,
    ) -> Result<Account, ATMError> {
        Mediator::default()
            .account_add(self.atm, profile, did_hash, acls)
            .await
    }

    /// Removes an account from the mediator
    /// See [`Mediator::account_remove`] for full documentation
    pub async fn account_remove(
        &self,
        profile: &Arc<ATMProfile>,
        did_hash: Option<String>,
    ) -> Result<bool, ATMError> {
        Mediator::default()
            .account_remove(self.atm, profile, did_hash)
            .await
    }

    /// Lists known DID accounts in the mediator
    /// See [`Mediator::accounts_list`] for full documentation
    pub async fn accounts_list(
        &self,
        profile: &Arc<ATMProfile>,
        cursor: Option<u32>,
        limit: Option<u32>,
    ) -> Result<MediatorAccountList, ATMError> {
        Mediator::default()
            .accounts_list(self.atm, profile, cursor, limit)
            .await
    }

    /// Change the Account Type for a DID
    /// See [`Mediator::account_change_type`] for full documentation
    pub async fn account_change_type(
        &self,
        profile: &Arc<ATMProfile>,
        did_hash: &str,
        new_type: AccountType,
    ) -> Result<bool, ATMError> {
        Mediator::default()
            .account_change_type(self.atm, profile, did_hash, new_type)
            .await
    }

    /// Change the Queue Limits for a DID
    /// See [`Mediator::account_change_queue_limits`] for full documentation
    pub async fn account_change_queue_limits(
        &self,
        profile: &Arc<ATMProfile>,
        did_hash: &str,
        send_queue_limit: Option<i32>,
        receive_queue_limit: Option<i32>,
    ) -> Result<AccountChangeQueueLimitsResponse, ATMError> {
        Mediator::default()
            .account_change_queue_limits(
                self.atm,
                profile,
                did_hash,
                send_queue_limit,
                receive_queue_limit,
            )
            .await
    }
}

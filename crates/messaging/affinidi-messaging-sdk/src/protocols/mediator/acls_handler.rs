/*!
 * DIDComm handling for ACLs
 */

use super::{
    acls::MediatorACLSet,
    administration::{Mediator, MediatorOps},
};
use crate::{ATM, errors::ATMError, profiles::ATMProfile, transports::SendMessageResponse};
use affinidi_messaging_didcomm::message::Message;
use serde_json::json;
use sha256::digest;
use std::{sync::Arc, time::SystemTime};
use tracing::{Instrument, Level, debug, span};
use uuid::Uuid;

// Wire-shape vocabulary lives in
// `affinidi-messaging-mediator-common::types::acls_handler`. This SDK
// module owns only the client-side handler methods on `MediatorOps`,
// keeping the request/response types resolvable at their original
// `affinidi_messaging_sdk::*` paths via these re-exports.
pub use affinidi_messaging_mediator_common::types::acls_handler::{
    MediatorACLExpanded, MediatorACLGetResponse, MediatorACLRequest, MediatorACLSetResponse,
    MediatorAccessListAddResponse, MediatorAccessListGetResponse, MediatorAccessListListResponse,
};

impl Mediator {
    /// Parses the response from the mediator for ACL Get
    fn _parse_acls_get_response(
        &self,
        message: &Message,
    ) -> Result<MediatorACLGetResponse, ATMError> {
        serde_json::from_value(message.body.clone()).map_err(|err| {
            ATMError::MsgReceiveError(format!(
                "Mediator ACL get response could not be parsed. Reason: {err}"
            ))
        })
    }

    /// Get the ACL's set for a list of DIDs
    pub async fn acls_get(
        &self,
        atm: &ATM,
        profile: &Arc<ATMProfile>,
        dids: &Vec<String>,
    ) -> Result<MediatorACLGetResponse, ATMError> {
        let _span = span!(Level::DEBUG, "acls_get");

        async move {
            debug!("Requesting ACLs for DIDs: {:?}", dids);

            let (profile_did, mediator_did) = profile.dids()?;

            let now = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs();

            let msg = Message::build(
                Uuid::new_v4().to_string(),
                "https://didcomm.org/mediator/1.0/acl-management".to_owned(),
                json!({"acl_get": dids}),
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
                SendMessageResponse::Message(message) => self._parse_acls_get_response(&message),
                _ => Err(ATMError::MsgReceiveError(
                    "No response from mediator".to_owned(),
                )),
            }
        }
        .instrument(_span)
        .await
    }

    /// Set the ACL's for a DID
    /// This is a convenience method for setting the ACLs for a single DID
    /// `did_hash` is the hash of the DID you are changing
    /// `acls` is the ACLs you are setting
    pub async fn acls_set(
        &self,
        atm: &ATM,
        profile: &Arc<ATMProfile>,
        did_hash: &str,
        acls: &MediatorACLSet,
    ) -> Result<MediatorACLSetResponse, ATMError> {
        let _span = span!(Level::DEBUG, "acls_get");

        async move {
            debug!("Setting ACL ({}) for DID: ({})", acls.to_u64(), did_hash);

            let (profile_did, mediator_did) = profile.dids()?;

            let now = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs();

            let msg = Message::build(
                Uuid::new_v4().to_string(),
                "https://didcomm.org/mediator/1.0/acl-management".to_owned(),
                json!({"acl_set": {"did_hash": did_hash, "acls": acls.to_u64()}}),
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
                SendMessageResponse::Message(message) => self._parse_acls_set_response(&message),
                _ => Err(ATMError::MsgReceiveError(
                    "No response from mediator".to_owned(),
                )),
            }
        }
        .instrument(_span)
        .await
    }

    // Parses the response from the mediator for ACL Set
    fn _parse_acls_set_response(
        &self,
        message: &Message,
    ) -> Result<MediatorACLSetResponse, ATMError> {
        serde_json::from_value(message.body.clone()).map_err(|err| {
            ATMError::MsgReceiveError(format!(
                "Mediator ACL set response could not be parsed. Reason: {err}"
            ))
        })
    }

    /// Access List List: Lists hash of DID's in the Access Control List for a given DID
    /// `atm`: ATM instance
    /// `profile`: Profile instance
    /// `did_hash`: DID Hash (If None, use profile DID)
    /// `cursor`: Cursor for pagination (None means start at the beginning)
    pub async fn access_list_list(
        &self,
        atm: &ATM,
        profile: &Arc<ATMProfile>,
        did_hash: Option<&str>,
        cursor: Option<u64>,
    ) -> Result<MediatorAccessListListResponse, ATMError> {
        let did_hash = if let Some(did_hash) = did_hash {
            did_hash.to_owned()
        } else {
            digest(&profile.inner.did)
        };

        let _span = span!(
            Level::DEBUG,
            "access_list_list",
            did_hash = did_hash,
            cursor = cursor
        );

        async move {
            debug!("Start");

            let (profile_did, mediator_did) = profile.dids()?;

            let now = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs();

            let msg = Message::build(
                Uuid::new_v4().to_string(),
                "https://didcomm.org/mediator/1.0/acl-management".to_owned(),
                json!({"access_list_list": {"did_hash": did_hash, "cursor": cursor}}),
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
                    self._parse_access_list_list_response(&message)
                }
                _ => Err(ATMError::MsgReceiveError(
                    "No response from mediator".to_owned(),
                )),
            }
        }
        .instrument(_span)
        .await
    }

    // Parses the response from the mediator for Access List List
    fn _parse_access_list_list_response(
        &self,
        message: &Message,
    ) -> Result<MediatorAccessListListResponse, ATMError> {
        serde_json::from_value(message.body.clone()).map_err(|err| {
            ATMError::MsgReceiveError(format!(
                "Mediator Access List List could not be parsed. Reason: {err}"
            ))
        })
    }

    /// Access List Add: Adds one or more DIDs to a Access Control List for a given DID
    /// `atm`: ATM instance
    /// `profile`: Profile instance
    /// `did_hash`: DID Hash (If None, use profile DID)
    /// `hashes`: SHA256 hashes of DIDs to add
    pub async fn access_list_add(
        &self,
        atm: &ATM,
        profile: &Arc<ATMProfile>,
        did_hash: Option<&str>,
        hashes: &[&str],
    ) -> Result<MediatorAccessListAddResponse, ATMError> {
        let did_hash = if let Some(did_hash) = did_hash {
            did_hash.to_owned()
        } else {
            digest(&profile.inner.did)
        };

        let _span = span!(
            Level::DEBUG,
            "access_list_add",
            did_hash = did_hash,
            count = hashes.len()
        );

        async move {
            debug!("Start");

            if hashes.len() > 100 {
                return Err(ATMError::MsgSendError(
                    "Too many (max 100) DIDs to add to the access list".to_owned(),
                ));
            } else if hashes.is_empty() {
                return Err(ATMError::MsgSendError(
                    "No DIDs to add to the access list".to_owned(),
                ));
            }

            let (profile_did, mediator_did) = profile.dids()?;

            let now = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs();

            let msg = Message::build(
                Uuid::new_v4().to_string(),
                "https://didcomm.org/mediator/1.0/acl-management".to_owned(),
                json!({"access_list_add": {"did_hash": did_hash, "hashes": hashes}}),
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
                    self._parse_access_list_add_response(&message)
                }
                _ => Err(ATMError::MsgReceiveError(
                    "No response from mediator".to_owned(),
                )),
            }
        }
        .instrument(_span)
        .await
    }

    // Parses the response from the mediator for Access List Add
    fn _parse_access_list_add_response(
        &self,
        message: &Message,
    ) -> Result<MediatorAccessListAddResponse, ATMError> {
        serde_json::from_value(message.body.clone()).map_err(|err| {
            ATMError::MsgReceiveError(format!(
                "Mediator Access List Add could not be parsed. Reason: {err}"
            ))
        })
    }

    /// Access List Remove: Removes one or more DIDs from a Access Control List for a given DID
    /// `atm`: ATM instance
    /// `profile`: Profile instance
    /// `did_hash`: DID Hash (If None, use profile DID)
    /// `hashes`: SHA256 hashes of DIDs to remove
    ///
    /// Returns: # of Hashes removed
    pub async fn access_list_remove(
        &self,
        atm: &ATM,
        profile: &Arc<ATMProfile>,
        did_hash: Option<&str>,
        hashes: &[&str],
    ) -> Result<usize, ATMError> {
        let did_hash = if let Some(did_hash) = did_hash {
            did_hash.to_owned()
        } else {
            digest(&profile.inner.did)
        };

        let _span = span!(
            Level::DEBUG,
            "access_list_remove",
            did_hash = did_hash,
            count = hashes.len()
        );

        async move {
            debug!("Start");

            if hashes.len() > 100 {
                return Err(ATMError::MsgSendError(
                    "Too many (max 100) DIDs to remove from the access list".to_owned(),
                ));
            } else if hashes.is_empty() {
                return Err(ATMError::MsgSendError(
                    "No DIDs to remove from the access list".to_owned(),
                ));
            }

            let (profile_did, mediator_did) = profile.dids()?;

            let now = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs();

            let msg = Message::build(
                Uuid::new_v4().to_string(),
                "https://didcomm.org/mediator/1.0/acl-management".to_owned(),
                json!({"access_list_remove": {"did_hash": did_hash, "hashes": hashes}}),
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
                    self._parse_access_list_remove_response(&message)
                }
                _ => Err(ATMError::MsgReceiveError(
                    "No response from mediator".to_owned(),
                )),
            }
        }
        .instrument(_span)
        .await
    }

    // Parses the response from the mediator for Access List Remove
    fn _parse_access_list_remove_response(&self, message: &Message) -> Result<usize, ATMError> {
        serde_json::from_value(message.body.clone()).map_err(|err| {
            ATMError::MsgReceiveError(format!(
                "Mediator Access List Remove could not be parsed. Reason: {err}"
            ))
        })
    }

    /// Access List Clear: Clears Access Control List for a given DID
    /// `atm`: ATM instance
    /// `profile`: Profile instance
    /// `did_hash`: DID Hash (If None, use profile DID)
    pub async fn access_list_clear(
        &self,
        atm: &ATM,
        profile: &Arc<ATMProfile>,
        did_hash: Option<&str>,
    ) -> Result<(), ATMError> {
        let did_hash = if let Some(did_hash) = did_hash {
            did_hash.to_owned()
        } else {
            digest(&profile.inner.did)
        };

        let _span = span!(Level::DEBUG, "access_list_clear", did_hash = did_hash,);

        async move {
            debug!("Start");

            let (profile_did, mediator_did) = profile.dids()?;

            let now = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs();

            let msg = Message::build(
                Uuid::new_v4().to_string(),
                "https://didcomm.org/mediator/1.0/acl-management".to_owned(),
                json!({"access_list_clear": {"did_hash": did_hash}}),
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
                    self._parse_access_list_clear_response(&message)
                }
                _ => Err(ATMError::MsgReceiveError(
                    "No response from mediator".to_owned(),
                )),
            }
        }
        .instrument(_span)
        .await
    }

    // Parses the response from the mediator for Access List Clear
    fn _parse_access_list_clear_response(&self, message: &Message) -> Result<(), ATMError> {
        serde_json::from_value(message.body.clone()).map_err(|err| {
            ATMError::MsgReceiveError(format!(
                "Mediator Access List Clear could not be parsed. Reason: {err}"
            ))
        })
    }

    /// Access List Get: Searches for one or more DID's in the Access Control List for a given DID
    /// `atm`: ATM instance
    /// `profile`: Profile instance
    /// `did_hash`: DID Hash (If None, use profile DID)
    /// `hashes`: SHA256 hashes of DIDs to search for
    ///
    /// Returns a list of DID Hashes that matched the search criteria
    pub async fn access_list_get(
        &self,
        atm: &ATM,
        profile: &Arc<ATMProfile>,
        did_hash: Option<&str>,
        hashes: &[&str],
    ) -> Result<MediatorAccessListGetResponse, ATMError> {
        let did_hash = if let Some(did_hash) = did_hash {
            did_hash.to_owned()
        } else {
            digest(&profile.inner.did)
        };

        let _span = span!(
            Level::DEBUG,
            "access_list_get",
            did_hash = did_hash,
            count = hashes.len()
        );

        async move {
            debug!("Start");

            if hashes.len() > 100 {
                return Err(ATMError::MsgSendError(
                    "Too many (max 100) DIDs to get from the access list".to_owned(),
                ));
            } else if hashes.is_empty() {
                return Err(ATMError::MsgSendError(
                    "No DIDs to get from the access list".to_owned(),
                ));
            }

            let (profile_did, mediator_did) = profile.dids()?;

            let now = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs();

            let msg = Message::build(
                Uuid::new_v4().to_string(),
                "https://didcomm.org/mediator/1.0/acl-management".to_owned(),
                json!({"access_list_get": {"did_hash": did_hash, "hashes": hashes}}),
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
                    self._parse_access_list_get_response(&message)
                }
                _ => Err(ATMError::MsgReceiveError(
                    "No response from mediator".to_owned(),
                )),
            }
        }
        .instrument(_span)
        .await
    }

    // Parses the response from the mediator for Access List Get
    fn _parse_access_list_get_response(
        &self,
        message: &Message,
    ) -> Result<MediatorAccessListGetResponse, ATMError> {
        serde_json::from_value(message.body.clone()).map_err(|err| {
            ATMError::MsgReceiveError(format!(
                "Mediator Access List Get could not be parsed. Reason: {err}"
            ))
        })
    }
}

impl<'a> MediatorOps<'a> {
    /// Get the ACL's set for a list of DIDs
    /// See [`Mediator::acls_get`] for full documentation
    pub async fn acls_get(
        &self,
        profile: &Arc<ATMProfile>,
        dids: &Vec<String>,
    ) -> Result<MediatorACLGetResponse, ATMError> {
        Mediator::default().acls_get(self.atm, profile, dids).await
    }

    /// Set the ACL's for a DID
    /// See [`Mediator::acls_set`] for full documentation
    pub async fn acls_set(
        &self,
        profile: &Arc<ATMProfile>,
        did_hash: &str,
        acls: &MediatorACLSet,
    ) -> Result<MediatorACLSetResponse, ATMError> {
        Mediator::default()
            .acls_set(self.atm, profile, did_hash, acls)
            .await
    }

    /// Access List List: Lists hash of DID's in the Access Control List for a given DID
    /// See [`Mediator::access_list_list`] for full documentation
    pub async fn access_list_list(
        &self,
        profile: &Arc<ATMProfile>,
        did_hash: Option<&str>,
        cursor: Option<u64>,
    ) -> Result<MediatorAccessListListResponse, ATMError> {
        Mediator::default()
            .access_list_list(self.atm, profile, did_hash, cursor)
            .await
    }

    /// Access List Add: Adds one or more DIDs to a Access Control List for a given DID
    /// See [`Mediator::access_list_add`] for full documentation
    pub async fn access_list_add(
        &self,
        profile: &Arc<ATMProfile>,
        did_hash: Option<&str>,
        hashes: &[&str],
    ) -> Result<MediatorAccessListAddResponse, ATMError> {
        Mediator::default()
            .access_list_add(self.atm, profile, did_hash, hashes)
            .await
    }

    /// Access List Remove: Removes one or more DIDs from a Access Control List for a given DID
    /// See [`Mediator::access_list_remove`] for full documentation
    pub async fn access_list_remove(
        &self,
        profile: &Arc<ATMProfile>,
        did_hash: Option<&str>,
        hashes: &[&str],
    ) -> Result<usize, ATMError> {
        Mediator::default()
            .access_list_remove(self.atm, profile, did_hash, hashes)
            .await
    }

    /// Access List Clear: Clears Access Control List for a given DID
    /// See [`Mediator::access_list_clear`] for full documentation
    pub async fn access_list_clear(
        &self,
        profile: &Arc<ATMProfile>,
        did_hash: Option<&str>,
    ) -> Result<(), ATMError> {
        Mediator::default()
            .access_list_clear(self.atm, profile, did_hash)
            .await
    }

    /// Access List Get: Searches for one or more DID's in the Access Control List for a given DID
    /// See [`Mediator::access_list_get`] for full documentation
    pub async fn access_list_get(
        &self,
        profile: &Arc<ATMProfile>,
        did_hash: Option<&str>,
        hashes: &[&str],
    ) -> Result<MediatorAccessListGetResponse, ATMError> {
        Mediator::default()
            .access_list_get(self.atm, profile, did_hash, hashes)
            .await
    }
}

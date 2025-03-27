/*!
Out Of Band (OOB) Discovery Protocol

Used to help discover 3rd party DID's while protecting your own privacy.
*/

use crate::{
    ATM,
    errors::ATMError,
    messages::{GenericDataStruct, SuccessResponse},
    profiles::ATMProfile,
};
use affinidi_messaging_didcomm::Message;
use base64::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    sync::Arc,
    time::{Duration, SystemTime},
};
use tracing::debug;
use uuid::Uuid;

#[derive(Default)]
pub struct OOBDiscovery {}

#[derive(Clone, Default, Debug, Serialize, Deserialize)]
pub struct OOBInviteResponse {
    pub _oobid: String,
}
impl GenericDataStruct for OOBInviteResponse {}

impl OOBDiscovery {
    /// Creates an OOB Invite
    /// atm :: ATM SDK Client
    /// expiry :: Optional - how long should this invitation exist for in seconds?
    ///           Default is 24 hours
    pub async fn create_invite(
        &self,
        atm: &ATM,
        profile: &Arc<ATMProfile>,
        expiry: Option<Duration>,
    ) -> Result<String, ATMError> {
        let (profile_did, mediator_did) = profile.dids()?;
        // Check if authenticated
        let tokens = atm
            .get_tdk()
            .authentication
            .authenticate(profile_did.to_string(), mediator_did.to_string(), 3, None)
            .await?;

        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut msg = Message::build(
            Uuid::new_v4().into(),
            "https://didcomm.org/out-of-band/2.0/invitation".into(),
            json!({}),
        )
        .thid(Uuid::new_v4().into())
        .from(profile.inner.did.clone())
        .created_time(now);

        if let Some(expiry) = expiry {
            msg = msg.expires_time(now + expiry.as_secs());
        } else {
            msg = msg.expires_time(now + 86_400);
        }

        let msg = msg.finalize();
        let msg = serde_json::to_string(&msg).map_err(|e| {
            ATMError::SDKError(format!("Could not serialize Invitation message: {:?}", e))
        })?;

        let Some(mediator_url) = profile.get_mediator_rest_endpoint() else {
            return Err(ATMError::MsgSendError(format!(
                "Profile ({}): Missing a valid mediator URL",
                profile.inner.alias
            )));
        };

        let res = atm
            .inner
            .tdk_common
            .client
            .post([&mediator_url, "/oob"].concat())
            .header("Content-Type", "application/json")
            .header("Authorization", format!("Bearer {}", tokens.access_token))
            .body(msg)
            .send()
            .await
            .map_err(|e| {
                ATMError::TransportError(format!("Could not send OOB Invitation request: {:?}", e))
            })?;

        let status = res.status();
        debug!("API response: status({})", status);

        let body = res
            .text()
            .await
            .map_err(|e| ATMError::TransportError(format!("Couldn't get body: {:?}", e)))?;

        if !status.is_success() {
            return Err(ATMError::TransportError(format!(
                "Status not successful. status({}), response({})",
                status, body
            )));
        }

        let body = serde_json::from_str::<SuccessResponse<OOBInviteResponse>>(&body)
            .ok()
            .unwrap();

        if let Some(data) = body.data {
            Ok(data._oobid)
        } else {
            Err(ATMError::MediatorError(
                "EMPTY".into(),
                "Expected to get _oobid, but it was empty...".into(),
            ))
        }
    }

    /// Retrieve an Invitation from a shortened OOB Invitation URL
    /// atm :: ATM SDK Client
    /// url :: Invitation OOB URL
    pub async fn retrieve_invite(&self, atm: &ATM, url: &str) -> Result<Message, ATMError> {
        let res = atm
            .inner
            .tdk_common
            .client
            .get(url)
            .header("Content-Type", "application/json")
            .send()
            .await
            .map_err(|e| {
                ATMError::TransportError(format!("Could not send OOB Invitation request: {:?}", e))
            })?;

        let status = res.status();
        debug!("API response: status({})", status);

        let body = res
            .text()
            .await
            .map_err(|e| ATMError::TransportError(format!("Couldn't get body: {:?}", e)))?;

        if !status.is_success() {
            return Err(ATMError::TransportError(format!(
                "Status not successful. status({}), response({})",
                status, body
            )));
        }

        let body = serde_json::from_str::<SuccessResponse<String>>(&body)
            .ok()
            .unwrap();

        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        if let Some(data) = body.data {
            // base64 decode the output
            let msg_str = String::from_utf8(
                BASE64_URL_SAFE_NO_PAD
                    .decode(data)
                    .expect("base64 decoding issue"),
            )
            .unwrap();
            let msg: Message =
                serde_json::from_str(&msg_str).expect("Can't deserialize Invitation");

            if let Some(expires_time) = msg.expires_time {
                if expires_time <= now {
                    return Err(ATMError::MediatorError(
                        "EXPIRED".into(),
                        "Invitation has expired...".into(),
                    ));
                }
            }
            Ok(msg)
        } else {
            Err(ATMError::MediatorError(
                "EMPTY".into(),
                "Expected to get OOB Invitation, but it was empty...".into(),
            ))
        }
    }

    /// Deletes OOB Invite
    /// atm :: ATM SDK Client
    /// oobid :: ID of the OOB Invitation to delete
    pub async fn delete_invite(
        &self,
        atm: &ATM,
        profile: &Arc<ATMProfile>,
        oobid: &str,
    ) -> Result<String, ATMError> {
        let (profile_did, mediator_did) = profile.dids()?;
        // Check if authenticated
        let tokens = atm
            .get_tdk()
            .authentication
            .authenticate(profile_did.to_string(), mediator_did.to_string(), 3, None)
            .await?;

        let Some(mediator_url) = profile.get_mediator_rest_endpoint() else {
            return Err(ATMError::MsgSendError(format!(
                "Profile ({}): Missing a valid mediator URL",
                profile.inner.alias
            )));
        };

        let res = atm
            .inner
            .tdk_common
            .client
            .delete(format!("{}/oob?_oobid={}", mediator_url, oobid))
            .header("Content-Type", "application/json")
            .header("Authorization", format!("Bearer {}", tokens.access_token))
            .send()
            .await
            .map_err(|e| {
                ATMError::TransportError(format!(
                    "Could not delete OOB Invitation request: {:?}",
                    e
                ))
            })?;

        let status = res.status();
        debug!("API response: status({})", status);

        let body = res
            .text()
            .await
            .map_err(|e| ATMError::TransportError(format!("Couldn't get body: {:?}", e)))?;

        if !status.is_success() {
            return Err(ATMError::TransportError(format!(
                "Status not successful. status({}), response({})",
                status, body
            )));
        }

        let body = serde_json::from_str::<SuccessResponse<String>>(&body)
            .ok()
            .unwrap();

        if let Some(data) = body.data {
            Ok(data)
        } else {
            Err(ATMError::MediatorError(
                "EMPTY".into(),
                "Expected to get delete status, but it was empty...".into(),
            ))
        }
    }
}

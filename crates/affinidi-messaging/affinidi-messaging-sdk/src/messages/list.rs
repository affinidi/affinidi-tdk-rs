use super::{Folder, MessageList};
use crate::{ATM, errors::ATMError, messages::SuccessResponse, profiles::ATMProfile};
use sha256::digest;
use std::sync::Arc;
use tracing::{Instrument, Level, debug, span};

impl ATM {
    /// Returns a list of messages that are stored in the ATM
    /// # Parameters
    /// - `did`: The DID to list messages for
    /// - `folder`: The folder to list messages from
    pub async fn list_messages(
        &self,
        profile: &Arc<ATMProfile>,
        folder: Folder,
    ) -> Result<MessageList, ATMError> {
        let _span = span!(Level::DEBUG, "list_messages", folder = folder.to_string());
        async move {
            let (profile_did, mediator_did) = profile.dids()?;
            debug!("listing folder({}) for DID({})", profile_did, folder);

            // Check if authenticated
            let tokens = self
                .get_tdk()
                .authentication
                .authenticate(profile_did.to_string(), mediator_did.to_string(), 3, None)
                .await?;

            let Some(mediator_url) = profile.get_mediator_rest_endpoint() else {
                return Err(ATMError::TransportError(
                    "No mediator URL found".to_string(),
                ));
            };

            let res = self
                .inner
                .tdk_common
                .client
                .get(format!(
                    "{}/list/{}/{}",
                    mediator_url,
                    digest(profile_did),
                    folder,
                ))
                .header("Content-Type", "application/json")
                .header("Authorization", format!("Bearer {}", tokens.access_token))
                .send()
                .await
                .map_err(|e| {
                    ATMError::TransportError(format!(
                        "Could not send list_messages request: {e:?}"
                    ))
                })?;

            let status = res.status();
            debug!("API response: status({})", status);

            let body = res
                .text()
                .await
                .map_err(|e| ATMError::TransportError(format!("Couldn't get body: {e:?}")))?;

            if !status.is_success() {
                return Err(ATMError::TransportError(format!(
                    "Status not successful. status({status}), response({body})"
                )));
            }

            let body = serde_json::from_str::<SuccessResponse<MessageList>>(&body)
                .ok()
                .unwrap();

            let list = if let Some(list) = body.data {
                list
            } else {
                return Err(ATMError::TransportError("No messages found".to_string()));
            };

            debug!("List contains ({}) messages", list.len());

            Ok(list)
        }
        .instrument(_span)
        .await
    }
}

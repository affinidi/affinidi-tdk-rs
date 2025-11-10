use super::GetMessagesRequest;
use crate::{
    ATM,
    errors::ATMError,
    messages::{GetMessagesResponse, SuccessResponse},
    profiles::ATMProfile,
};
use std::sync::Arc;
use tracing::{Instrument, Level, debug, span};

impl ATM {
    /// Returns a list of messages that are stored in the ATM
    /// - messages : List of message IDs to retrieve
    pub async fn get_messages(
        &self,
        profile: &Arc<ATMProfile>,
        messages: &GetMessagesRequest,
    ) -> Result<GetMessagesResponse, ATMError> {
        let _span = span!(Level::DEBUG, "get_messages");

        async move {
            let (profile_did, mediator_did) = profile.dids()?;
            // Check if authenticated
            let tokens = self
                .get_tdk()
                .authentication
                .authenticate(profile_did.to_string(), mediator_did.to_string(), 3, None)
                .await?;

            let body = serde_json::to_string(messages).map_err(|e| {
                ATMError::TransportError(format!(
                    "Could not serialize get message request: {e:?}"
                ))
            })?;

            let Some(mediator_url) = profile.get_mediator_rest_endpoint() else {
                return Err(ATMError::TransportError(
                    "No mediator URL found".to_string(),
                ));
            };

            debug!("Sending get_messages request: {:?}", body);

            let res = self
                .inner
                .tdk_common
                .client
                .post([&mediator_url, "/outbound"].concat())
                .header("Content-Type", "application/json")
                .header("Authorization", format!("Bearer {}", tokens.access_token))
                .body(body)
                .send()
                .await
                .map_err(|e| {
                    ATMError::TransportError(format!(
                        "Could not send get_messages request: {e:?}"
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

            let body = serde_json::from_str::<SuccessResponse<GetMessagesResponse>>(&body)
                .ok()
                .unwrap();

            let list = if let Some(list) = body.data {
                list
            } else {
                return Err(ATMError::TransportError("No messages found".to_string()));
            };

            debug!(
                "response: success({}) messages, failed({}) messages, failed_deleted({}) messages",
                list.success.len(),
                list.get_errors.len(),
                list.delete_errors.len()
            );
            if !list.get_errors.is_empty() {
                for (msg, err) in &list.get_errors {
                    debug!("failed get: msg({}) error({})", msg, err);
                }
            }
            if !list.delete_errors.is_empty() {
                for (msg, err) in &list.delete_errors {
                    debug!("failed delete: msg({}) error({})", msg, err);
                }
            }

            Ok(list)
        }
        .instrument(_span)
        .await
    }
}

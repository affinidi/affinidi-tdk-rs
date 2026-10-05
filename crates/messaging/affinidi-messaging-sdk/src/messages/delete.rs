use std::{sync::Arc, time::Duration};

use tokio::sync::mpsc::error::SendTimeoutError;

use tracing::{Instrument, Level, debug, span};

use crate::{
    ATM,
    delete_handler::DeletionHandlerCommands,
    errors::{ATMError, check_response},
    messages::SuccessResponse,
    profiles::ATMProfile,
};

use super::{DeleteMessageRequest, DeleteMessageResponse};

const MAX_DELETED_MESSAGES: usize = 100;

/// How long [`ATM::delete_message_background`] waits for room in the deletion
/// handler's queue before giving up.
pub const DELETE_ENQUEUE_TIMEOUT: Duration = Duration::from_secs(5);

impl ATM {
    /// Deletes a message from ATM in the background
    /// There is no guarantee as to when the message will be deleted
    /// You can choose to use `delete_message_direct` for a more immediate deletion
    ///
    /// # Bounded
    ///
    /// The deletion is queued for the background deletion handler. Its queue
    /// is small (32), and the handler retries a failing batch with backoff —
    /// honouring a mediator's `Retry-After` — so while the mediator is slow or
    /// rate-limiting deletes the queue can stay full for a long time. This
    /// used to await a slot without limit, which parked the caller: the
    /// delivery layer's single dispatcher, acking a message it had already
    /// handed off, stopped dispatching anything, and the socket looked healthy
    /// while nothing was being deleted at the mediator. The enqueue now gives
    /// up after [`DELETE_ENQUEUE_TIMEOUT`] with an [`ATMError::SDKError`]; the
    /// message is still at the mediator and is redelivered, so a caller that
    /// cares parks and retries the delete rather than blocking on it.
    pub async fn delete_message_background(
        &self,
        profile: &Arc<ATMProfile>,
        message_id: &str,
    ) -> Result<(), ATMError> {
        debug!("Deleting message in the background: {}", message_id);
        self.inner
            .deletion_handler_send_stream
            .send_timeout(
                DeletionHandlerCommands::DeleteMessage(profile.clone(), message_id.to_string()),
                DELETE_ENQUEUE_TIMEOUT,
            )
            .await
            .map_err(|e| match e {
                SendTimeoutError::Timeout(_) => ATMError::SDKError(format!(
                    "Deletion handler queue still full after {DELETE_ENQUEUE_TIMEOUT:?}; \
                     message ({message_id}) not queued for deletion"
                )),
                SendTimeoutError::Closed(_) => ATMError::SDKError(
                    "Couldn't send deletion request to Deletion Handler: channel closed"
                        .to_string(),
                ),
            })
    }

    /// Queue a deletion without waiting at all. `false` when the deletion
    /// handler's queue is full or closed — the message stays at the mediator
    /// and is redelivered. For callers that must never park, such as the
    /// websocket transport task itself.
    pub(crate) fn try_delete_message_background(
        &self,
        profile: &Arc<ATMProfile>,
        message_id: &str,
    ) -> bool {
        self.inner
            .deletion_handler_send_stream
            .try_send(DeletionHandlerCommands::DeleteMessage(
                profile.clone(),
                message_id.to_string(),
            ))
            .is_ok()
    }

    /// Delete messages from ATM directly
    /// This will delete messages from the mediator through a direct message
    /// NOTE: Use `delete_message_background` as a more efficient way to delete messages
    /// - messages: List of message_ids to delete
    ///
    /// Each request is bounded by the configured request timeout
    /// (`ATMConfig::with_request_timeout`, default 15s); an unreachable
    /// mediator returns `ATMError::TransportError` rather than hanging.
    pub async fn delete_messages_direct(
        &self,
        profile: &Arc<ATMProfile>,
        messages: &DeleteMessageRequest,
    ) -> Result<DeleteMessageResponse, ATMError> {
        let _span = span!(Level::DEBUG, "delete_messages");

        async move {
            let (profile_did, mediator_did) = profile.dids()?;
            // Check if authenticated
            let tokens = self
                .get_tdk()
                .authentication()
                .authenticate(profile_did.to_string(), mediator_did.to_string(), 3, None)
                .await?;

        if messages.message_ids.len() > MAX_DELETED_MESSAGES {
            return  Err(ATMError::MsgSendError(format!(
                "Operation exceeds the allowed limit. You may delete a maximum of 100 messages per request. Received {} ids.",
                messages.message_ids.len()
            )));
        }
        let msg = serde_json::to_string(messages).map_err(|e| {
            ATMError::TransportError(format!(
                "Could not serialize delete message request: {e:?}"
            ))
        })?;

        let Some(mediator_url) = profile.get_mediator_rest_endpoint() else {
            return Err(ATMError::TransportError(
                "No mediator URL found".to_string(),
            ));
        };
        debug!("Sending delete_messages request: {:?}", msg);

        let res = self
            .inner
            .tdk_common
            .client()
            .delete([&mediator_url, "/delete"].concat())
            .header("Content-Type", "application/json")
            .header("Authorization", format!("Bearer {}", tokens.access_token))
            .body(msg)
            .timeout(self.inner.config.request_timeout)
            .send()
            .await
            .map_err(|e| {
                ATMError::TransportError(format!("Could not send delete_messages request: {e:?}"))
            })?;

        debug!("API response: status({})", res.status());
        let body = check_response("delete messages", res).await?;

        let body = serde_json::from_str::<SuccessResponse<DeleteMessageResponse>>(&body)
            .map_err(|e| {
                ATMError::TransportError(format!(
                    "Could not parse delete_messages response: {e:?}"
                ))
            })?;

        let list = if let Some(list) = body.data {
            list
        } else {
            return Err(ATMError::TransportError("No messages found".to_string()));
        };

        debug!(
            "response: success({}) messages, failed({}) messages",
            list.success.len(),
            list.errors.len()
        );
        if !list.errors.is_empty() {
            for (msg, err) in &list.errors {
                debug!("failed: msg({}) error({})", msg, err);
            }
        }

        Ok(list)
    }.instrument(_span).await
    }
}

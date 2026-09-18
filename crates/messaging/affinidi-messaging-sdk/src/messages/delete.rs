use std::sync::Arc;

use tracing::{Instrument, Level, debug, span};

use crate::{
    ATM,
    delete_handler::DeletionHandlerCommands,
    errors::{ATMError, check_response},
    messages::SuccessResponse,
    profiles::ATMProfile,
};

use super::{DeleteMessageRequest, DeleteMessageResponse, Folder, PurgeQueueResponse};

const MAX_DELETED_MESSAGES: usize = 100;

impl ATM {
    /// Deletes a message from ATM in the background
    /// There is no guarantee as to when the message will be deleted
    /// You can choose to use `delete_message_direct` for a more immediate deletion
    pub async fn delete_message_background(
        &self,
        profile: &Arc<ATMProfile>,
        message_id: &str,
    ) -> Result<(), ATMError> {
        debug!("Deleting message in the background: {}", message_id);
        self.inner
            .deletion_handler_send_stream
            .send(DeletionHandlerCommands::DeleteMessage(
                profile.clone(),
                message_id.to_string(),
            ))
            .await
            .map_err(|e| {
                ATMError::SDKError(format!(
                    "Couldn't send deletion request to Deletion Handler: {e}"
                ))
            })
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

impl ATM {
    /// Empty one of this profile's own queues at the mediator in a single call.
    ///
    /// # When you want this instead of deleting by id
    ///
    /// Deleting by id is the right tool while a queue is healthy. It stops
    /// being one when a queue is *stuck*: `/list` is capped at 100 with no
    /// cursor, `/fetch` pages, and every batch is separately authenticated —
    /// so clearing a large backlog costs exactly the kind of request volume
    /// that gets a node rate-limited, which is usually how the backlog started.
    ///
    /// The queue that strands a deployment is often not this node's inbox but a
    /// **peer's send queue**: a message is held against the sender's account
    /// until the recipient deletes it, so a receiver whose deletes are failing
    /// fills the send queue of everyone talking to it, up to
    /// `queued_send_messages_hard` (1000 by default), after which that peer
    /// cannot send at all. This is how such a peer gets itself back.
    ///
    /// # This destroys messages
    ///
    /// Purged messages are gone — not returned to their senders, not
    /// recoverable. On [`Folder::Inbox`] that is undelivered mail addressed to
    /// you. Prefer deleting by id whenever the queue is small enough to page.
    ///
    /// Scoped to the calling DID: there is no way to purge another DID's queue.
    pub async fn purge_queue(
        &self,
        profile: &Arc<ATMProfile>,
        folder: Folder,
    ) -> Result<PurgeQueueResponse, ATMError> {
        let _span = span!(Level::DEBUG, "purge_queue", ?folder);

        async move {
            let (profile_did, mediator_did) = profile.dids()?;
            let tokens = self
                .get_tdk()
                .authentication()
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
                .client()
                .delete([&mediator_url, "/purge/", &folder.to_string()].concat())
                .header("Authorization", format!("Bearer {}", tokens.access_token))
                .timeout(self.inner.config.request_timeout)
                .send()
                .await
                .map_err(|e| {
                    ATMError::TransportError(format!("Could not send purge_queue request: {e:?}"))
                })?;

            let body = check_response("purge queue", res).await?;
            let body = serde_json::from_str::<SuccessResponse<PurgeQueueResponse>>(&body).map_err(
                |e| {
                    ATMError::TransportError(format!("Could not parse purge_queue response: {e:?}"))
                },
            )?;

            let purged = body.data.ok_or_else(|| {
                ATMError::TransportError("Purge response carried no data".to_string())
            })?;

            debug!(count = purged.count, bytes = purged.bytes, "purged queue");
            Ok(purged)
        }
        .instrument(_span)
        .await
    }
}

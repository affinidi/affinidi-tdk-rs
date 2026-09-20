use std::sync::Arc;

use tracing::{Instrument, Level, debug, span};

use crate::{
    ATM,
    delete_handler::DeletionHandlerCommands,
    errors::{ATMError, check_response},
    messages::SuccessResponse,
    profiles::ATMProfile,
};

use super::{
    DeleteMessageRequest, DeleteMessageResponse, Folder, PurgeQueueResponse, QueueStatusResponse,
};

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
        self.purge_queue_filtered(profile, folder, &PurgeOptions::default())
            .await
    }

    /// Empty part of one of the calling DID's own queues, or report what that
    /// would remove.
    ///
    /// The whole-folder purge is rarely the operation an operator wants. The
    /// queue that strands a deployment is usually full of messages for **one**
    /// peer that stopped collecting, or of messages old enough to be certain
    /// they are never going to be collected — and destroying the rest of the
    /// outbox to clear them is a second incident.
    ///
    /// [`PurgeOptions::dry_run`] reports what would go without removing
    /// anything. Use it first: a purge is unrecoverable.
    ///
    /// With no options set this is exactly [`purge_queue`](Self::purge_queue),
    /// and takes the mediator's faster whole-folder path.
    pub async fn purge_queue_filtered(
        &self,
        profile: &Arc<ATMProfile>,
        folder: Folder,
        options: &PurgeOptions,
    ) -> Result<PurgeQueueResponse, ATMError> {
        let _span = span!(Level::DEBUG, "purge_queue", ?folder, ?options);

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
                .delete(
                    [
                        &mediator_url,
                        "/purge/",
                        &folder.to_string(),
                        &options.query_string(),
                    ]
                    .concat(),
                )
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

            debug!(
                count = purged.count,
                bytes = purged.bytes,
                scanned = purged.scanned,
                dry_run = purged.dry_run,
                "purged queue"
            );
            Ok(purged)
        }
        .instrument(_span)
        .await
    }

    /// This DID's own queue depth, effective limits and oldest-message age at
    /// the mediator.
    ///
    /// The point is to pace **before** being refused: `saturation` reaching 1.0
    /// is the depth at which the mediator starts rejecting sends, so a client
    /// that slows at 0.8 never reaches it. A climbing `oldest_age_secs` beside
    /// a steady depth says the peer at the other end has stopped collecting —
    /// which depth alone cannot distinguish from a busy queue.
    pub async fn queue_status(
        &self,
        profile: &Arc<ATMProfile>,
    ) -> Result<QueueStatusResponse, ATMError> {
        let _span = span!(Level::DEBUG, "queue_status");

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
                .get([&mediator_url, "/queue/status"].concat())
                .header("Authorization", format!("Bearer {}", tokens.access_token))
                .timeout(self.inner.config.request_timeout)
                .send()
                .await
                .map_err(|e| {
                    ATMError::TransportError(format!("Could not send queue_status request: {e:?}"))
                })?;

            let body = check_response("queue status", res).await?;
            let body = serde_json::from_str::<SuccessResponse<QueueStatusResponse>>(&body)
                .map_err(|e| {
                    ATMError::TransportError(format!(
                        "Could not parse queue_status response: {e:?}"
                    ))
                })?;

            body.data.ok_or_else(|| {
                ATMError::TransportError("Queue status response carried no data".to_string())
            })
        }
        .instrument(_span)
        .await
    }
}

/// How to narrow a [`purge_queue_filtered`](ATM::purge_queue_filtered) call.
///
/// All fields default to "no narrowing", which is the whole-folder purge.
#[derive(Debug, Default, Clone)]
pub struct PurgeOptions {
    /// Only messages exchanged with this counterparty (a DID **hash**).
    ///
    /// Which end that is depends on the folder: in an outbox it is who the
    /// message was sent to, in an inbox who sent it.
    pub peer: Option<String>,
    /// Only messages queued at least this long.
    pub older_than_secs: Option<u64>,
    /// Report what would be purged and purge nothing.
    pub dry_run: bool,
}

/// Percent-encode a query-string **value**.
///
/// Written here rather than pulling in an encoding crate for one call: the
/// only values that reach this are DID hashes, and the requirement is simply
/// that nothing a caller passes can turn one parameter into two. Everything
/// outside the unreserved set of RFC 3986 §2.3 is escaped, which is stricter
/// than necessary and cannot under-escape.
fn percent_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

impl PurgeOptions {
    /// Render as a query string, including the leading `?`, or empty when
    /// nothing is set.
    fn query_string(&self) -> String {
        let mut parts: Vec<String> = Vec::new();
        if let Some(peer) = &self.peer {
            // DID hashes are hex, but encode anyway: a caller can pass
            // anything, and a raw `&` in a query value would silently become a
            // second parameter.
            parts.push(format!("peer={}", percent_encode(peer)));
        }
        if let Some(secs) = self.older_than_secs {
            parts.push(format!("olderThanSecs={secs}"));
        }
        if self.dry_run {
            parts.push("dryRun=true".to_string());
        }
        if parts.is_empty() {
            String::new()
        } else {
            format!("?{}", parts.join("&"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_options_is_the_plain_whole_folder_purge() {
        assert_eq!(PurgeOptions::default().query_string(), "");
    }

    #[test]
    fn options_render_in_camel_case_as_the_mediator_expects() {
        let opts = PurgeOptions {
            peer: Some("abc123".into()),
            older_than_secs: Some(604_800),
            dry_run: true,
        };
        assert_eq!(
            opts.query_string(),
            "?peer=abc123&olderThanSecs=604800&dryRun=true"
        );
    }

    /// A raw `&` in a value would otherwise become a second parameter, and the
    /// mediator rejects unknown ones — so this fails loudly rather than
    /// purging something unintended.
    #[test]
    fn a_peer_value_is_encoded() {
        let opts = PurgeOptions {
            peer: Some("a&dryRun=true".into()),
            ..Default::default()
        };
        assert_eq!(opts.query_string(), "?peer=a%26dryRun%3Dtrue");
    }

    #[test]
    fn a_dry_run_alone_still_narrows() {
        let opts = PurgeOptions {
            dry_run: true,
            ..Default::default()
        };
        assert_eq!(opts.query_string(), "?dryRun=true");
    }
}

/*!
 * The message delete database function sits in common so that it can be used by
 * both the mediator and the processors (message_expiry for example)
 */
use super::DatabaseHandler;
use crate::errors::MediatorError;
use crate::store::types::{DeletionAuthority, OutboxReceipt};
use crate::store::{OUTBOX_RECEIPT_TTL, ops};
use crate::types::problem_report::{ProblemReportScope, ProblemReportSorter};
use axum::http::StatusCode;
use tracing::{Instrument, Level, debug, info, span, warn};

impl DatabaseHandler {
    /// Deletes a message in the database.
    ///
    /// The Lua `delete_message` function performs an ownership check:
    /// the requesting DID must be the message's TO, FROM, or match
    /// the `admin_did_hash` (for system operations like expiry cleanup).
    ///
    /// Returns specific errors for not-found and permission-denied cases.
    pub async fn delete_message(
        &self,
        session_id: Option<&str>,
        did_hash: &str,
        message_hash: &str,
        request_msg_id: Option<&str>,
        admin_did_hash: Option<&str>,
    ) -> Result<(), MediatorError> {
        let _span = span!(
            Level::INFO,
            "database_delete",
            session = session_id,
            did_hash = did_hash,
            message_hash = message_hash,
        );
        async move {
            let mut conn = self.get_async_connection().await?;

            // Read before the delete, because the delete removes the metadata.
            // The receipt is written here in Rust rather than in the stored
            // function for the reason `mark_delivered` gives: a stale function
            // library loads without complaint and would silently never write
            // it. A metadata read that fails only costs the receipt.
            let parties: Option<(String, String)> = redis::cmd("HMGET")
                .arg(["MSG:META:", message_hash].concat())
                .arg("TO")
                .arg("FROM")
                .arg("SEND_ID")
                .query_async::<Vec<Option<String>>>(&mut conn)
                .await
                .ok()
                .and_then(|fields| match fields.as_slice() {
                    // `SEND_ID` is present exactly when the message sits in
                    // a sender's outbox, i.e. has a recorded sender.
                    [Some(to), Some(from), Some(_)] => Some((to.clone(), from.clone())),
                    _ => None,
                });

            let mut cmd = redis::cmd("FCALL");
            cmd.arg("delete_message")
                .arg(1)
                .arg(message_hash)
                .arg(did_hash);
            if let Some(admin_hash) = admin_did_hash {
                cmd.arg(admin_hash);
            }
            let result: Result<String, redis::RedisError> = cmd.query_async(&mut conn).await;

            match result {
                Ok(response) if response == "OK" => {
                    info!("Successfully deleted message_hash({})", message_hash);
                    if let Some((to, from)) = parties {
                        self.record_outbox_receipt(
                            &mut conn,
                            message_hash,
                            did_hash,
                            admin_did_hash.is_some(),
                            &to,
                            &from,
                        )
                        .await;
                    }
                    Ok(())
                }
                Ok(response) => {
                    // Lua returned a non-OK status (shouldn't happen with current script)
                    warn!(
                        "delete_message returned unexpected status: {} for message_hash({})",
                        response, message_hash
                    );
                    Err(MediatorError::problem_with_log(
                        11,
                        "NA",
                        request_msg_id.map(|s| s.to_string()),
                        ProblemReportSorter::Warning,
                        ProblemReportScope::Message,
                        "database.message.delete.status",
                        "delete returned unexpected status ({1}) for message ({2})",
                        vec![response.to_string(), message_hash.to_string()],
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("delete returned unexpected status ({response}) for message ({message_hash})"),
                    ))
                }
                Err(err) => {
                    let err_str = err.to_string();

                    // Parse Lua error responses for specific handling
                    if err_str.contains("NOT_FOUND") {
                        debug!(
                            "Message not found for deletion: message_hash({})",
                            message_hash
                        );
                        Err(MediatorError::problem(
                            10,
                            "NA",
                            request_msg_id.map(|s| s.to_string()),
                            ProblemReportSorter::Warning,
                            ProblemReportScope::Message,
                            "database.message.delete.not_found",
                            "Message ({1}) not found",
                            vec![message_hash.to_string()],
                            StatusCode::NOT_FOUND,
                        ))
                    } else if err_str.contains("PERMISSION_DENIED") {
                        warn!(
                            "Permission denied deleting message_hash({}) by did_hash({})",
                            message_hash, did_hash
                        );
                        Err(MediatorError::problem(
                            10,
                            "NA",
                            request_msg_id.map(|s| s.to_string()),
                            ProblemReportSorter::Warning,
                            ProblemReportScope::Message,
                            "database.message.delete.permission_denied",
                            "Not authorized to delete message ({1})",
                            vec![message_hash.to_string()],
                            StatusCode::FORBIDDEN,
                        ))
                    } else {
                        // Generic database error
                        Err(MediatorError::problem_with_log(
                            10,
                            "NA",
                            request_msg_id.map(|s| s.to_string()),
                            ProblemReportSorter::Warning,
                            ProblemReportScope::Message,
                            "database.message.delete.error",
                            "Couldn't delete message_hash ({1}). Reason: {2}",
                            vec![message_hash.to_string(), err_str],
                            StatusCode::SERVICE_UNAVAILABLE,
                            format!("Couldn't delete message_hash ({message_hash}). Reason: {err}"),
                        ))
                    }
                }
            }
        }
        .instrument(_span)
        .await
    }

    /// Leave `from` a receipt saying why `message_hash` left its outbox.
    ///
    /// Best-effort: the message is already gone, and a receipt that could not
    /// be written reads as `Unknown` to the sender, which it treats as no
    /// evidence. Never as delivery.
    async fn record_outbox_receipt(
        &self,
        conn: &mut redis::aio::ConnectionManager,
        message_hash: &str,
        did_hash: &str,
        as_admin: bool,
        to: &str,
        from: &str,
    ) {
        let authority = if as_admin {
            DeletionAuthority::Admin {
                admin_did_hash: did_hash.to_string(),
            }
        } else {
            DeletionAuthority::Owner {
                did_hash: did_hash.to_string(),
            }
        };
        let Some(reason) = ops::removal_reason(&authority, to, Some(from)) else {
            return;
        };
        let receipt = OutboxReceipt {
            reason,
            at_ms: now_ms(),
        };
        let written: Result<(), redis::RedisError> = redis::cmd("SET")
            .arg(outbox_receipt_key(from, message_hash))
            .arg(receipt.encode())
            .arg("EX")
            .arg(OUTBOX_RECEIPT_TTL.as_secs())
            .query_async(conn)
            .await;
        if let Err(err) = written {
            warn!("Couldn't record the outbox receipt for message_hash({message_hash}): {err}");
        }
    }
}

/// Where a sender's receipt for one removed message lives. Keyed under the
/// sender so no other account's lookup can reach it.
pub(crate) fn outbox_receipt_key(from: &str, message_hash: &str) -> String {
    ["RECEIPT:", from, ":", message_hash].concat()
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

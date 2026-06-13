//! Database routines for the privileged-change audit log.
//!
//! Stored as a Redis LIST keyed `AUDIT_LOG`: `LPUSH` puts the newest entry at
//! the head (index 0), so the list is naturally newest-first, and `LTRIM` after
//! each push bounds it to [`AUDIT_LOG_MAX_ENTRIES`] — a fixed-size ring.

use crate::errors::MediatorError;
use crate::types::audit::{AUDIT_LOG_MAX_ENTRIES, AuditLogEntry, MediatorAuditLogList};
use tracing::{Instrument, Level, span};

use super::Database;

/// Redis key for the audit-log list.
const AUDIT_LOG_KEY: &str = "AUDIT_LOG";

// Redis-backend implementation behind `RedisStore`.
impl Database {
    pub(crate) async fn audit_log_record(
        &self,
        entry: &AuditLogEntry,
    ) -> Result<(), MediatorError> {
        let _span = span!(Level::DEBUG, "audit_log_record");
        async move {
            let json = serde_json::to_string(entry).map_err(|e| {
                MediatorError::InternalError(
                    14,
                    "NA".into(),
                    format!("audit_log_record: serialise failed: {e}"),
                )
            })?;

            let mut con = self.get_connection().await?;
            // LPUSH (newest at head) then LTRIM to the cap — atomic so a reader
            // never sees the list briefly over the cap.
            redis::pipe()
                .atomic()
                .cmd("LPUSH")
                .arg(AUDIT_LOG_KEY)
                .arg(&json)
                .cmd("LTRIM")
                .arg(AUDIT_LOG_KEY)
                .arg(0)
                .arg(AUDIT_LOG_MAX_ENTRIES as isize - 1)
                .exec_async(&mut con)
                .await
                .map_err(|e| {
                    MediatorError::DatabaseError(
                        14,
                        "NA".into(),
                        format!("audit_log_record failed: {e}"),
                    )
                })?;
            Ok(())
        }
        .instrument(_span)
        .await
    }

    pub(crate) async fn audit_log_list(
        &self,
        cursor: u32,
        limit: u32,
    ) -> Result<MediatorAuditLogList, MediatorError> {
        let _span = span!(
            Level::DEBUG,
            "audit_log_list",
            cursor = cursor,
            limit = limit
        );
        async move {
            let limit = limit.min(100);
            let mut con = self.get_connection().await?;

            // The list is already newest-first; page directly by index.
            let start = cursor as isize;
            let stop = start + limit as isize - 1;
            let (items, total): (Vec<String>, u64) = redis::pipe()
                .cmd("LRANGE")
                .arg(AUDIT_LOG_KEY)
                .arg(start)
                .arg(stop)
                .cmd("LLEN")
                .arg(AUDIT_LOG_KEY)
                .query_async(&mut con)
                .await
                .map_err(|e| {
                    MediatorError::DatabaseError(
                        14,
                        "NA".into(),
                        format!("audit_log_list failed at cursor ({cursor}): {e}"),
                    )
                })?;

            let mut entries = Vec::with_capacity(items.len());
            for item in &items {
                let entry: AuditLogEntry = serde_json::from_str(item).map_err(|e| {
                    MediatorError::InternalError(
                        14,
                        "NA".into(),
                        format!("audit_log_list: deserialise failed: {e}"),
                    )
                })?;
                entries.push(entry);
            }

            let next_cursor = if cursor as u64 + entries.len() as u64 >= total {
                0
            } else {
                cursor + entries.len() as u32
            };
            Ok(MediatorAuditLogList {
                entries,
                cursor: next_cursor,
            })
        }
        .instrument(_span)
        .await
    }
}

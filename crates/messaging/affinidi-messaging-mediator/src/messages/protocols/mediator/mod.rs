pub(crate) mod accounts;
pub(crate) mod acls;
pub(crate) mod administration;

use crate::{SharedData, common::session::Session};
use affinidi_messaging_mediator_common::types::audit::{AuditAction, AuditLogEntry};
use tracing::warn;

/// Record a privileged-change audit entry, best-effort.
///
/// Called *after* the mutation has already succeeded, so a failure to record
/// must not turn a successful admin/self-service action into an error — we log
/// and move on. The actor is the authenticated caller (`session.did_hash`);
/// `target_did_hash` is the DID whose record changed; `detail` is a short
/// human-readable summary (not machine-parsed).
pub(crate) async fn record_audit(
    state: &SharedData,
    session: &Session,
    target_did_hash: &str,
    action: AuditAction,
    detail: String,
) {
    let entry = AuditLogEntry {
        timestamp: state.clock.unix_secs(),
        actor_did_hash: session.did_hash.clone(),
        target_did_hash: target_did_hash.to_string(),
        action,
        detail,
    };
    if let Err(e) = state.database.audit_log_record(&entry).await {
        warn!(
            action = ?action,
            target = %target_did_hash,
            "Failed to record audit-log entry: {e}"
        );
    }
}

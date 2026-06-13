//! Audit-log vocabulary for privileged (admin / self-service) changes.
//!
//! Every mutation to a DID's ACLs, access list, account record, or admin
//! status is recorded as an [`AuditLogEntry`] so operators have a tamper-evident
//! trail of *who changed what, when*. The log is a bounded ring — see
//! [`AUDIT_LOG_MAX_ENTRIES`] — kept newest-first; the oldest entries are dropped
//! once the cap is reached.
//!
//! The store layer (`MediatorStore::audit_log_record` / `audit_log_list`)
//! produces and serves these; the admin query protocol (a later increment)
//! exposes [`MediatorAuditLogList`] over DIDComm.

use serde::{Deserialize, Serialize};

/// Maximum number of audit entries retained per mediator. The log is a ring:
/// once full, recording a new entry drops the oldest. Admin changes are
/// infrequent, so this bounds disk/memory while keeping a long history.
pub const AUDIT_LOG_MAX_ENTRIES: usize = 10_000;

/// The kind of privileged change an [`AuditLogEntry`] records. Serialized with
/// stable snake_case names so the wire form is independent of the Rust spelling.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditAction {
    /// A DID's ACL bitmask was replaced (`set_did_acl`).
    #[serde(rename = "set_acl")]
    SetAcl,
    /// Hashes were added to a DID's access list.
    #[serde(rename = "access_list_add")]
    AccessListAdd,
    /// Hashes were removed from a DID's access list.
    #[serde(rename = "access_list_remove")]
    AccessListRemove,
    /// A DID's entire access list was cleared.
    #[serde(rename = "access_list_clear")]
    AccessListClear,
    /// An account was created.
    #[serde(rename = "account_add")]
    AccountAdd,
    /// An account was removed.
    #[serde(rename = "account_remove")]
    AccountRemove,
    /// An account's role/type was changed.
    #[serde(rename = "account_change_type")]
    AccountChangeType,
    /// An account's send/receive queue limits were changed.
    #[serde(rename = "account_change_queue_limits")]
    AccountChangeQueueLimits,
    /// One or more DIDs were promoted to admin.
    #[serde(rename = "admin_add")]
    AdminAdd,
    /// One or more DIDs had admin status stripped.
    #[serde(rename = "admin_strip")]
    AdminStrip,
}

/// A single audit-log record: one privileged change, by one actor, at one time.
///
/// `actor_did_hash` is the authenticated caller that made the change (an admin,
/// or the account owner for self-service changes); `target_did_hash` is the DID
/// whose record changed. `detail` is a short human-readable summary (e.g. the
/// new ACL value, or the number of hashes added) — not machine-parsed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditLogEntry {
    /// Unix timestamp (seconds) when the change was recorded.
    pub timestamp: u64,
    /// SHA-256 hash of the DID that performed the change.
    pub actor_did_hash: String,
    /// SHA-256 hash of the DID whose record was changed.
    pub target_did_hash: String,
    /// What kind of change this was.
    pub action: AuditAction,
    /// Short human-readable detail of the change.
    pub detail: String,
}

/// A page of audit-log entries (newest-first) plus the cursor for the next page.
///
/// `cursor` is an opaque offset to feed back into the next `audit_log_list`
/// call; `0` means there are no more pages (the same convention as
/// `MediatorAccountList` / `MediatorAdminList`).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MediatorAuditLogList {
    /// The entries on this page, ordered newest-first.
    pub entries: Vec<AuditLogEntry>,
    /// Offset for the next page, or `0` when the listing is exhausted.
    pub cursor: u32,
}

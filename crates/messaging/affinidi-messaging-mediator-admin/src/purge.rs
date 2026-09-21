//! Preview-then-confirm purges.
//!
//! A purge removes messages for good, so the console never runs one blind:
//! [`MediatorConsole::purge_preview`](crate::MediatorConsole::purge_preview)
//! counts what would go and returns a [`PurgePlan`]; the user confirms the
//! count; [`MediatorConsole::purge`](crate::MediatorConsole::purge) carries it
//! out — and refuses, removing nothing, if the queue no longer matches the
//! count the user confirmed.

use chrono::{DateTime, Utc};
use trust_tasks_rs::specs::messaging::queue::purge::v0_1::Queue;

use crate::console::Target;

/// What to purge.
#[derive(Clone, Debug)]
pub struct PurgeRequest {
    /// Whose queue: `None` is the console's own account.
    pub target: Target,
    pub queue: Queue,
    /// Only messages exchanged with this counterparty.
    pub peer: Option<String>,
    /// Only messages queued at least this long.
    pub older_than_seconds: Option<u64>,
}

/// A counted purge, ready to confirm.
#[derive(Clone, Debug)]
pub struct PurgePlan {
    pub request: PurgeRequest,
    /// Messages the preview matched — what the user is asked to confirm.
    pub matched: u64,
    pub matched_bytes: u64,
    pub previewed_at: DateTime<Utc>,
}

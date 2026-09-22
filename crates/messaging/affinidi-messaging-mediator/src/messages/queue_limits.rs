//! Queue-depth gates shared by every path that stores a message.
//!
//! These used to live in `protocols::routing`, which exists only in a
//! `didcomm` build and is reached only by a `forward`. That left **direct
//! delivery** (a client sending an already-packed envelope to a local
//! recipient) and the **TSP bridge** storing to a recipient's inbox with no
//! depth limit of any kind — not the sender total, not the recipient total,
//! and not the per-relationship count added for VTI-29. A sender using the
//! direct path could therefore fill any inbox without bound, and the fix for
//! VTI-29 did not reach it.
//!
//! So they live here, outside the `didcomm` gate, and identify a message by
//! `msg_id` rather than by a `Message` — the direct path has an opaque
//! envelope, not a parsed message.
//!
//! **Mediator-generated replies are exempt**, and that exemption is
//! load-bearing rather than a convenience: they are how a client is told its
//! queue is full. Gating them means a full inbox becomes an unreportable
//! inbox, and the peer sees a silence it cannot distinguish from a dead
//! mediator.

use affinidi_messaging_mediator_common::errors::MediatorError;
use affinidi_messaging_sdk::messages::problem_report::{ProblemReportScope, ProblemReportSorter};
use affinidi_messaging_sdk::protocols::mediator::accounts::Account;
use http::StatusCode;
use tracing::warn;

use crate::SharedData;
use crate::common::metrics::names;
use crate::common::session::Session;

/// Gate label for [`names::QUEUE_LIMIT_REFUSALS_TOTAL`]. Three fixed values,
/// so the label is cardinality-safe: it never carries a DID.
const GATE_PEER: &str = "peer";
const GATE_SENDER: &str = "sender";
const GATE_RECIPIENT: &str = "recipient";

/// Count one refusal by the gate that made it.
///
/// Counted here rather than at the call sites so that a gate cannot be added
/// later and refuse silently — every `return Err` below goes through this.
/// Without it a refusal left only a `warn!`, which is legible to somebody
/// already reading logs for the DID in question and to nobody else.
fn count_refusal(gate: &'static str) {
    metrics::counter!(names::QUEUE_LIMIT_REFUSALS_TOTAL, "gate" => gate).increment(1);
}

/// Whether adding `incoming` messages to a queue already holding `queued`
/// would meet or exceed `limit`. `-1` means "unlimited"; `ephemeral`
/// forwards (live-stream only) never count against a queue.
pub(crate) fn queue_at_capacity(queued: u32, incoming: usize, limit: i32, ephemeral: bool) -> bool {
    limit != -1 && !ephemeral && queued + incoming as u32 >= limit as u32
}

/// Reject the forward when the sender already has too many messages queued
/// **for this one recipient**.
///
/// This is the gate that catches a sender flooding a peer. The per-DID totals
/// below cannot: a community holding one uncollected membership card for each
/// of two hundred members presents identically to a sender aiming two hundred
/// messages at one victim, so capping the total silences the community because
/// *its members* went offline. That is the failure this function exists to
/// stop — it moves only when one relationship is genuinely over-full.
///
/// Inert when the backend does not track per-pair counts (the trait default
/// returns 0) or when the limit is `-1`. `ephemeral` forwards (live-stream
/// only) bypass queue accounting entirely, as with the other gates.
pub(crate) async fn validate_peer_queue_limit(
    msg_id: Option<&str>,
    from_did_hash: &str,
    next_did_hash: &str,
    attachment_count: usize,
    ephemeral: bool,
    state: &SharedData,
    session: &Session,
) -> Result<(), MediatorError> {
    let limit = state.limits().queued_send_messages_per_peer;
    if limit == -1 || ephemeral {
        return Ok(());
    }
    let queued = state
        .database
        .peer_queue_count(from_did_hash, next_did_hash)
        .await?;
    if queue_at_capacity(queued, attachment_count, limit, ephemeral) {
        count_refusal(GATE_PEER);
        warn!(
            "Sender DID ({}) has too many messages waiting for recipient ({})",
            session.did_hash, next_did_hash
        );
        return Err(MediatorError::problem(
            95,
            &session.session_id,
            msg_id.map(str::to_string),
            ProblemReportSorter::Error,
            ProblemReportScope::Protocol,
            "limits.queue.peer",
            "Too many messages already waiting for this recipient",
            vec![],
            StatusCode::SERVICE_UNAVAILABLE,
        ));
    }
    Ok(())
}

/// Reject the forward when the sender already has too many messages queued.
/// `ephemeral` forwards (live-stream only) bypass the queue accounting.
///
/// A **coarse ceiling only** — see [`validate_peer_queue_limit`], which is the
/// gate that distinguishes flooding from fan-out. This one cannot, so its
/// default sits high enough not to catch legitimate fan-out. It is deliberately
/// not the mediator's storage bound either: every queued message is counted in
/// exactly one recipient's inbox, so the per-recipient caps already bound total
/// storage on their own.
pub(crate) fn validate_sender_queue_limit(
    msg_id: Option<&str>,
    from_account: &Account,
    attachment_count: usize,
    ephemeral: bool,
    state: &SharedData,
    session: &Session,
) -> Result<(), MediatorError> {
    let send_limit = from_account
        .queue_send_limit
        .unwrap_or(state.limits().queued_send_messages_soft);
    if queue_at_capacity(
        from_account.send_queue_count,
        attachment_count,
        send_limit,
        ephemeral,
    ) {
        count_refusal(GATE_SENDER);
        warn!(
            "Sender DID ({}) has too many messages waiting to be delivered",
            session.did_hash
        );
        return Err(MediatorError::problem(
            61,
            &session.session_id,
            msg_id.map(str::to_string),
            ProblemReportSorter::Error,
            ProblemReportScope::Protocol,
            "limits.queue.sender",
            "Sender has too many messages waiting to be delivered",
            vec![],
            StatusCode::SERVICE_UNAVAILABLE,
        ));
    }
    Ok(())
}

/// Reject the forward when the recipient (next hop) already has too many
/// messages queued. Bypassed for `ephemeral` forwards.
pub(crate) fn validate_recipient_queue_limit(
    msg_id: Option<&str>,
    next_account: &Account,
    next_did_hash: &str,
    attachment_count: usize,
    ephemeral: bool,
    state: &SharedData,
    session: &Session,
) -> Result<(), MediatorError> {
    let recv_limit = next_account
        .queue_receive_limit
        .unwrap_or(state.limits().queued_receive_messages_soft);
    if queue_at_capacity(
        next_account.receive_queue_count,
        attachment_count,
        recv_limit,
        ephemeral,
    ) {
        count_refusal(GATE_RECIPIENT);
        warn!(
            "Next DID ({}) has too many messages waiting to be delivered",
            next_did_hash
        );
        return Err(MediatorError::problem(
            62,
            &session.session_id,
            msg_id.map(str::to_string),
            ProblemReportSorter::Error,
            ProblemReportScope::Protocol,
            "limits.queue.recipient",
            "Recipient (next) has too many messages waiting to be delivered",
            vec![],
            StatusCode::SERVICE_UNAVAILABLE,
        ));
    }
    Ok(())
}

/// Run every queue gate for one `from -> to` store, fetching the two account
/// records the gates read.
///
/// The forward path calls the three gates directly — it has already resolved
/// both accounts and must not re-read them, since resolving the sender there
/// can auto-register it. This wrapper is for the paths that have only hashes:
/// direct delivery and the TSP bridge.
///
/// An account the mediator has never seen resolves to [`Account::default`],
/// whose `queue_*_limit` are `None`, so the gates fall back to the configured
/// defaults exactly as they do for a known account with no override.
pub(crate) async fn validate_store_queue_limits(
    state: &SharedData,
    session: &Session,
    msg_id: Option<&str>,
    from_did_hash: &str,
    to_did_hash: &str,
) -> Result<(), MediatorError> {
    let from_account = state
        .database
        .account_get(from_did_hash)
        .await?
        .unwrap_or_default();
    let to_account = state
        .database
        .account_get(to_did_hash)
        .await?
        .unwrap_or_default();

    // One message, no attachments to account for separately: the direct path
    // stores a single opaque envelope, where a forward may carry several.
    let attachment_count = 1;
    // `ephemeral` is a forward-only concept (live-stream-only delivery that
    // bypasses the queue). A stored message is by definition not ephemeral.
    let ephemeral = false;

    validate_peer_queue_limit(
        msg_id,
        from_did_hash,
        to_did_hash,
        attachment_count,
        ephemeral,
        state,
        session,
    )
    .await?;
    validate_sender_queue_limit(
        msg_id,
        &from_account,
        attachment_count,
        ephemeral,
        state,
        session,
    )?;
    validate_recipient_queue_limit(
        msg_id,
        &to_account,
        to_did_hash,
        attachment_count,
        ephemeral,
        state,
        session,
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queue_at_capacity_logic() {
        // `-1` means unlimited — never at capacity, even when massively over.
        assert!(!queue_at_capacity(1_000, 1_000, -1, false));
        // Ephemeral (live-stream) forwards bypass queue accounting entirely.
        assert!(!queue_at_capacity(1_000, 1_000, 10, true));
        // Strictly under the limit.
        assert!(!queue_at_capacity(5, 4, 10, false)); // 9 < 10
        // At the limit (>=) is rejected.
        assert!(queue_at_capacity(5, 5, 10, false)); // 10 >= 10
        // Over the limit.
        assert!(queue_at_capacity(20, 1, 10, false)); // 21 >= 10
    }
}

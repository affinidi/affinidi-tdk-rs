//! Choosing which queued messages a pickup returns, when several senders are
//! competing for one recipient's attention.
//!
//! # The problem
//!
//! An inbox is an arrival-ordered stream, and a pickup reads it from the head.
//! So a sender that put fifty messages in front of yours is fifty messages you
//! must collect before you see mine — and if you cannot process theirs and do
//! not delete them, you never see mine at all.
//!
//! The per-relationship cap bounds how bad this gets (one sender can hold at
//! most `queued_send_messages_per_peer` of a recipient's inbox), so this is
//! head-of-line delay rather than unbounded starvation. It is still the wrong
//! shape: a recipient's ability to hear from a live peer should not depend on
//! how much a different peer sent first.
//!
//! # What this changes, and what it does not
//!
//! **Order within a sender is preserved exactly.** Each sender's messages are
//! taken oldest-first, and their relative order never changes. What changes is
//! only the *interleaving between* senders, which no ordering guarantee covers:
//! two senders' messages arrive at a mediator in whatever order the network
//! delivered them, and a recipient that depended on that was depending on a
//! coincidence.
//!
//! An anonymous sender is treated as one sender, not as many, because that is
//! what it looks like from the recipient's side — the alternative would let
//! anonymous traffic take a share per message.

use crate::types::messages::MessageListElement;

/// Sender key used when a message records no sender.
///
/// Grouped together deliberately: unattributed traffic gets one share between
/// it, not one share each, which is the conservative reading.
const ANONYMOUS: &str = "";

/// Pick up to `limit` message ids from `window`, taking one from each sender in
/// turn before taking a second from any.
///
/// `window` must be in arrival order — it is the inbox listing — and the result
/// preserves each sender's own order.
///
/// Returns ids rather than elements because the caller fetches bodies
/// separately: the listing is cheap and bodies are not, so selecting first
/// means only the chosen messages are read.
pub fn round_robin_select(window: &[MessageListElement], limit: usize) -> Vec<String> {
    if limit == 0 || window.is_empty() {
        return Vec::new();
    }

    // Group by sender, preserving arrival order within each group. A `Vec` of
    // groups rather than a map so the *groups* also keep a stable order — the
    // sender whose message arrived first gets the first turn, which keeps the
    // result deterministic and keeps a single-sender inbox byte-identical to
    // what a plain range read would have returned.
    let mut senders: Vec<&str> = Vec::new();
    let mut groups: Vec<Vec<&str>> = Vec::new();
    for element in window {
        let sender = element.from_address.as_deref().unwrap_or(ANONYMOUS);
        match senders.iter().position(|s| *s == sender) {
            Some(idx) => groups[idx].push(&element.msg_id),
            None => {
                senders.push(sender);
                groups.push(vec![&element.msg_id]);
            }
        }
    }

    // Deal round by round: one from each sender that still has messages.
    let mut out: Vec<String> = Vec::with_capacity(limit.min(window.len()));
    let mut round = 0usize;
    while out.len() < limit {
        let mut dealt_any = false;
        for group in &groups {
            if let Some(id) = group.get(round) {
                out.push((*id).to_string());
                dealt_any = true;
                if out.len() == limit {
                    return out;
                }
            }
        }
        // Every group is exhausted — the window held fewer than `limit`.
        if !dealt_any {
            break;
        }
        round += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn msg(id: &str, from: Option<&str>) -> MessageListElement {
        MessageListElement {
            msg_id: id.to_string(),
            from_address: from.map(str::to_string),
            ..Default::default()
        }
    }

    /// The case this exists for: one sender's backlog no longer hides another
    /// sender's message behind it.
    #[test]
    fn a_backlog_does_not_hide_the_sender_behind_it() {
        let window = vec![
            msg("a1", Some("alice")),
            msg("a2", Some("alice")),
            msg("a3", Some("alice")),
            msg("a4", Some("alice")),
            msg("b1", Some("bob")),
        ];
        // A plain range read of 2 would return a1, a2 and bob would wait.
        assert_eq!(round_robin_select(&window, 2), vec!["a1", "b1"]);
    }

    /// Order within a sender is never disturbed — that is the guarantee this
    /// must not break, and the one a recipient can legitimately rely on.
    #[test]
    fn each_senders_own_order_is_preserved() {
        let window = vec![
            msg("a1", Some("alice")),
            msg("b1", Some("bob")),
            msg("a2", Some("alice")),
            msg("b2", Some("bob")),
            msg("a3", Some("alice")),
        ];
        let picked = round_robin_select(&window, 5);
        let alice: Vec<&String> = picked.iter().filter(|id| id.starts_with('a')).collect();
        let bob: Vec<&String> = picked.iter().filter(|id| id.starts_with('b')).collect();
        assert_eq!(alice, vec!["a1", "a2", "a3"]);
        assert_eq!(bob, vec!["b1", "b2"]);
    }

    /// With one sender the result is exactly the arrival order, so a recipient
    /// that talks to one peer sees no change at all.
    #[test]
    fn a_single_sender_is_unchanged_arrival_order() {
        let window = vec![
            msg("m1", Some("alice")),
            msg("m2", Some("alice")),
            msg("m3", Some("alice")),
        ];
        assert_eq!(round_robin_select(&window, 3), vec!["m1", "m2", "m3"]);
        assert_eq!(round_robin_select(&window, 2), vec!["m1", "m2"]);
    }

    /// Turn order follows first arrival, so the result is deterministic rather
    /// than depending on a hash map's iteration order.
    #[test]
    fn turn_order_follows_first_arrival() {
        let window = vec![
            msg("b1", Some("bob")),
            msg("a1", Some("alice")),
            msg("b2", Some("bob")),
            msg("a2", Some("alice")),
        ];
        assert_eq!(
            round_robin_select(&window, 4),
            vec!["b1", "a1", "b2", "a2"],
            "bob arrived first, so bob takes the first turn"
        );
    }

    /// An exhausted sender drops out and the rest keep dealing, rather than the
    /// round stalling on the shortest queue.
    #[test]
    fn an_exhausted_sender_drops_out_of_later_rounds() {
        let window = vec![
            msg("a1", Some("alice")),
            msg("b1", Some("bob")),
            msg("a2", Some("alice")),
            msg("a3", Some("alice")),
        ];
        assert_eq!(round_robin_select(&window, 4), vec!["a1", "b1", "a2", "a3"]);
    }

    /// Unattributed traffic gets one share between it, not one share per
    /// message — otherwise anonymous senders would out-compete named ones.
    #[test]
    fn anonymous_senders_share_a_single_turn() {
        let window = vec![
            msg("x1", None),
            msg("x2", None),
            msg("x3", None),
            msg("a1", Some("alice")),
        ];
        assert_eq!(round_robin_select(&window, 2), vec!["x1", "a1"]);
    }

    #[test]
    fn a_limit_beyond_the_window_returns_the_whole_window() {
        let window = vec![msg("a1", Some("alice")), msg("b1", Some("bob"))];
        assert_eq!(round_robin_select(&window, 100), vec!["a1", "b1"]);
    }

    #[test]
    fn empty_inputs_select_nothing() {
        assert!(round_robin_select(&[], 10).is_empty());
        assert!(round_robin_select(&[msg("a1", Some("alice"))], 0).is_empty());
    }
}

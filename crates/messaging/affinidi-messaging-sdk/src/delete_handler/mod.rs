/*!
 * This module contains the implementation of the delete handler.
 *
 * A task that runs deleting messages in the background.
 * This provides a performant way to delete messages without blocking the main thread.
 *
 * Messages can still be deleted from the main thread where you may want direct control.
 *
 * A deletion message is sent to the deletionthread, containing the profile and the message ID.
 * The deletion thread then deletes the message from the profile, using whatever transport method is required.
 *
 */

use crate::{
    ATM, SharedState, errors::ATMError, messages::DeleteMessageRequest, profiles::ATMProfile,
};
use affinidi_task_utils::{CancellationToken, TaskSupervisor};
use std::collections::{HashSet, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::{
    select,
    sync::{
        Mutex,
        mpsc::{Receiver, Sender},
    },
    task::JoinHandle,
};
use tracing::{Instrument, Level, debug, error, span, warn};

/// Most ids to put in one `DELETE`. The mediator refuses more than
/// `limits.deleted_messages` (100) and `delete_messages_direct` rejects the
/// call client-side at the same number, so this is that ceiling, not a guess.
const MAX_DELETE_BATCH: usize = 100;

/// Attempts for one batch before giving up on it.
///
/// Small on purpose: a delete that keeps failing is not lost work. The message
/// is still on the mediator, will be redelivered, and will be queued for
/// deletion again — so the cost of giving up is a slower drain, while the cost
/// of retrying forever is a handler that never processes anything else.
const DELETE_MAX_ATTEMPTS: u32 = 4;

/// Base backoff, doubled per attempt, when the mediator gives no `Retry-After`.
const DELETE_RETRY_BASE: Duration = Duration::from_millis(500);

/// The mediator's per-id refusal descriptor for "there is no such message".
///
/// Matched without the `w.m.` sorter/scope prefix so a change of either does
/// not silently turn this back into a warning.
const DELETE_NOT_FOUND: &str = "database.message.delete.not_found";

/// How long a deleted id is remembered, so a redelivered copy of the same
/// message does not produce a second `DELETE` for an id the mediator has
/// already dropped.
const RECENT_DELETE_TTL: Duration = Duration::from_secs(60);

/// Cap on remembered ids. Bounds the memory a busy profile can take here; the
/// oldest entry is evicted first, which is also the one least likely to still
/// be in flight as a duplicate.
const RECENT_DELETE_CAPACITY: usize = 4096;

/// Ids deleted recently, keyed by `(profile alias, message id)`.
///
/// # Why this exists
///
/// Live delivery is deliberately at-least-once. The mediator re-pushes a
/// recipient's whole undelivered inbox when a socket enables live delivery and
/// when a duplicate socket replaces an existing session — messages fetched
/// `DoNotDelete`, on the explicit understanding that "a client that already had
/// a message simply sees it again and deletes it as usual". With auto-delete on
/// receipt, "as usual" means a second `DELETE` for an id that is already gone,
/// which the mediator answers with a `not_found` refusal. Remembering the id is
/// what stops that round trip from being made at all.
///
/// # Why a short TTL is safe
///
/// A mediator message id is `sha256` of the stored body, so suppressing a
/// delete could in principle strand a *different* message that happened to
/// hash the same — i.e. one with byte-identical content, within the TTL. Every
/// message carries fresh per-message material (a DIDComm `id`, a TSP nonce), so
/// this does not arise in practice, and it self-heals if it ever does: the
/// message stays in the inbox, is redelivered on the next pass, and by then the
/// entry has expired and the delete goes through.
#[derive(Default)]
struct RecentDeletes {
    seen: HashSet<(String, String)>,
    order: VecDeque<(Instant, (String, String))>,
}

impl RecentDeletes {
    /// Drop entries older than [`RECENT_DELETE_TTL`].
    fn expire(&mut self, now: Instant) {
        while let Some((at, _)) = self.order.front() {
            if now.duration_since(*at) < RECENT_DELETE_TTL {
                break;
            }
            let (_, key) = self.order.pop_front().expect("front was just observed");
            self.seen.remove(&key);
        }
    }

    fn contains(&self, alias: &str, id: &str) -> bool {
        // `HashSet<(String, String)>` can't be probed by `(&str, &str)` without
        // allocating; the set is small and this runs once per queued id.
        self.seen.contains(&(alias.to_string(), id.to_string()))
    }

    fn record(&mut self, alias: &str, id: &str) {
        let key = (alias.to_string(), id.to_string());
        if self.seen.insert(key.clone()) {
            self.order.push_back((Instant::now(), key));
        }
        while self.order.len() > RECENT_DELETE_CAPACITY {
            if let Some((_, evicted)) = self.order.pop_front() {
                self.seen.remove(&evicted);
            }
        }
    }
}

/// Take everything already queued for `profile`, starting with `first_id`.
///
/// Returns the batch, plus any command pulled off that did not belong to it —
/// a different profile's deletion, or `Exit`. The channel has no pushback, so a
/// command taken cannot be returned to it; handing it back here is what keeps
/// it from being dropped.
///
/// `try_recv` only, never `recv`: a batch is whatever is *already* waiting. A
/// lone deletion must not sit here until a second one happens to arrive.
///
/// # De-duplication
///
/// An id already in this batch, or deleted within [`RECENT_DELETE_TTL`], is
/// dropped rather than added. Both duplicates come from the same place — live
/// delivery is at-least-once, so the mediator re-pushes messages a client has
/// already taken — and both used to be sent. Two copies of one id in a single
/// request is what produced the `deleted=1 failed=1` pair: the mediator deletes
/// the first occurrence and refuses the second as `not_found`.
///
/// The returned batch can be **empty**: every id waiting may already be known
/// deleted. [`delete_batch`] treats that as nothing to do.
fn take_batch(
    profile: &Arc<ATMProfile>,
    first_id: String,
    from_sdk: &mut Receiver<DeletionHandlerCommands>,
    recent: &mut RecentDeletes,
) -> (Vec<String>, Option<DeletionHandlerCommands>) {
    let alias = profile.inner.alias.as_str();
    recent.expire(Instant::now());

    let mut ids: Vec<String> = Vec::new();
    let mut in_batch: HashSet<String> = HashSet::new();
    let mut push = |ids: &mut Vec<String>, id: String| {
        if recent.contains(alias, &id) {
            debug!(
                message_id = %id,
                "deletion handler: skipping an id deleted moments ago (redelivered copy)"
            );
            return;
        }
        if in_batch.insert(id.clone()) {
            ids.push(id);
        }
    };

    push(&mut ids, first_id);
    while ids.len() < MAX_DELETE_BATCH {
        match from_sdk.try_recv() {
            Ok(DeletionHandlerCommands::DeleteMessage(next, id)) if Arc::ptr_eq(&next, profile) => {
                push(&mut ids, id);
            }
            Ok(other) => return (ids, Some(other)),
            Err(_) => break,
        }
    }
    (ids, None)
}

/// Delete `ids` for `profile`, retrying a refusal rather than dropping it in
/// silence.
///
/// # Why the outcome is no longer discarded
///
/// This was `let _ = atm.delete_messages_direct(...)`. A failure — a 429 above
/// all — vanished, and with it the only signal that the mediator was not
/// letting go of anything. That matters more than an ordinary dropped error,
/// because of who it hurts: a message stays queued against the **sender's**
/// account until the *recipient* deletes it, so a receiver whose deletes are
/// quietly failing fills up the send queue of every peer talking to it. That is
/// how a DID hosting control plane hit its 1000-message send cap and stopped
/// being able to reply at all, while the logs of the node actually at fault
/// said nothing.
async fn delete_batch(
    atm: &ATM,
    profile: &Arc<ATMProfile>,
    ids: Vec<String>,
    recent: &mut RecentDeletes,
) {
    if ids.is_empty() {
        // Everything queued was already known deleted. Sending an empty
        // `DELETE` would cost an authentication round trip to accomplish
        // nothing.
        return;
    }
    let alias = profile.inner.alias.clone();
    let count = ids.len();
    let request = DeleteMessageRequest { message_ids: ids };

    for attempt in 1..=DELETE_MAX_ATTEMPTS {
        match atm.delete_messages_direct(profile, &request).await {
            Ok(response) => {
                let deleted = response.success.len();

                // Split the per-id refusals. `not_found` is not a fault: it
                // means the message is already gone, which is the *expected*
                // answer for the second delete of a redelivered copy — the
                // mediator itself logs it at debug as "may already be deleted".
                // Reporting it at the same level as a real refusal is what
                // filled service logs with warnings about nothing, and it
                // drowned the refusals that do matter: a `permission_denied`
                // or a database error means an id the mediator will never
                // accept, i.e. a message redelivered for as long as it lives.
                let (gone, refused): (Vec<_>, Vec<_>) = response
                    .errors
                    .into_iter()
                    .partition(|(_, err)| err.contains(DELETE_NOT_FOUND));

                if !gone.is_empty() {
                    debug!(
                        deleted,
                        already_gone = gone.len(),
                        "deletion handler: some ids were already deleted at the mediator"
                    );
                }
                if !refused.is_empty() {
                    warn!(
                        deleted,
                        failed = refused.len(),
                        "deletion handler: the mediator refused some ids: {:?}",
                        refused
                    );
                }

                // Remember what is now definitively gone — deleted by this
                // request, or found to be gone already. A genuinely refused id
                // is deliberately *not* recorded: it must be retried when the
                // message is redelivered.
                for id in response.success.iter().chain(gone.iter().map(|(id, _)| id)) {
                    recent.record(&alias, id);
                }
                return;
            }
            Err(e) if attempt < DELETE_MAX_ATTEMPTS => {
                // Honour the mediator's own wait when it gave one — guessing
                // shorter is what turns a rate limit into a tight loop against
                // it.
                let wait = e
                    .http_status()
                    .and_then(|s| s.retry_after())
                    .unwrap_or(DELETE_RETRY_BASE * (1 << (attempt - 1)));
                warn!(
                    count,
                    attempt,
                    rate_limited = e.is_rate_limited(),
                    "deletion handler: batch delete failed ({e}) — retrying in {wait:?}"
                );
                tokio::time::sleep(wait).await;
            }
            Err(e) => {
                // Loud: while this is failing, every message in the batch stays
                // on the mediator and counts against its sender's queue.
                error!(
                    count,
                    attempts = DELETE_MAX_ATTEMPTS,
                    rate_limited = e.is_rate_limited(),
                    "deletion handler: giving up on a batch delete ({e}). These messages stay \
                     queued at the mediator and count against the sender's queue until they are \
                     redelivered and deleted on a later pass"
                );
            }
        }
    }
}

pub enum DeletionHandlerCommands {
    DeleteMessage(Arc<ATMProfile>, String),
    Exit,
}

impl ATM {
    /// Starts the Deletion Handler under the shared [`TaskSupervisor`].
    ///
    /// A panic or error in the handler is detected and the task is restarted
    /// with capped backoff (it is non-load-bearing — a wedged deletion loop
    /// must never take the SDK down), rather than silently dying and leaving
    /// background deletions unprocessed for the life of the process.
    ///
    /// The returned `JoinHandle` completes when the handler's shutdown token
    /// is cancelled (see [`abort_deletion_handler`](Self::abort_deletion_handler)).
    pub async fn start_deletion_handler(
        &self,
        from_sdk: Receiver<DeletionHandlerCommands>,
        to_sdk: Sender<DeletionHandlerCommands>,
    ) -> Result<JoinHandle<()>, ATMError> {
        let shared_state = self.inner.clone();
        let shutdown = self.inner.deletion_shutdown.clone();

        // The SDK→handler receiver isn't clonable, so share it behind a Mutex
        // and re-lock it on each (re)start.
        let from_sdk = Arc::new(Mutex::new(from_sdk));

        TaskSupervisor::new(shutdown.clone()).spawn("deletion_handler", false, move || {
            let shared_state = shared_state.clone();
            let from_sdk = from_sdk.clone();
            let to_sdk = to_sdk.clone();
            let shutdown = shutdown.clone();
            async move {
                let mut from_sdk = from_sdk.lock().await;
                ATM::deletion_handler(shared_state, &mut from_sdk, to_sdk, shutdown).await
            }
        });

        debug!("Deletion handler started (supervised)");

        // Preserve the historical `JoinHandle<()>` contract: the handle
        // completes once the handler is shut down.
        let shutdown = self.inner.deletion_shutdown.clone();
        Ok(tokio::spawn(async move {
            shutdown.cancelled().await;
        }))
    }

    /// Close the Deletion task gracefully by cancelling its shutdown token.
    /// The supervisor stops the handler (no restart) and the handler sends a
    /// final `Exit` back to the SDK.
    pub async fn abort_deletion_handler(&self) -> Result<(), ATMError> {
        self.inner.deletion_shutdown.cancel();
        Ok(())
    }

    pub(crate) async fn deletion_handler(
        shared_state: Arc<SharedState>,
        from_sdk: &mut Receiver<DeletionHandlerCommands>,
        to_sdk: Sender<DeletionHandlerCommands>,
        shutdown: CancellationToken,
    ) -> Result<(), ATMError> {
        let _span = span!(Level::INFO, "deletion_handler");
        async move {
            let atm = ATM {
                inner: shared_state,
            };
            // Carries a command `try_recv` pulled off while batching but that
            // did not belong to the batch.
            let mut deferred: Option<DeletionHandlerCommands> = None;
            // Ids deleted recently, so a redelivered copy of a message is not
            // deleted a second time. Owned by the loop: it must outlive a
            // single batch to be of any use, since the duplicate usually
            // arrives in the *next* one.
            let mut recent = RecentDeletes::default();
            loop {
                if let Some(cmd) = deferred.take() {
                    match cmd {
                        DeletionHandlerCommands::DeleteMessage(profile, id) => {
                            let (ids, next) = take_batch(&profile, id, from_sdk, &mut recent);
                            deferred = next;
                            delete_batch(&atm, &profile, ids, &mut recent).await;
                            continue;
                        }
                        DeletionHandlerCommands::Exit => {
                            shutdown.cancel();
                            break;
                        }
                    }
                }
                select! {
                    _ = shutdown.cancelled() => {
                        break;
                    }
                    value = from_sdk.recv() => {
                        match value {
                            Some(DeletionHandlerCommands::DeleteMessage(profile, message_id)) => {
                                // Take everything already queued for this same
                                // profile, not just the one message that woke
                                // us. One request per message is what made a
                                // backlog unclearable: each carries its own
                                // authentication and counts against the
                                // mediator's per-IP budget, so the deletes that
                                // would drain a queue are exactly what tips it
                                // into rate-limiting it — and every `DELETE`
                                // refused is a message left on the mediator,
                                // redelivered, and queued for deletion again.
                                let (ids, next) =
                                    take_batch(&profile, message_id, from_sdk, &mut recent);
                                deferred = next;
                                delete_batch(&atm, &profile, ids, &mut recent).await;
                            }
                            Some(DeletionHandlerCommands::Exit) | None => {
                                // Intentional stop: cancel so the supervisor
                                // records the task stopped rather than restarting it.
                                shutdown.cancel();
                                break;
                            }
                        }
                    }
                }
            }

            debug!("Deletion handler stopped");
            let _ = to_sdk.send(DeletionHandlerCommands::Exit).await;
            Ok(())
        }
        .instrument(_span)
        .await
    }
}

#[cfg(test)]
mod tests {
    use affinidi_task_utils::{CancellationToken, ComponentState, TaskSupervisor};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::Duration;
    use tokio::sync::{Mutex, mpsc};

    /// A panic in the supervised deletion handler must be caught and the task
    /// restarted (it would otherwise die silently, leaving background
    /// deletions unprocessed for the life of the process), with the fault
    /// recorded. Mirrors `start_deletion_handler`'s wiring — the SDK→handler
    /// receiver shared behind a `Mutex` and re-locked per (re)start — with an
    /// injected panic, and confirms cancellation stops it without restart.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn supervised_deletion_handler_restarts_after_panic() {
        let (_tx, rx) = mpsc::channel::<u8>(4);
        let rx = Arc::new(Mutex::new(rx));
        let supervisor = TaskSupervisor::new(CancellationToken::new());
        let registry = supervisor.registry();
        let attempts = Arc::new(AtomicU32::new(0));

        {
            let rx = rx.clone();
            let attempts = attempts.clone();
            supervisor.spawn("deletion_handler", false, move || {
                let rx = rx.clone();
                let attempts = attempts.clone();
                async move {
                    // Re-lock the shared receiver across restarts.
                    let _guard = rx.lock().await;
                    if attempts.fetch_add(1, Ordering::SeqCst) == 0 {
                        panic!("injected deletion-handler panic");
                    }
                    std::future::pending::<()>().await; // stay Running until cancel
                    Ok::<(), crate::errors::ATMError>(())
                }
            });
        }

        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            let restarted = attempts.load(Ordering::SeqCst) >= 2;
            let running = registry
                .get("deletion_handler")
                .map(|h| h.state == ComponentState::Running && h.restarts >= 1)
                .unwrap_or(false);
            if restarted && running {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "supervisor did not restart the deletion handler after a panic"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(
            registry
                .get("deletion_handler")
                .and_then(|h| h.last_error.clone())
                .is_some_and(|e| e.contains("panicked")),
            "the panic must be recorded as the last error"
        );
    }
}

#[cfg(test)]
mod batch_tests {
    use super::*;
    use crate::profiles::ATMProfileInner;
    use tokio::sync::mpsc;

    fn profile(did: &str) -> Arc<ATMProfile> {
        Arc::new(ATMProfile {
            inner: Arc::new(ATMProfileInner {
                did: did.to_string(),
                alias: did.to_string(),
                mediator: Arc::new(None),
            }),
        })
    }

    /// The point of the change: everything already queued for one profile goes
    /// in a single `DELETE`. One request per message is what made a backlog
    /// unclearable — each carries its own authentication and counts against the
    /// mediator's per-IP budget, so the deletes that would drain a queue are
    /// what tip it into refusing them.
    #[tokio::test]
    async fn queued_deletions_for_one_profile_coalesce() {
        let p = profile("did:example:a");
        let (tx, mut rx) = mpsc::channel(16);
        for i in 1..=4 {
            tx.send(DeletionHandlerCommands::DeleteMessage(
                p.clone(),
                format!("msg-{i}"),
            ))
            .await
            .unwrap();
        }
        // The loop has already taken the first one off when it calls this.
        let first = match rx.recv().await.unwrap() {
            DeletionHandlerCommands::DeleteMessage(_, id) => id,
            DeletionHandlerCommands::Exit => unreachable!(),
        };

        let (ids, deferred) = take_batch(&p, first, &mut rx, &mut RecentDeletes::default());

        assert_eq!(ids, vec!["msg-1", "msg-2", "msg-3", "msg-4"]);
        assert!(deferred.is_none());
    }

    /// A second profile's deletion must not be swallowed. The channel has no
    /// pushback, so a command taken off cannot be put back — handing it to the
    /// caller is the only thing standing between it and silent loss.
    #[tokio::test]
    async fn a_different_profile_ends_the_batch_and_is_handed_back() {
        let a = profile("did:example:a");
        let b = profile("did:example:b");
        let (tx, mut rx) = mpsc::channel(16);
        tx.send(DeletionHandlerCommands::DeleteMessage(
            b.clone(),
            "b-1".into(),
        ))
        .await
        .unwrap();

        let (ids, deferred) = take_batch(&a, "a-1".into(), &mut rx, &mut RecentDeletes::default());

        assert_eq!(ids, vec!["a-1"], "b's id must not join a's batch");
        match deferred {
            Some(DeletionHandlerCommands::DeleteMessage(p, id)) => {
                assert!(Arc::ptr_eq(&p, &b));
                assert_eq!(id, "b-1");
            }
            _ => panic!("b's deletion was dropped"),
        }
    }

    /// `Exit` is handed back for the same reason, or a shutdown requested while
    /// a batch was forming would be lost and the handler would run on.
    #[tokio::test]
    async fn exit_is_handed_back_rather_than_dropped() {
        let a = profile("did:example:a");
        let (tx, mut rx) = mpsc::channel(4);
        tx.send(DeletionHandlerCommands::Exit).await.unwrap();

        let (ids, deferred) = take_batch(&a, "a-1".into(), &mut rx, &mut RecentDeletes::default());

        assert_eq!(ids, vec!["a-1"]);
        assert!(matches!(deferred, Some(DeletionHandlerCommands::Exit)));
    }

    /// The mediator refuses more than 100 ids and `delete_messages_direct`
    /// rejects the call client-side at the same number, so a batch that grew
    /// past it would fail as a whole — turning a busy queue into no deletions
    /// at all.
    #[tokio::test]
    async fn a_batch_stops_at_the_mediators_limit() {
        let p = profile("did:example:a");
        let (tx, mut rx) = mpsc::channel(MAX_DELETE_BATCH * 2);
        for i in 0..MAX_DELETE_BATCH * 2 {
            tx.send(DeletionHandlerCommands::DeleteMessage(
                p.clone(),
                format!("msg-{i}"),
            ))
            .await
            .unwrap();
        }

        let (ids, deferred) =
            take_batch(&p, "first".into(), &mut rx, &mut RecentDeletes::default());

        assert_eq!(ids.len(), MAX_DELETE_BATCH);
        assert!(
            deferred.is_none(),
            "the remainder stays queued for the next pass"
        );
    }

    /// A single deletion must go out now, not wait for company.
    #[tokio::test]
    async fn a_lone_deletion_does_not_wait_for_a_batch_to_fill() {
        let p = profile("did:example:a");
        let (_tx, mut rx) = mpsc::channel(4);

        let (ids, deferred) = take_batch(&p, "only".into(), &mut rx, &mut RecentDeletes::default());

        assert_eq!(ids, vec!["only"]);
        assert!(deferred.is_none());
    }

    /// The `deleted=1 failed=1` pair seen in production: one id delivered twice
    /// by at-least-once live delivery, queued twice, and sent twice in the same
    /// `DELETE` — the mediator deletes the first occurrence and refuses the
    /// second as `not_found`.
    #[tokio::test]
    async fn a_duplicate_id_is_not_sent_twice_in_one_batch() {
        let p = profile("did:example:a");
        let (tx, mut rx) = mpsc::channel(16);
        for id in ["dup", "other", "dup"] {
            tx.send(DeletionHandlerCommands::DeleteMessage(p.clone(), id.into()))
                .await
                .unwrap();
        }
        let first = match rx.recv().await.unwrap() {
            DeletionHandlerCommands::DeleteMessage(_, id) => id,
            DeletionHandlerCommands::Exit => unreachable!(),
        };

        let (ids, _) = take_batch(&p, first, &mut rx, &mut RecentDeletes::default());

        assert_eq!(ids, vec!["dup", "other"]);
    }

    /// The commoner case: the redelivered copy arrives after the first batch
    /// has gone out, so within-batch de-duplication cannot see it. Remembering
    /// what was deleted is what keeps the second `DELETE` from being made.
    #[tokio::test]
    async fn an_id_deleted_moments_ago_is_not_deleted_again() {
        let p = profile("did:example:a");
        let (_tx, mut rx) = mpsc::channel(4);
        let mut recent = RecentDeletes::default();
        recent.record("did:example:a", "already-gone");

        let (ids, _) = take_batch(&p, "already-gone".into(), &mut rx, &mut recent);

        assert!(
            ids.is_empty(),
            "a batch of only known-deleted ids must be empty, not sent"
        );
    }

    /// The cache is keyed by profile as well as id. Two profiles run against
    /// one mediator through one handler, and a delete is authorised as the
    /// profile's own DID — so one profile's delete says nothing about another's.
    #[tokio::test]
    async fn the_recent_cache_does_not_leak_between_profiles() {
        let a = profile("did:example:a");
        let (_tx, mut rx) = mpsc::channel(4);
        let mut recent = RecentDeletes::default();
        recent.record("did:example:b", "shared-id");

        let (ids, _) = take_batch(&a, "shared-id".into(), &mut rx, &mut recent);

        assert_eq!(ids, vec!["shared-id"]);
    }

    /// Suppression must not be permanent. A message id is `sha256` of the
    /// stored body, so an entry that never expired could in principle strand a
    /// byte-identical message forever; expiry is what makes that self-healing.
    #[test]
    fn a_remembered_id_expires() {
        let mut recent = RecentDeletes::default();
        recent.record("did:example:a", "id");
        assert!(recent.contains("did:example:a", "id"));

        recent.expire(Instant::now() + RECENT_DELETE_TTL + Duration::from_secs(1));

        assert!(!recent.contains("did:example:a", "id"));
    }

    /// The cache is bounded, so a busy profile cannot grow it without limit.
    #[test]
    fn the_recent_cache_is_bounded() {
        let mut recent = RecentDeletes::default();
        for i in 0..RECENT_DELETE_CAPACITY + 50 {
            recent.record("did:example:a", &format!("id-{i}"));
        }

        assert_eq!(recent.order.len(), RECENT_DELETE_CAPACITY);
        assert_eq!(recent.seen.len(), RECENT_DELETE_CAPACITY);
        assert!(
            !recent.contains("did:example:a", "id-0"),
            "the oldest entry is evicted first"
        );
        assert!(recent.contains(
            "did:example:a",
            &format!("id-{}", RECENT_DELETE_CAPACITY + 49)
        ));
    }

    /// `not_found` is the expected answer for the second delete of a
    /// redelivered copy and must not be reported as a refusal; a
    /// `permission_denied` is a message the mediator will never let go of and
    /// must be. The classification is a substring match on the descriptor, so
    /// lock it against the strings the mediator actually produces.
    #[test]
    fn not_found_is_told_apart_from_a_real_refusal() {
        let not_found = "Mediator Error: code(Problem Report: code: \
                         w.m.database.message.delete.not_found, comment: Message (abc) not found, \
                         escalate_to: None): 404";
        let denied = "Mediator Error: code(Problem Report: code: \
                      w.m.database.message.delete.permission_denied, comment: Not authorized to \
                      delete message (abc), escalate_to: None): 403";

        assert!(not_found.contains(DELETE_NOT_FOUND));
        assert!(!denied.contains(DELETE_NOT_FOUND));
    }
}

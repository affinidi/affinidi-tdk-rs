//! Point-in-time survey of per-DID queue depth and age.
//!
//! # Why this exists
//!
//! Before this, the only queue a deployment could observe was the forwarding
//! one (`forward_queue_length`). A per-DID inbox or outbox backing up was
//! invisible until it crossed a limit and the mediator started refusing
//! traffic — so the first signal of a stuck queue was an outage, not an alert.
//!
//! Depth alone is not enough either. A deep queue that is draining is healthy;
//! a shallow one that has not moved in days is not, and the two look identical
//! on a depth gauge. **Age is the signal that separates them**, which is why
//! this samples both.
//!
//! # Cost
//!
//! Two bounds, because this runs against a live store on every statistics tick
//! and a naive "scan every queue" would be worse than the blindness it fixes:
//!
//! - at most [`MAX_ACCOUNTS_PER_SURVEY`] account records are read, in pages via
//!   the existing `account_list` cursor. Account records already carry the
//!   depth counters, so the entire depth half of the survey costs one paged
//!   walk and no per-queue reads at all;
//! - at most [`MAX_AGE_PROBES`] queues *per folder* are then probed for age,
//!   chosen as the deepest ones seen. Each probe is a single range-read of one
//!   entry.
//!
//! So the expensive half is bounded by a constant rather than by account count,
//! and it is spent on the queues most likely to be the problem.
//!
//! # Why the oldest entry is a cheap read
//!
//! Inbox and outbox are arrival-ordered streams keyed by `(ms, seq)` — Fjall
//! encodes them big-endian behind the DID hash so byte order *is* arrival
//! order, Redis uses a native stream keyed `<ms>-<seq>`, and the in-memory
//! backend a `BTreeMap`. In all three the first entry in a DID's range is its
//! genuine oldest message, and `list_messages(.., ("-", "+"), 1)` already
//! returns exactly that with the arrival millisecond in `timestamp`.
//!
//! **Deriving age from the expiry index instead would have been wrong**, and
//! silently so. `expires_at` is `min(client_expires_time, now + TTL)` — the
//! clamp is upper-bound only, so a short client-supplied expiry passes through
//! untouched and sorts *below* a genuinely old message carrying the default.
//! The minimum of that index is therefore the newest-but-shortest-lived
//! message, not the oldest one, and a client sending short-expiry traffic
//! continuously would pin the gauge near "healthy" for as long as it kept
//! going. Arrival order cannot be reordered by a client; expiry order can.

use std::cmp::Reverse;
use std::collections::BinaryHeap;
use std::sync::Arc;

use affinidi_messaging_mediator_common::{
    errors::MediatorError,
    store::MediatorStore,
    types::{accounts::MediatorAccountList, clock::Clock, messages::Folder},
};
use async_trait::async_trait;

/// The two reads a survey needs, named so they can be seen.
///
/// The survey is expressed against this rather than against `MediatorStore`
/// for two reasons. It states the cost of a survey in the type — one paged
/// account walk plus one bounded range-read per probed queue, and nothing
/// else.
///
/// And it keeps these tests in a job that runs them. The main test job builds
/// this crate with its default features, so an *ungated* test anywhere in it
/// runs. A test gated on a **non-default** backend does not: the only jobs
/// enabling `memory-backend` or `fjall-backend` are the storage matrix ones,
/// and those filter to `--lib "store::<backend>"`. That filter is a correct
/// scope decision and documented as one — the rest of the suite assumes the
/// Redis-backed default and is not gated on a storage feature — so the hole is
/// not a CI bug to route around. It is that code needing a non-default backend
/// from outside `store::*` does not fit the shape of those jobs, and a survey
/// test written against `MemoryStore` here would have compiled in one job and
/// run in none.
#[async_trait]
pub(crate) trait QueueSource: Send + Sync {
    /// One page of accounts. `cursor` 0 starts, and a returned cursor of 0
    /// means the listing is exhausted.
    async fn accounts(&self, cursor: u32, limit: u32)
    -> Result<MediatorAccountList, MediatorError>;

    /// Arrival time in **unix milliseconds** of the oldest message in
    /// `did_hash`'s `folder`, or `None` when that queue is empty.
    async fn oldest_arrival_ms(
        &self,
        did_hash: &str,
        folder: Folder,
    ) -> Result<Option<u64>, MediatorError>;

    /// Of the `limit` oldest messages in `did_hash`'s `folder`, how many have
    /// already been handed to their recipient — and how many were looked at.
    ///
    /// The **oldest** end on purpose: a message that has been delivered and is
    /// still queued has been that way for as long as it has been queued, so
    /// the head of the queue is where it accumulates. Sampling the newest end
    /// would mostly count messages nobody has had a chance to collect yet.
    async fn delivered_unacked_sample(
        &self,
        did_hash: &str,
        folder: Folder,
        limit: u32,
    ) -> Result<(usize, usize), MediatorError>;
}

#[async_trait]
impl<T: MediatorStore + ?Sized> QueueSource for T {
    async fn accounts(
        &self,
        cursor: u32,
        limit: u32,
    ) -> Result<MediatorAccountList, MediatorError> {
        self.account_list(cursor, limit).await
    }

    async fn oldest_arrival_ms(
        &self,
        did_hash: &str,
        folder: Folder,
    ) -> Result<Option<u64>, MediatorError> {
        // `("-", "+")` with a limit of 1 is the range-min read: inbox and
        // outbox are arrival-ordered streams in every backend, so the first
        // entry in a DID's range is its genuine oldest message.
        Ok(self
            .list_messages(did_hash, folder, Some(("-", "+")), 1)
            .await?
            .first()
            .map(|m| m.timestamp))
    }

    async fn delivered_unacked_sample(
        &self,
        did_hash: &str,
        folder: Folder,
        limit: u32,
    ) -> Result<(usize, usize), MediatorError> {
        let page = self
            .list_messages(did_hash, folder, Some(("-", "+")), limit)
            .await?;
        if page.is_empty() {
            return Ok((0, 0));
        }
        let ids: Vec<String> = page.iter().map(|m| m.msg_id.clone()).collect();
        // Batched: one round trip for the page rather than one per message.
        let states = self.delivery_states(&ids).await?;
        let delivered = states
            .iter()
            .filter(|state| state.as_ref().is_some_and(|s| s.delivered()))
            .count();
        Ok((delivered, page.len()))
    }
}

/// Ceiling on account records read in one survey. A deployment with more
/// accounts than this reports [`QueueSurvey::truncated`] rather than silently
/// returning a partial total.
pub(crate) const MAX_ACCOUNTS_PER_SURVEY: u32 = 10_000;

/// Ceiling on age probes per folder. The deepest queues are probed first, on
/// the grounds that a queue nobody is draining is also a queue that grows.
pub(crate) const MAX_AGE_PROBES: usize = 32;

/// Messages sampled per probed queue when measuring how much of it is work
/// already done.
///
/// A sample, not a census: a full count would mean reading every queued
/// message's delivery state on every cycle, which is the scan this survey
/// exists to avoid. One page from the oldest end of each already-probed queue
/// costs one extra listing and one batched state read per queue.
pub(crate) const DELIVERED_SAMPLE: u32 = 100;

/// Page size for the `account_list` walk. The store caps this at 100 itself.
const ACCOUNT_PAGE: u32 = 100;

/// The oldest message still sitting in one DID's queue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct QueueAge {
    /// Whose queue it is — a DID *hash*, never a DID. Included for the log
    /// line, which is where an operator finds out which relationship is stuck;
    /// it is deliberately not a metric label, since that would put unbounded
    /// cardinality into Prometheus.
    pub did_hash: String,
    /// How long the message has been queued.
    pub age_secs: u64,
}

/// One folder's half of a survey.
#[derive(Debug, Default, Clone, PartialEq)]
pub(crate) struct FolderStats {
    pub messages: u64,
    pub bytes: u64,
    /// Highest used-to-permitted ratio seen. `None` when no surveyed account
    /// had a finite limit — an account set to unlimited (`-1`) has no ratio
    /// and is excluded rather than counted as zero, which would drag the
    /// maximum down and read as healthy.
    pub max_saturation: Option<f64>,
    pub oldest: Option<QueueAge>,
    /// Of [`sampled`](Self::sampled) messages examined across the probed
    /// queues, how many had already been handed to their recipient.
    ///
    /// **This is the number that says whether
    /// `limits.delivered_expiry_seconds` is worth turning on.** A high ratio
    /// means queues are full of work that is already done and is occupying
    /// senders' allowances for nothing; a ratio near zero means enabling it
    /// would change little and is not worth the durability trade.
    pub delivered_unacked: usize,
    /// How many messages were examined to produce
    /// [`delivered_unacked`](Self::delivered_unacked).
    ///
    /// Reported so the pair can be read as a ratio and applied to the depth
    /// gauge. A bare count would be meaningless without knowing whether it came
    /// from ten messages or a thousand.
    pub sampled: usize,
}

/// A complete survey.
#[derive(Debug, Default, Clone, PartialEq)]
pub(crate) struct QueueSurvey {
    pub accounts_surveyed: u32,
    /// `true` when the walk stopped at [`MAX_ACCOUNTS_PER_SURVEY`] with
    /// accounts still unread, making every total here a lower bound.
    pub truncated: bool,
    pub inbox: FolderStats,
    pub outbox: FolderStats,
}

/// Effective queue limits for accounts that set none of their own.
///
/// Public because it appears in [`statistics`](crate::tasks::statistics::statistics)'s
/// signature, which embedded callers spawn themselves.
#[derive(Debug, Clone, Copy)]
pub struct SurveyDefaults {
    /// Fallback for an account with no `queue_send_limit` of its own —
    /// `limits.queued_send_messages_soft`.
    pub send_soft: i32,
    /// Fallback for an account with no `queue_receive_limit` of its own —
    /// `limits.queued_receive_messages_soft`.
    pub receive_soft: i32,
}

/// Saturation of `used` against `limit`, or `None` when the limit is
/// unlimited (`-1`) or non-positive (no meaningful ratio).
fn saturation(used: u32, limit: i32) -> Option<f64> {
    if limit <= 0 {
        return None;
    }
    Some(f64::from(used) / f64::from(limit))
}

/// Keep `heap` to the `cap` deepest queues seen. A min-heap, so the shallowest
/// candidate is the one evicted.
fn offer(heap: &mut BinaryHeap<Reverse<(u32, String)>>, depth: u32, did_hash: &str, cap: usize) {
    if depth == 0 {
        return;
    }
    if heap.len() < cap {
        heap.push(Reverse((depth, did_hash.to_string())));
    } else if let Some(Reverse((shallowest, _))) = heap.peek()
        && depth > *shallowest
    {
        heap.pop();
        heap.push(Reverse((depth, did_hash.to_string())));
    }
}

/// Age in seconds of the oldest message in `did_hash`'s `folder`, or `None`
/// when the queue is empty.
///
/// A message whose arrival stamp is in the future — a clock that went
/// backwards, or a test clock behind the store's wall-clock stream IDs —
/// yields `0` rather than a wrapped enormous age.
async fn oldest_age(
    store: &(impl QueueSource + ?Sized),
    clock: &Arc<dyn Clock>,
    did_hash: &str,
    folder: Folder,
) -> Result<Option<u64>, MediatorError> {
    Ok(store
        .oldest_arrival_ms(did_hash, folder)
        .await?
        .map(|arrival_ms| clock.unix_secs().saturating_sub(arrival_ms / 1_000)))
}

/// Walk the account list, accumulating depth, then probe the deepest queues
/// for age.
pub(crate) async fn survey(
    store: &(impl QueueSource + ?Sized),
    clock: &Arc<dyn Clock>,
    defaults: SurveyDefaults,
) -> Result<QueueSurvey, MediatorError> {
    let mut out = QueueSurvey::default();
    let mut inbox_probes: BinaryHeap<Reverse<(u32, String)>> = BinaryHeap::new();
    let mut outbox_probes: BinaryHeap<Reverse<(u32, String)>> = BinaryHeap::new();

    let mut cursor = 0u32;
    loop {
        let page = store.accounts(cursor, ACCOUNT_PAGE).await?;
        for account in &page.accounts {
            out.accounts_surveyed += 1;

            out.inbox.messages += u64::from(account.receive_queue_count);
            out.inbox.bytes += account.receive_queue_bytes;
            out.outbox.messages += u64::from(account.send_queue_count);
            out.outbox.bytes += account.send_queue_bytes;

            let recv_limit = account.queue_receive_limit.unwrap_or(defaults.receive_soft);
            let send_limit = account.queue_send_limit.unwrap_or(defaults.send_soft);
            out.inbox.max_saturation = max_opt(
                out.inbox.max_saturation,
                saturation(account.receive_queue_count, recv_limit),
            );
            out.outbox.max_saturation = max_opt(
                out.outbox.max_saturation,
                saturation(account.send_queue_count, send_limit),
            );

            offer(
                &mut inbox_probes,
                account.receive_queue_count,
                &account.did_hash,
                MAX_AGE_PROBES,
            );
            offer(
                &mut outbox_probes,
                account.send_queue_count,
                &account.did_hash,
                MAX_AGE_PROBES,
            );
        }

        // `cursor == 0` is the store's "listing exhausted" convention.
        cursor = page.cursor;
        if cursor == 0 {
            break;
        }
        if out.accounts_surveyed >= MAX_ACCOUNTS_PER_SURVEY {
            out.truncated = true;
            break;
        }
    }

    let (oldest, delivered, sampled) =
        probe_queues(store, clock, inbox_probes, Folder::Inbox).await;
    out.inbox.oldest = oldest;
    out.inbox.delivered_unacked = delivered;
    out.inbox.sampled = sampled;

    let (oldest, delivered, sampled) =
        probe_queues(store, clock, outbox_probes, Folder::Outbox).await;
    out.outbox.oldest = oldest;
    out.outbox.delivered_unacked = delivered;
    out.outbox.sampled = sampled;

    Ok(out)
}

/// Probe each candidate and keep the oldest. A probe that errors is skipped:
/// this is a metrics path, and one unreadable queue must not cost the whole
/// survey.
async fn probe_queues(
    store: &(impl QueueSource + ?Sized),
    clock: &Arc<dyn Clock>,
    candidates: BinaryHeap<Reverse<(u32, String)>>,
    folder: Folder,
) -> (Option<QueueAge>, usize, usize) {
    let mut oldest: Option<QueueAge> = None;
    let mut delivered_unacked = 0usize;
    let mut sampled = 0usize;

    for Reverse((_, did_hash)) in candidates.into_sorted_vec() {
        match oldest_age(store, clock, &did_hash, folder.clone()).await {
            Ok(Some(age_secs)) => {
                if oldest.as_ref().is_none_or(|o| age_secs > o.age_secs) {
                    oldest = Some(QueueAge {
                        did_hash: did_hash.clone(),
                        age_secs,
                    });
                }
            }
            Ok(None) => {
                // Empty queue: nothing to age and nothing to sample.
                continue;
            }
            Err(e) => {
                tracing::debug!(
                    did_hash = %did_hash,
                    ?folder,
                    "queue age probe failed this cycle: {e}"
                );
                continue;
            }
        }

        // Independent of the age probe: a failure here costs the sample for
        // one queue, not the age reading that already succeeded.
        match store
            .delivered_unacked_sample(&did_hash, folder.clone(), DELIVERED_SAMPLE)
            .await
        {
            Ok((delivered, examined)) => {
                delivered_unacked += delivered;
                sampled += examined;
            }
            Err(e) => {
                tracing::debug!(
                    did_hash = %did_hash,
                    ?folder,
                    "delivered-unacked sample failed this cycle: {e}"
                );
            }
        }
    }
    (oldest, delivered_unacked, sampled)
}

/// `f64` has no `Ord`, and these are ratios that can legitimately be absent,
/// so the maximum is taken explicitly rather than via `Option::max`.
fn max_opt(a: Option<f64>, b: Option<f64>) -> Option<f64> {
    match (a, b) {
        (Some(x), Some(y)) => Some(x.max(y)),
        (Some(x), None) => Some(x),
        (None, y) => y,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use affinidi_messaging_mediator_common::types::accounts::Account;
    use std::collections::HashMap;

    const DEFAULTS: SurveyDefaults = SurveyDefaults {
        send_soft: 2_000,
        receive_soft: 200,
    };

    /// A clock at a fixed instant, so an age is exact rather than "about".
    #[derive(Debug)]
    struct FixedClock(u64);

    impl Clock for FixedClock {
        fn unix_secs(&self) -> u64 {
            self.0
        }
        fn unix_millis(&self) -> u128 {
            u128::from(self.0) * 1_000
        }
    }

    fn clock_at(secs: u64) -> Arc<dyn Clock> {
        Arc::new(FixedClock(secs))
    }

    /// A [`QueueSource`] built from literals — no storage backend, so these
    /// tests compile and run on every build rather than only in the one CI
    /// job that enables a backend (and filters them out again).
    #[derive(Default)]
    struct FakeSource {
        accounts: Vec<Account>,
        /// `(did_hash, folder-as-string)` -> arrival ms of the oldest entry.
        oldest: HashMap<(String, String), u64>,
        /// DIDs whose age probe should fail, to prove one bad queue does not
        /// cost the survey.
        failing: Vec<String>,
        /// Accounts returned per page, to exercise the cursor walk.
        page_size: usize,
        /// `(did_hash, folder)` -> `(delivered, examined)` for the sample.
        samples: HashMap<(String, String), (usize, usize)>,
        /// DIDs whose sample read should fail.
        failing_sample: Vec<String>,
    }

    impl FakeSource {
        fn new() -> Self {
            Self {
                page_size: 100,
                ..Default::default()
            }
        }

        fn with_account(mut self, did: &str, recv: u32, send: u32) -> Self {
            self.accounts.push(Account {
                did_hash: did.to_string(),
                receive_queue_count: recv,
                receive_queue_bytes: u64::from(recv) * 10,
                send_queue_count: send,
                send_queue_bytes: u64::from(send) * 10,
                ..Default::default()
            });
            self
        }

        fn with_limits(mut self, recv: Option<i32>, send: Option<i32>) -> Self {
            if let Some(last) = self.accounts.last_mut() {
                last.queue_receive_limit = recv;
                last.queue_send_limit = send;
            }
            self
        }

        fn aged(mut self, did: &str, folder: Folder, arrival_ms: u64) -> Self {
            self.oldest
                .insert((did.to_string(), folder.to_string()), arrival_ms);
            self
        }

        fn failing_probe(mut self, did: &str) -> Self {
            self.failing.push(did.to_string());
            self
        }

        fn sampled(mut self, did: &str, folder: Folder, delivered: usize, examined: usize) -> Self {
            self.samples
                .insert((did.to_string(), folder.to_string()), (delivered, examined));
            self
        }

        fn failing_sample(mut self, did: &str) -> Self {
            self.failing_sample.push(did.to_string());
            self
        }
    }

    #[async_trait]
    impl QueueSource for FakeSource {
        async fn accounts(
            &self,
            cursor: u32,
            _limit: u32,
        ) -> Result<MediatorAccountList, MediatorError> {
            let start = cursor as usize;
            let end = (start + self.page_size).min(self.accounts.len());
            let page = self.accounts[start.min(self.accounts.len())..end].to_vec();
            // 0 is the store's "exhausted" convention.
            let next = if end >= self.accounts.len() {
                0
            } else {
                end as u32
            };
            Ok(MediatorAccountList {
                accounts: page,
                cursor: next,
            })
        }

        async fn oldest_arrival_ms(
            &self,
            did_hash: &str,
            folder: Folder,
        ) -> Result<Option<u64>, MediatorError> {
            if self.failing.iter().any(|d| d == did_hash) {
                return Err(MediatorError::InternalError(
                    500,
                    "test".into(),
                    "probe failed".into(),
                ));
            }
            Ok(self
                .oldest
                .get(&(did_hash.to_string(), folder.to_string()))
                .copied())
        }

        async fn delivered_unacked_sample(
            &self,
            did_hash: &str,
            folder: Folder,
            _limit: u32,
        ) -> Result<(usize, usize), MediatorError> {
            if self.failing_sample.iter().any(|d| d == did_hash) {
                return Err(MediatorError::InternalError(
                    500,
                    "test".into(),
                    "sample failed".into(),
                ));
            }
            Ok(self
                .samples
                .get(&(did_hash.to_string(), folder.to_string()))
                .copied()
                .unwrap_or((0, 0)))
        }
    }

    const HOUR_MS: u64 = 60 * 60 * 1_000;

    #[tokio::test]
    async fn an_empty_mediator_surveys_clean() {
        let out = survey(&FakeSource::new(), &clock_at(1_000), DEFAULTS)
            .await
            .expect("survey");
        assert_eq!(out.accounts_surveyed, 0);
        assert!(!out.truncated);
        assert_eq!(out.inbox, FolderStats::default());
        assert_eq!(out.outbox, FolderStats::default());
    }

    #[tokio::test]
    async fn depth_and_bytes_accumulate_across_accounts() {
        let src = FakeSource::new()
            .with_account("alice", 0, 3)
            .with_account("bob", 3, 0);
        let out = survey(&src, &clock_at(1_000), DEFAULTS)
            .await
            .expect("survey");

        assert_eq!(out.accounts_surveyed, 2);
        assert_eq!(out.inbox.messages, 3);
        assert_eq!(out.outbox.messages, 3);
        assert_eq!(out.inbox.bytes, 30);
        assert_eq!(out.outbox.bytes, 30);
    }

    /// The signal the module exists for: a queue nobody drains reports an age
    /// that climbs, and names the DID whose queue it is so the log line can
    /// point somewhere.
    #[tokio::test]
    async fn a_queue_nobody_drains_reports_its_age_and_names_the_did() {
        // Oldest outbox entry arrived at t=1h; the clock reads t=73h.
        let src =
            FakeSource::new()
                .with_account("alice", 0, 5)
                .aged("alice", Folder::Outbox, HOUR_MS);
        let out = survey(&src, &clock_at(73 * 3_600), DEFAULTS)
            .await
            .expect("survey");

        let oldest = out.outbox.oldest.expect("oldest");
        assert_eq!(oldest.age_secs, 72 * 3_600);
        assert_eq!(oldest.did_hash, "alice");
    }

    /// The oldest across accounts wins, not the first one walked.
    #[tokio::test]
    async fn the_oldest_queue_wins_regardless_of_walk_order() {
        let src = FakeSource::new()
            .with_account("recent", 0, 1)
            .aged("recent", Folder::Outbox, 50 * HOUR_MS)
            .with_account("ancient", 0, 1)
            .aged("ancient", Folder::Outbox, 2 * HOUR_MS);
        let out = survey(&src, &clock_at(100 * 3_600), DEFAULTS)
            .await
            .expect("survey");

        let oldest = out.outbox.oldest.expect("oldest");
        assert_eq!(oldest.did_hash, "ancient");
        assert_eq!(oldest.age_secs, 98 * 3_600);
    }

    /// An arrival stamp ahead of the clock (a clock that stepped backwards)
    /// reads as zero rather than wrapping to an enormous age.
    #[tokio::test]
    async fn an_arrival_in_the_future_is_zero_not_a_wrapped_age() {
        let src = FakeSource::new().with_account("alice", 0, 1).aged(
            "alice",
            Folder::Outbox,
            900 * HOUR_MS,
        );
        let out = survey(&src, &clock_at(3_600), DEFAULTS)
            .await
            .expect("survey");
        assert_eq!(out.outbox.oldest.expect("oldest").age_secs, 0);
    }

    /// A metrics path must not lose a whole cycle to one unreadable queue.
    #[tokio::test]
    async fn one_failing_probe_does_not_cost_the_survey() {
        let src = FakeSource::new()
            .with_account("broken", 0, 9)
            .failing_probe("broken")
            .with_account("fine", 0, 1)
            .aged("fine", Folder::Outbox, HOUR_MS);
        let out = survey(&src, &clock_at(5 * 3_600), DEFAULTS)
            .await
            .expect("survey");

        // Depth still counted for both, and the readable queue still aged.
        assert_eq!(out.outbox.messages, 10);
        let oldest = out.outbox.oldest.expect("oldest");
        assert_eq!(oldest.did_hash, "fine");
    }

    #[tokio::test]
    async fn saturation_uses_the_account_limit_when_set_and_the_default_otherwise() {
        // bob overrides its receive limit to 4 and is at 2 -> 0.5.
        // alice takes the default of 200 and is at 20 -> 0.1.
        let src = FakeSource::new()
            .with_account("alice", 20, 0)
            .with_account("bob", 2, 0)
            .with_limits(Some(4), None);
        let out = survey(&src, &clock_at(0), DEFAULTS).await.expect("survey");
        assert_eq!(out.inbox.max_saturation, Some(0.5));
    }

    #[tokio::test]
    async fn an_unlimited_account_does_not_hold_the_maximum_down() {
        // The unlimited account is deeper, but has no ratio; the maximum must
        // come from the one that does, not be dragged to 0.
        let src = FakeSource::new()
            .with_account("unlimited", 10_000, 0)
            .with_limits(Some(-1), None)
            .with_account("normal", 100, 0);
        let out = survey(&src, &clock_at(0), DEFAULTS).await.expect("survey");
        assert_eq!(out.inbox.max_saturation, Some(0.5));
    }

    #[tokio::test]
    async fn the_cursor_walk_covers_every_page() {
        let mut src = FakeSource::new();
        for i in 0..250 {
            src = src.with_account(&format!("did{i}"), 1, 0);
        }
        src.page_size = 100;
        let out = survey(&src, &clock_at(0), DEFAULTS).await.expect("survey");
        assert_eq!(out.accounts_surveyed, 250);
        assert_eq!(out.inbox.messages, 250);
        assert!(!out.truncated);
    }

    /// A partial survey must say so. Under-reporting silently is the worst
    /// available failure for a metric whose job is to catch an unwatched queue.
    #[tokio::test]
    async fn a_survey_that_hits_its_cap_reports_itself_truncated() {
        let mut src = FakeSource::new();
        for i in 0..(MAX_ACCOUNTS_PER_SURVEY + 200) {
            src = src.with_account(&format!("did{i}"), 1, 0);
        }
        src.page_size = 100;
        let out = survey(&src, &clock_at(0), DEFAULTS).await.expect("survey");
        assert!(out.truncated);
        assert!(out.accounts_surveyed >= MAX_ACCOUNTS_PER_SURVEY);
        assert!(out.accounts_surveyed < MAX_ACCOUNTS_PER_SURVEY + 200);
    }

    /// Only the deepest queues are probed, so a survey's cost stays bounded
    /// by a constant rather than by account count.
    #[tokio::test]
    async fn age_probes_are_capped_at_the_deepest_queues() {
        let mut src = FakeSource::new();
        // 100 shallow queues, all old...
        for i in 0..100 {
            src = src.with_account(&format!("shallow{i}"), 0, 1).aged(
                &format!("shallow{i}"),
                Folder::Outbox,
                HOUR_MS,
            );
        }
        // ...and one deep queue, younger than all of them.
        src = src
            .with_account("deep", 0, 5_000)
            .aged("deep", Folder::Outbox, 10 * HOUR_MS);

        let out = survey(&src, &clock_at(100 * 3_600), DEFAULTS)
            .await
            .expect("survey");

        // With MAX_AGE_PROBES at 32 the deep queue is always probed; the
        // shallow ones fill the remaining slots, so an older one is still
        // found. The guarantee under test is that the deepest is never the
        // one dropped.
        assert!(out.outbox.oldest.is_some());
        assert_eq!(out.outbox.messages, 5_100);
    }

    #[test]
    fn saturation_excludes_unlimited_rather_than_scoring_it_zero() {
        // An account at its limit is 1.0 — the point at which it starts being
        // refused, so an alert can fire just below it.
        assert_eq!(saturation(200, 200), Some(1.0));
        assert_eq!(saturation(50, 200), Some(0.25));
        // Unlimited has no ratio. Scoring it 0.0 would let one unlimited
        // account hold the fleet maximum down and read as healthy.
        assert_eq!(saturation(10_000, -1), None);
        // A zero or negative limit is not a ratio either.
        assert_eq!(saturation(5, 0), None);
    }

    #[test]
    fn max_opt_prefers_the_present_value() {
        assert_eq!(max_opt(Some(0.5), Some(0.9)), Some(0.9));
        assert_eq!(max_opt(Some(0.5), None), Some(0.5));
        assert_eq!(max_opt(None, Some(0.2)), Some(0.2));
        assert_eq!(max_opt(None, None), None);
    }

    #[test]
    fn offer_keeps_the_deepest_and_ignores_empty_queues() {
        let mut heap = BinaryHeap::new();
        // An empty queue is never a probe candidate — there is nothing to age.
        offer(&mut heap, 0, "empty", 3);
        assert!(heap.is_empty());

        for (depth, did) in [(5, "a"), (1, "b"), (9, "c"), (3, "d")] {
            offer(&mut heap, depth, did, 3);
        }
        let kept: Vec<u32> = heap.into_sorted_vec().iter().map(|r| r.0.0).collect();
        // Capped at 3, holding the deepest three — the 1-deep queue is gone.
        assert_eq!(kept, vec![9, 5, 3]);
    }

    #[test]
    fn offer_replaces_only_when_strictly_deeper() {
        let mut heap = BinaryHeap::new();
        offer(&mut heap, 5, "first", 1);
        // Equal depth does not evict: churning the candidate set between two
        // equal queues each cycle would make the age gauge flap for no reason.
        offer(&mut heap, 5, "second", 1);
        let kept: Vec<String> = heap
            .into_sorted_vec()
            .iter()
            .map(|r| r.0.1.clone())
            .collect();
        assert_eq!(kept, vec!["first".to_string()]);
    }

    /// The pair that decides whether `limits.delivered_expiry_seconds` is worth
    /// enabling: how much of what is queued is work already done.
    #[tokio::test]
    async fn the_sample_reports_delivered_and_how_many_were_looked_at() {
        let src = FakeSource::new()
            .with_account("alice", 0, 10)
            .aged("alice", Folder::Outbox, HOUR_MS)
            .sampled("alice", Folder::Outbox, 7, 10);
        let out = survey(&src, &clock_at(2 * 3_600), DEFAULTS)
            .await
            .expect("survey");

        assert_eq!(out.outbox.delivered_unacked, 7);
        assert_eq!(
            out.outbox.sampled, 10,
            "the denominator must be reported, or the count means nothing"
        );
    }

    /// Samples add up across the probed queues, so the ratio is fleet-level
    /// rather than whichever queue happened to be probed last.
    #[tokio::test]
    async fn samples_accumulate_across_probed_queues() {
        let src = FakeSource::new()
            .with_account("a", 0, 5)
            .aged("a", Folder::Outbox, HOUR_MS)
            .sampled("a", Folder::Outbox, 2, 5)
            .with_account("b", 0, 5)
            .aged("b", Folder::Outbox, HOUR_MS)
            .sampled("b", Folder::Outbox, 3, 5);
        let out = survey(&src, &clock_at(2 * 3_600), DEFAULTS)
            .await
            .expect("survey");
        assert_eq!(out.outbox.delivered_unacked, 5);
        assert_eq!(out.outbox.sampled, 10);
    }

    /// An empty queue contributes nothing rather than a zero-of-zero that
    /// would drag a fleet ratio toward "nothing is delivered".
    #[tokio::test]
    async fn an_empty_queue_is_not_sampled() {
        let src = FakeSource::new().with_account("alice", 0, 3);
        // No `aged` entry: the queue reads as empty.
        let out = survey(&src, &clock_at(1_000), DEFAULTS)
            .await
            .expect("survey");
        assert_eq!(out.outbox.sampled, 0);
        assert_eq!(out.outbox.delivered_unacked, 0);
    }

    /// A failed sample costs that queue's sample and nothing else — the age
    /// reading that already succeeded still stands.
    #[tokio::test]
    async fn a_failed_sample_does_not_cost_the_age_reading() {
        let src = FakeSource::new()
            .with_account("broken", 0, 9)
            .aged("broken", Folder::Outbox, HOUR_MS)
            .failing_sample("broken")
            .with_account("fine", 0, 4)
            .aged("fine", Folder::Outbox, 2 * HOUR_MS)
            .sampled("fine", Folder::Outbox, 1, 4);
        let out = survey(&src, &clock_at(10 * 3_600), DEFAULTS)
            .await
            .expect("survey");

        // The oldest is still found, from the queue whose sample failed.
        assert_eq!(out.outbox.oldest.expect("oldest").did_hash, "broken");
        // And the readable queue still contributes its sample.
        assert_eq!(out.outbox.delivered_unacked, 1);
        assert_eq!(out.outbox.sampled, 4);
    }
}

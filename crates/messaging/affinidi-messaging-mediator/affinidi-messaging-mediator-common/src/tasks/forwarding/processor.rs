//! Forwarding Processor
//!
//! Reads messages from the FORWARD_Q Redis stream and delivers them to remote mediators.
//! Uses Redis consumer groups for multi-processor coordination:
//! - XREADGROUP BLOCK 0 for event-driven wake-up (no polling)
//! - XACK on successful delivery
//! - XAUTOCLAIM for recovering stale messages from crashed processors
//!
//! Transport selection:
//! - Tracks message rate per endpoint over a sliding window
//! - If rate exceeds threshold: use WebSocket (kept alive with idle timeout)
//! - Otherwise: use REST POST
//!
//! Scheduling:
//! - Endpoints are delivered to concurrently, up to `max_concurrent_endpoints`;
//!   messages for one endpoint go out one at a time, usually in queue order
//!   (a retried message can go after later ones)
//! - Held entries' claims are refreshed; an entry idle for
//!   `reclaim_idle_seconds` is taken over by any processor's reclaim sweep
//! - Each attempt is bounded by `delivery_timeout_seconds`
//!
//! Error handling:
//! - Connection failures: the endpoint backs off exponentially, and the
//!   message is queued again with a not-before at the end of the backoff
//! - Refusal from remote mediator (a 4xx other than 408/425/429): drop the
//!   message at once and send the sender a problem report; it is not retried
//! - An endpoint URL that does not parse, or that the egress policy does not
//!   admit: likewise dropped at once with a problem report of its own

use crate::errors::MediatorError;
use crate::store::{MediatorStore, types::ForwardQueueEntry};
use crate::tasks::forwarding::config::ForwardingConfig;
use crate::tasks::forwarding::observer::{ForwardOutcome, ForwardTransport, ForwardingObserver};
use crate::tasks::forwarding::packer::SystemMessagePacker;
use crate::time::{unix_timestamp_millis, unix_timestamp_secs};
use affinidi_net_guard::{EgressPolicy, GuardedResolver, guarded_dns_resolver};
use futures_util::{SinkExt, StreamExt};
use sha256::digest;
use std::{
    collections::{BTreeMap, HashMap, HashSet, VecDeque},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering as AtomicOrdering},
    },
    time::{Duration, Instant},
};
use tokio::sync::{Mutex, RwLock, mpsc};
use tokio::task::JoinSet;
use tokio_tungstenite::tungstenite;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;

use super::relay_ack::{RELAY_ACK_SUBPROTOCOL, RelayAck, frame_id};
use tracing::{debug, error, info, warn};
use uuid::Uuid;

/// Tracks message rate to a specific endpoint using time-bucketed counters.
///
/// Uses 1-second resolution buckets in a ring buffer instead of per-message
/// timestamps. All operations are O(1) regardless of message throughput.
struct EndpointRateTracker {
    /// Ring buffer of per-second message counts.
    /// Index = unix_seconds % bucket_count.
    buckets: Vec<(u64, u32)>, // (second_timestamp, count)
    /// Number of buckets (= window size in seconds)
    bucket_count: usize,
    /// Total count across all active buckets (cached for O(1) rate queries)
    total: u32,
    /// Window duration in seconds
    window_secs: u64,
}

impl EndpointRateTracker {
    fn new(window_seconds: u64) -> Self {
        let bucket_count = window_seconds.max(1) as usize;
        Self {
            buckets: vec![(0, 0); bucket_count],
            bucket_count,
            total: 0,
            window_secs: window_seconds,
        }
    }

    /// Record N message sends and return current rate per 10 seconds.
    fn record_and_rate(&mut self, count: u32) -> f64 {
        let now_secs = now_epoch_secs();
        self.expire_stale(now_secs);

        let idx = (now_secs as usize) % self.bucket_count;
        let bucket = &mut self.buckets[idx];
        if bucket.0 == now_secs {
            bucket.1 += count;
        } else {
            // New second — reset this bucket
            if bucket.0 > 0 {
                self.total = self.total.saturating_sub(bucket.1);
            }
            *bucket = (now_secs, count);
        }
        self.total += count;

        self.rate_per_10s()
    }

    /// Get current rate per 10 seconds without recording.
    fn current_rate(&mut self) -> f64 {
        self.expire_stale(now_epoch_secs());
        self.rate_per_10s()
    }

    fn rate_per_10s(&self) -> f64 {
        if self.window_secs > 0 {
            (self.total as f64 / self.window_secs as f64) * 10.0
        } else {
            0.0
        }
    }

    /// Expire buckets that are outside the window.
    fn expire_stale(&mut self, now_secs: u64) {
        let cutoff = now_secs.saturating_sub(self.window_secs);
        for bucket in &mut self.buckets {
            if bucket.0 > 0 && bucket.0 <= cutoff {
                self.total = self.total.saturating_sub(bucket.1);
                *bucket = (0, 0);
            }
        }
    }
}

fn now_epoch_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// A forward whose `message` is a TSP message decodes back to raw qb2 bytes for
/// the wire; a DIDComm message does not (and is sent as text, unchanged).
///
/// TSP forwards are queued as `base64url(qb2)` — the CESR qb64 text form of the
/// envelope's count code. A DIDComm JWE/JWS is not valid base64url of such
/// bytes, so this returns `None` and the message is sent verbatim.
///
/// Both framings are accepted. A short `-E##` frame reads `-E` in text and
/// leads with `0xF8`; a long `--E#####` frame reads `--E` and leads with
/// `0xFB`. Spec Rev 3 widened the `-E` count to cover the ciphertext, which
/// makes the long form reachable for any message over roughly 12 KB — and a
/// forwarding path that recognises only the short one drops exactly the large
/// messages it exists to carry.
fn decode_tsp_forward(message: &str) -> Option<Vec<u8>> {
    use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
    if !(message.starts_with("-E") || message.starts_with("--E")) {
        return None;
    }
    BASE64_URL_SAFE_NO_PAD
        .decode(message)
        .ok()
        .filter(|bytes| matches!(bytes.first(), Some(0xF8) | Some(0xFB)))
}

/// How long an endpoint may sit idle before its cached state is reaped.
///
/// Must stay comfortably above both the rate tracker's window (10s) and the
/// retry backoff ceiling (`max_backoff_ms`, 60s by default), so that state
/// still in active use is never dropped out from under a retry.
const ENDPOINT_IDLE_TTL: Duration = Duration::from_secs(300);

/// How long an endpoint is left on REST after a WebSocket attempt failed.
///
/// Long enough that a peer which cannot accept our WebSocket costs one failed
/// connect per window instead of one per message; short enough that a peer
/// which gains the capability (or recovers) is picked up without a restart.
const WS_SUPPRESSION_WINDOW: Duration = Duration::from_secs(300);

/// State for a connection to a remote mediator endpoint
struct EndpointState {
    rate_tracker: EndpointRateTracker,
    last_activity: Instant,
    /// Consecutive failure count for backoff calculation
    consecutive_failures: u32,
    /// Unix ms until which this endpoint is backing off after a failed
    /// attempt; `0` when it is not. While it is, its messages are queued
    /// again for after the window instead of being sent.
    retry_after_ms: u128,
    /// Set when a WebSocket attempt to this endpoint failed; until it elapses,
    /// delivery goes straight to REST.
    ///
    /// An inter-mediator hop is posted anonymously — the relaying mediator
    /// holds no session on the peer — and this mediator's own WebSocket route
    /// requires a bearer token, so a peer running this implementation refuses
    /// the upgrade every time. Without this, crossing the rate threshold buys
    /// a failed connect on *every* message before the REST fallback that was
    /// always going to carry it.
    ws_suppressed_until: Option<Instant>,
}

impl EndpointState {
    fn new(rate_window_seconds: u64) -> Self {
        EndpointState {
            rate_tracker: EndpointRateTracker::new(rate_window_seconds),
            last_activity: Instant::now(),
            consecutive_failures: 0,
            retry_after_ms: 0,
            ws_suppressed_until: None,
        }
    }

    /// Whether a WebSocket attempt is currently suppressed for this endpoint.
    fn ws_suppressed(&self, now: Instant) -> bool {
        self.ws_suppressed_until.is_some_and(|until| now < until)
    }
}

/// Shared HTTP client to avoid creating one per request.
///
/// The client is built on the [`affinidi_net_guard`] egress guard: names are
/// resolved through a fail-closed guarded resolver (any answer that is not
/// globally routable fails the whole name, closing DNS-rebinding) and redirects
/// are refused (a 3xx must not pivot the resolver onto an internal address).
/// The `policy` is retained so each delivery can additionally *vet* the target
/// URL up front — that is the half of the guard that sees IP literals, which
/// reqwest's custom resolver never gets to see (it is bypassed for literal
/// hosts). Together they stop an attacker-advertised service endpoint
/// (`169.254.169.254`, RFC1918, loopback, link-local, or plaintext http/ws)
/// from turning the mediator's forwarding client into an SSRF / open relay.
struct HttpClientPool {
    client: reqwest::Client,
    policy: EgressPolicy,
}

impl HttpClientPool {
    fn new(accept_invalid_certs: bool) -> Result<Self, String> {
        // `danger_accept_invalid_certs` is honoured ONLY in dev/test builds
        // (`test-clock`, where a local peer may present a self-signed cert). A
        // production mediator always validates TLS on the forwarding client —
        // disabling it would let a MITM on a public forwarding hop intercept
        // relayed traffic even behind the egress guard. So the config flag is
        // forced to `false` in a release build.
        #[cfg(not(feature = "test-clock"))]
        let accept_invalid_certs = {
            if accept_invalid_certs {
                warn!(
                    "ignoring danger_accept_invalid_certs: TLS validation is enforced on the \
                     forwarding client in non-test builds"
                );
            }
            false
        };
        if accept_invalid_certs {
            warn!(
                "forwarding HTTP client accepts invalid TLS certificates (test-clock build — NOT for production)"
            );
        }
        // Public-internet posture: https/wss only, globally-routable addresses
        // only, no special-use names. Deployments running an internal mediator
        // mesh (private-range peers) need an operator-configured allow-list —
        // tracked as a follow-up; the secure default is fail-closed.
        #[allow(unused_mut)]
        let mut policy = EgressPolicy::public_internet();
        // Integration-test builds only (`test-clock`, the fixture-mode marker —
        // never a default and never a production build): admit loopback +
        // plaintext http/ws so the test harness can forward between mediators on
        // 127.0.0.1. A release mediator keeps the fail-closed policy above.
        #[cfg(feature = "test-clock")]
        {
            policy = policy.with_dev_loopback(
                affinidi_net_guard::DevLoopback::acknowledge_ssrf_protection_disabled_for_loopback(
                ),
            );
            warn!(
                "forwarding egress guard: loopback/plaintext next hops permitted (test-clock build — NOT for production)"
            );
        }
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .danger_accept_invalid_certs(accept_invalid_certs)
            .pool_max_idle_per_host(10)
            .pool_idle_timeout(Duration::from_secs(90))
            // Following a redirect lets the remote host pivot the resolver onto
            // an arbitrary internal address (SSRF), so refuse.
            .redirect(reqwest::redirect::Policy::none())
            // Never honour ambient proxy env — it would route around the guard.
            .no_proxy()
            // Fail-closed DNS: refuse any name that resolves to a non-routable
            // address, and connect only to the vetted addresses (no rebind).
            .dns_resolver(guarded_dns_resolver(policy.clone()))
            .build()
            .map_err(|e| format!("HTTP client error: {e}"))?;
        Ok(Self { client, policy })
    }
}

/// A pooled WebSocket connection to a remote mediator
struct PooledWebSocket {
    /// The relay socket, unsplit: every relayed frame is answered by a
    /// [`RelayAck`] on the same connection, so this side both writes and reads
    /// and there is no concurrent use to split for.
    stream: tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
    /// When this connection was last used
    last_used: Instant,
}

/// Why a relayed frame did not come back acknowledged.
///
/// The distinction decides what happens to the *connection*: a rejection is the
/// peer answering about one message and leaves the socket usable, while a
/// transport failure means the socket itself is no longer trustworthy. Both
/// fail the message, which is what keeps WebSocket relay as safe as REST.
enum AckFailure {
    /// The peer answered with a negative [`RelayAck`] — the analogue of a
    /// non-2xx REST response.
    Rejected(String),
    /// The frame, or its answer, never made it: send error, closed socket,
    /// or no ack inside the timeout.
    Transport(String),
}

/// Why one relay attempt failed, which decides whether it is worth retrying.
#[derive(Debug)]
enum RelayFailure {
    /// The peer answered and refused the message: a 4xx other than 408, 425
    /// or 429. Sending it again gets the same answer, and a refusal must not
    /// turn into a delivery just because the recipient's policy changed
    /// while we were retrying, so it is dropped at once.
    Refused { status: u16, reason: String },
    /// The peer was unreachable, overloaded or failed: worth another try.
    Retryable(String),
    /// The endpoint URL does not parse, or the egress policy does not admit
    /// it. No request was made, and none ever will be, so it is final.
    NotPermitted(String),
    /// Not sent, because this processor could no longer confirm it holds
    /// the entry. Not a failure of the endpoint: the entry waits, keeping its
    /// retries, and no backoff opens.
    Deferred(String),
}

impl RelayFailure {
    /// Classify a non-2xx answer from the peer.
    fn from_status(status: u16, reason: String) -> Self {
        let transient = matches!(status, 408 | 425 | 429) || !(400..500).contains(&status);
        if transient {
            RelayFailure::Retryable(reason)
        } else {
            RelayFailure::Refused { status, reason }
        }
    }
}

impl std::fmt::Display for RelayFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RelayFailure::Refused { reason, .. }
            | RelayFailure::Retryable(reason)
            | RelayFailure::NotPermitted(reason)
            | RelayFailure::Deferred(reason) => f.write_str(reason),
        }
    }
}

/// Why a forward was dropped undelivered, which picks the sender's report.
#[derive(Clone, Copy, Debug)]
enum ReportReason {
    /// Its retries ran out.
    Abandoned,
    /// The peer refused it with this HTTP status.
    Refused(u16),
    /// The next-hop endpoint is not one this mediator sends to.
    NotPermitted,
}

/// When an entry may first be attempted (unix ms): after the delay its sender
/// asked for, and after the not-before of a retry.
fn due_at_ms(entry: &ForwardQueueEntry) -> u128 {
    let requested = if entry.delay_milli > 0 {
        entry.received_at_ms + entry.delay_milli as u128
    } else {
        0
    };
    requested.max(entry.not_before_ms)
}

/// What a delivery task hands back about its batch.
#[derive(Debug, Default)]
struct BatchOutcome {
    /// Entries it did not attempt — the endpoint was backing off, or claims
    /// were not confirmed lately — to be held until the given unix ms.
    deferred: Vec<(u128, ForwardQueueEntry)>,
    /// When the endpoint's backoff ends, if it is backing off.
    backing_off_until: Option<u128>,
}

/// The processor's claimed-but-unfinished entries, and which endpoint is
/// delivered to next.
///
/// Each held entry is in exactly one of `parked`, `queued`, or a running
/// delivery task (its endpoint is then in `busy`), and its stream id is in
/// `held` until that task finishes or it is forgotten. An endpoint is in
/// `waiting` exactly when it has queued entries and no running task.
///
/// An entry that is not held stays claimed in the store with its idle time
/// running, so the reclaim sweep hands it back later (to this processor or
/// another): that is how a delay beyond the park horizon, and an endpoint's
/// overflow beyond its share, are picked up again.
struct Scheduler {
    max_concurrent: usize,
    batch_size: usize,
    /// Stop reading once this many entries are held.
    max_held: usize,
    /// The most entries one endpoint may hold, so a backlogged endpoint
    /// cannot take the whole budget and stop other endpoints being read.
    max_held_per_endpoint: usize,
    /// The longest an entry is parked for on arrival. Retries never ask for
    /// more than `max_backoff_ms`; a longer requested delay is left to the
    /// reclaim sweep.
    park_horizon_ms: u128,
    held: HashSet<String>,
    held_by_endpoint: HashMap<String, usize>,
    /// Endpoints backing off, and until when (unix ms). One of these holds
    /// at most `batch_size` entries: they cannot be sent until the backoff
    /// ends, so holding more only takes room from other endpoints. The rest
    /// stay claimed in the store for the reclaim sweep.
    backing_off: HashMap<String, u128>,
    /// Entries not yet due, by (due unix ms, arrival order).
    parked: BTreeMap<(u128, u64), ForwardQueueEntry>,
    arrivals: u64,
    queued: HashMap<String, VecDeque<ForwardQueueEntry>>,
    waiting: VecDeque<String>,
    busy: HashSet<String>,
}

impl Scheduler {
    fn new(config: &ForwardingConfig) -> Self {
        let max_concurrent = config.max_concurrent_endpoints.max(1);
        let batch_size = config.batch_size.max(1);
        let max_held = batch_size.saturating_mul(max_concurrent);
        Scheduler {
            max_concurrent,
            batch_size,
            max_held,
            max_held_per_endpoint: (max_held / 2).max(batch_size),
            park_horizon_ms: config.max_backoff_ms.max(config.initial_backoff_ms) as u128,
            held: HashSet::new(),
            held_by_endpoint: HashMap::new(),
            backing_off: HashMap::new(),
            parked: BTreeMap::new(),
            arrivals: 0,
            queued: HashMap::new(),
            waiting: VecDeque::new(),
            busy: HashSet::new(),
        }
    }

    fn has_room(&self) -> bool {
        self.held.len() < self.max_held
    }

    /// How many entries `endpoint_url` may hold now.
    fn endpoint_cap(&self, endpoint_url: &str, now_ms: u128) -> usize {
        if self
            .backing_off
            .get(endpoint_url)
            .is_some_and(|until| *until > now_ms)
        {
            self.batch_size
        } else {
            self.max_held_per_endpoint
        }
    }

    fn held_for(&self, endpoint_url: &str) -> usize {
        self.held_by_endpoint
            .get(endpoint_url)
            .copied()
            .unwrap_or(0)
    }

    /// Forget backoffs that have ended.
    fn prune_backoffs(&mut self, now_ms: u128) {
        self.backing_off.retain(|_, until| *until > now_ms);
    }

    fn held_ids(&self) -> Vec<String> {
        self.held.iter().cloned().collect()
    }

    fn hold(&mut self, entry: &ForwardQueueEntry) {
        self.held.insert(entry.stream_id.clone());
        *self
            .held_by_endpoint
            .entry(entry.endpoint_url.clone())
            .or_default() += 1;
    }

    fn release(&mut self, stream_id: &str, endpoint_url: &str) {
        if !self.held.remove(stream_id) {
            return;
        }
        if let Some(count) = self.held_by_endpoint.get_mut(endpoint_url) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                self.held_by_endpoint.remove(endpoint_url);
            }
        }
    }

    /// Take newly claimed entries: due ones are queued for their endpoint,
    /// the rest parked until due. An entry already held is ignored, so a
    /// repeat (a read and a reclaim of the same entry) is handled once.
    fn accept(&mut self, entries: Vec<ForwardQueueEntry>, now_ms: u128) {
        for entry in entries {
            if self.held.contains(&entry.stream_id) {
                debug!(
                    "FORWARD_Q entry {} is already held; ignoring the repeat",
                    entry.stream_id
                );
                continue;
            }
            if self.held.len() >= self.max_held {
                debug!(
                    "Holding {} entries already; leaving {} for the reclaim sweep",
                    self.held.len(),
                    entry.stream_id
                );
                continue;
            }
            let held_here = self.held_for(&entry.endpoint_url);
            if held_here >= self.endpoint_cap(&entry.endpoint_url, now_ms) {
                debug!(
                    "Endpoint {} already holds {} entries; leaving {} for the reclaim sweep",
                    entry.endpoint_url, held_here, entry.stream_id
                );
                continue;
            }
            let due = due_at_ms(&entry);
            if due <= now_ms {
                self.hold(&entry);
                self.enqueue(entry);
            } else if entry.not_before_ms == 0 && due - now_ms > self.park_horizon_ms {
                debug!(
                    "Forward {} is delayed {}ms, beyond the {}ms park horizon; leaving it for the reclaim sweep",
                    entry.stream_id,
                    due - now_ms,
                    self.park_horizon_ms
                );
            } else {
                // A retry's not-before is at most `max_backoff_ms` ahead when
                // written; the clamp only bites on clock skew between
                // processors, where an early attempt beats holding it forever.
                self.hold(&entry);
                self.park(due.min(now_ms + self.park_horizon_ms), entry);
            }
        }
    }

    fn park(&mut self, until_ms: u128, entry: ForwardQueueEntry) {
        self.arrivals += 1;
        self.parked.insert((until_ms, self.arrivals), entry);
    }

    /// Move parked entries that are now due onto their endpoint's queue.
    fn release_due(&mut self, now_ms: u128) {
        while let Some(first) = self.parked.first_entry() {
            if first.key().0 > now_ms {
                break;
            }
            let entry = first.remove();
            self.enqueue(entry);
        }
    }

    fn enqueue(&mut self, entry: ForwardQueueEntry) {
        let endpoint_url = entry.endpoint_url.clone();
        let queue = self.queued.entry(endpoint_url.clone()).or_default();
        let was_empty = queue.is_empty();
        queue.push_back(entry);
        if was_empty && !self.busy.contains(&endpoint_url) {
            self.waiting.push_back(endpoint_url);
        }
    }

    /// The next endpoint to deliver to and up to `batch_size` of its entries,
    /// marking it busy. Endpoints take turns in the order they became ready.
    fn next_batch(&mut self) -> Option<(String, Vec<ForwardQueueEntry>)> {
        while let Some(endpoint_url) = self.waiting.pop_front() {
            let Some(queue) = self.queued.get_mut(&endpoint_url) else {
                continue;
            };
            let take = queue.len().min(self.batch_size);
            let batch: Vec<_> = queue.drain(..take).collect();
            if queue.is_empty() {
                self.queued.remove(&endpoint_url);
            }
            if batch.is_empty() {
                continue;
            }
            self.busy.insert(endpoint_url.clone());
            return Some((endpoint_url, batch));
        }
        None
    }

    /// A delivery task for `endpoint_url` has finished with `stream_ids`.
    /// Its deferred entries stay held, parked until the given time, up to
    /// what the endpoint may hold; the rest are let go, to come back through
    /// the reclaim sweep.
    fn finished(
        &mut self,
        endpoint_url: &str,
        stream_ids: &[String],
        outcome: BatchOutcome,
        now_ms: u128,
    ) {
        for id in stream_ids {
            self.release(id, endpoint_url);
        }
        match outcome.backing_off_until {
            Some(until) => {
                self.backing_off.insert(endpoint_url.to_string(), until);
            }
            None => {
                self.backing_off.remove(endpoint_url);
            }
        }
        let cap = self.endpoint_cap(endpoint_url, now_ms);
        for (until_ms, entry) in outcome.deferred {
            if self.held_for(endpoint_url) >= cap {
                debug!(
                    "Endpoint {} is at its hold limit; leaving {} for the reclaim sweep",
                    endpoint_url, entry.stream_id
                );
                continue;
            }
            self.hold(&entry);
            self.park(until_ms, entry);
        }
        self.busy.remove(endpoint_url);
        if self.queued.get(endpoint_url).is_some_and(|q| !q.is_empty()) {
            self.waiting.push_back(endpoint_url.to_string());
        }
    }

    /// Stop holding entries this processor no longer has claimed (another
    /// processor took them over). Those parked or queued are dropped here;
    /// the ids of those inside a running delivery task are returned, for the
    /// task to skip.
    fn forget(&mut self, stream_ids: &[String]) -> Vec<String> {
        let lost: HashSet<&str> = stream_ids.iter().map(String::as_str).collect();
        let mut dropped: Vec<(String, String)> = Vec::new();
        self.parked.retain(|_, entry| {
            let keep = !lost.contains(entry.stream_id.as_str());
            if !keep {
                dropped.push((entry.stream_id.clone(), entry.endpoint_url.clone()));
            }
            keep
        });
        for queue in self.queued.values_mut() {
            queue.retain(|entry| {
                let keep = !lost.contains(entry.stream_id.as_str());
                if !keep {
                    dropped.push((entry.stream_id.clone(), entry.endpoint_url.clone()));
                }
                keep
            });
        }
        self.queued.retain(|_, queue| !queue.is_empty());
        self.waiting
            .retain(|endpoint_url| self.queued.contains_key(endpoint_url));
        for (id, endpoint_url) in &dropped {
            self.release(id, endpoint_url);
        }
        stream_ids
            .iter()
            .filter(|id| self.held.contains(id.as_str()))
            .cloned()
            .collect()
    }

    fn next_due_ms(&self) -> Option<u128> {
        self.parked.keys().next().map(|(due, _)| *due)
    }
}

/// The forwarding processor that reads from FORWARD_Q and delivers to remote mediators
#[derive(Clone)]
pub struct ForwardingProcessor {
    config: ForwardingConfig,
    database: Arc<dyn MediatorStore>,
    consumer_name: String,
    endpoints: Arc<RwLock<HashMap<String, EndpointState>>>,
    http_pool: Arc<HttpClientPool>,
    /// WebSocket connection pool keyed by endpoint URL
    ws_pool: Arc<Mutex<HashMap<String, PooledWebSocket>>>,
    /// How mediator-authored messages (the forwarding-failure problem report)
    /// are encrypted for their recipient. `None` when the host has no mediator
    /// identity to pack with — see [`SystemMessagePacker`].
    packer: Option<Arc<dyn SystemMessagePacker>>,
    /// Told the fate of every relay attempt — see [`ForwardingObserver`].
    observer: Option<Arc<dyn ForwardingObserver>>,
    /// Entries handed to a delivery task that another processor has since
    /// taken over: the task skips them.
    revoked: Arc<std::sync::Mutex<HashSet<String>>>,
    /// Unix ms when this processor's claims were last confirmed by a
    /// successful refresh; see [`Self::claims_current`].
    claims_confirmed_at_ms: Arc<AtomicU64>,
    /// Test-only: while set, claim refreshes fail as if the store were
    /// unreachable.
    #[cfg(feature = "test-clock")]
    refresh_fault: Option<Arc<std::sync::atomic::AtomicBool>>,
}

impl ForwardingProcessor {
    pub fn new(
        config: ForwardingConfig,
        database: Arc<dyn MediatorStore>,
    ) -> Result<Self, crate::errors::MediatorError> {
        let consumer_name = format!("processor_{}", Uuid::new_v4());
        info!(
            "ForwardingProcessor created: consumer={}, group={}",
            consumer_name, config.consumer_group
        );
        let http_pool = Arc::new(HttpClientPool::new(config.accept_invalid_certs).map_err(
            |e| {
                crate::errors::MediatorError::InternalError(
                    17,
                    "forwarding".into(),
                    format!("Failed to create HTTP client pool: {e}"),
                )
            },
        )?);
        Ok(Self {
            config,
            database,
            consumer_name,
            endpoints: Arc::new(RwLock::new(HashMap::new())),
            http_pool,
            ws_pool: Arc::new(Mutex::new(HashMap::new())),
            packer: None,
            observer: None,
            revoked: Arc::new(std::sync::Mutex::new(HashSet::new())),
            claims_confirmed_at_ms: Arc::new(AtomicU64::new(0)),
            #[cfg(feature = "test-clock")]
            refresh_fault: None,
        })
    }

    /// Supply the mediator identity that mediator-authored messages are packed
    /// under. Without it the processor can still forward — only the
    /// forwarding-failure problem report needs to be encrypted — so this is a
    /// post-construction opt-in rather than a `new` argument, keeping the
    /// standalone `forwarding_processor` binary (which has no mediator DID or
    /// secrets in its config) compiling and running unchanged.
    pub fn with_system_packer(mut self, packer: Arc<dyn SystemMessagePacker>) -> Self {
        self.packer = Some(packer);
        self
    }

    /// Test-only: make claim refreshes fail while `fault` is set, to exercise
    /// what the processor does when it cannot confirm its claims.
    #[cfg(feature = "test-clock")]
    pub fn with_claim_refresh_fault(mut self, fault: Arc<std::sync::atomic::AtomicBool>) -> Self {
        self.refresh_fault = Some(fault);
        self
    }

    /// Report each relay attempt's outcome to `observer` (the mediator's traffic
    /// monitor). Optional for the same reason as
    /// [`with_system_packer`](Self::with_system_packer).
    pub fn with_observer(mut self, observer: Arc<dyn ForwardingObserver>) -> Self {
        self.observer = Some(observer);
        self
    }

    fn observe(&self, entry: &ForwardQueueEntry, outcome: ForwardOutcome) {
        if let Some(observer) = &self.observer {
            observer.observe(entry, outcome);
        }
    }

    /// Start the forwarding processor. This runs indefinitely.
    ///
    /// Reading and delivering are decoupled. A reader task claims batches from
    /// the queue, and periodically reclaims entries left idle (a crashed or
    /// restarted processor's, a long requested delay, an endpoint's
    /// overflow). This loop sorts each entry into "ready now" or "parked until
    /// its not-before", and hands ready entries to one delivery task per
    /// endpoint, at most `max_concurrent_endpoints` at a time. A slow or
    /// failing endpoint therefore occupies one slot, and its backoff is a
    /// not-before on its own entries rather than a pause of the whole loop.
    ///
    /// Every claimed entry is held in exactly one place — parked, queued for
    /// its endpoint, or inside that endpoint's delivery task — and only the
    /// delivery task acks or deletes it, once. An endpoint never has two
    /// delivery tasks at a time, which keeps its pooled WebSocket single-user.
    ///
    /// Held entries have their claims refreshed every quarter of
    /// `reclaim_idle_seconds`, so another processor's reclaim sweep (which only
    /// takes entries idle that long) does not take them. Entries arriving from
    /// the reader are checked the same way before they are held, and any the
    /// refresh finds taken over are dropped here or skipped by their delivery
    /// task: an entry is delivered by whichever processor holds its claim.
    ///
    /// The background tasks live as long as this call: dropping or aborting
    /// it stops them.
    pub async fn start(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // The consumer group is created lazily on the first
        // `forward_queue_read` call; no explicit ensure step needed.
        info!(
            "ForwardingProcessor started: consumer={}, group={}, batch_size={}, max_concurrent_endpoints={}, delivery_timeout={}s, reclaim_idle={}s, ws_threshold={} msgs/10s, ws_idle_timeout={}s",
            self.consumer_name,
            self.config.consumer_group,
            self.config.batch_size,
            self.config.max_concurrent_endpoints,
            self.config.delivery_timeout_seconds,
            self.config.reclaim_idle_seconds,
            self.config.ws_threshold_msgs_per_10s,
            self.config.ws_idle_timeout_seconds
        );

        // `report_errors` promises the sender an explanation when we give up on
        // their forward, and we can only keep that promise if we can encrypt it
        // as ourselves. Say so at startup rather than at the first abandonment,
        // which may be weeks later and buried in a batch of delivery failures.
        if self.config.report_errors && self.packer.is_none() {
            warn!(
                "report_errors is enabled but no system message packer is configured — \
                 abandoned forwards will be logged here and NOT reported to their senders"
            );
        }

        // Whatever a previous run of this processor held is no longer held:
        // its claims go idle and the reclaim sweep hands them back.
        self.revoked
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
        // Nothing is held yet, so there is nothing unconfirmed.
        self.claims_confirmed_at_ms
            .store(unix_timestamp_millis() as u64, AtomicOrdering::Release);

        if self.config.delivery_timeout_seconds.saturating_mul(2) > self.config.reclaim_idle_seconds
        {
            warn!(
                "reclaim_idle_seconds ({}) is less than twice delivery_timeout_seconds ({}): a send \
                 under way when this processor's claims stop being confirmed can outlast its \
                 claim, so another processor may take the entry over and send it again",
                self.config.reclaim_idle_seconds, self.config.delivery_timeout_seconds
            );
        }

        if self.config.delivery_timeout_seconds < 60 {
            let ws = ws_limits_for(Duration::from_secs(
                self.config.delivery_timeout_seconds.max(1),
            ));
            warn!(
                "delivery_timeout_seconds ({}) is below 60: a WebSocket relay attempt is cut to                  {} ms to leave time for the REST fallback, and the REST request may itself be                  cut short of its 30 s",
                self.config.delivery_timeout_seconds,
                ws.attempt.as_millis()
            );
        }

        let reclaim_idle = Duration::from_secs(self.config.reclaim_idle_seconds.max(1));
        let refresh_every = reclaim_idle / 4;
        let sweep_every = reclaim_idle / 2;

        // Background tasks, aborted when this call returns or is dropped.
        let mut background: JoinSet<()> = JoinSet::new();

        // Clean up idle WebSocket connections and idle per-endpoint state.
        let ws_pool = self.ws_pool.clone();
        let endpoints = self.endpoints.clone();
        let idle_timeout = Duration::from_secs(self.config.ws_idle_timeout_seconds);
        background.spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(10)).await;
                let mut pool = ws_pool.lock().await;
                let now = Instant::now();
                let before = pool.len();
                pool.retain(|endpoint, ws| {
                    if now.duration_since(ws.last_used) > idle_timeout {
                        info!(
                            "Closing idle WebSocket to {} (idle {}s)",
                            endpoint,
                            now.duration_since(ws.last_used).as_secs()
                        );
                        // Dropping the writer closes the connection
                        false
                    } else {
                        true
                    }
                });
                let closed = before - pool.len();
                if closed > 0 {
                    debug!(
                        "Closed {} idle WebSocket connections ({} remaining)",
                        closed,
                        pool.len()
                    );
                }
                drop(pool);

                // `endpoints` is keyed by the service endpoint URL out of a
                // peer's DID Doc, so its key space is remote-controlled and it
                // would otherwise grow for the process lifetime. Entries only
                // cache a rate window and a failure count, both of which are
                // meaningless once an endpoint has been silent this long, so
                // dropping them just means the next forward starts fresh.
                let mut endpoints = endpoints.write().await;
                let before = endpoints.len();
                endpoints.retain(|_, state| {
                    now.duration_since(state.last_activity) <= ENDPOINT_IDLE_TTL
                });
                let reaped = before - endpoints.len();
                if reaped > 0 {
                    debug!(
                        "Reaped {} idle forwarding endpoint(s) ({} remaining)",
                        reaped,
                        endpoints.len()
                    );
                }
            }
        });

        // The reader: new entries, and every `sweep_every` the entries left
        // idle for `reclaim_idle`. It runs in its own task because a read is
        // not cancel-safe: a Redis XREADGROUP abandoned mid-flight still
        // claims what it read. The channel holds one batch, so the reader
        // stays at most one batch ahead of what this loop has accepted.
        let (batch_tx, mut batch_rx) = mpsc::channel::<Vec<ForwardQueueEntry>>(1);
        // Set while this processor holds all it may; the reader then skips
        // reclaim sweeps.
        let saturated = Arc::new(std::sync::atomic::AtomicBool::new(false));
        {
            let database = self.database.clone();
            let group = self.config.consumer_group.clone();
            let consumer = self.consumer_name.clone();
            let batch_size = self.config.batch_size.max(1);
            let block = sweep_every.min(Duration::from_secs(5));
            let claims_confirmed_at_ms = self.claims_confirmed_at_ms.clone();
            let unconfirmed_after_ms = reclaim_idle.as_millis() / 2;
            let claims_unconfirmed = move || {
                let confirmed = claims_confirmed_at_ms.load(AtomicOrdering::Acquire) as u128;
                unix_timestamp_millis().saturating_sub(confirmed) > unconfirmed_after_ms
            };
            let saturated = saturated.clone();
            background.spawn(async move {
                let mut next_sweep = Instant::now() + sweep_every;
                loop {
                    // While this processor cannot confirm its claims it takes
                    // on nothing new. Its sweep in particular would re-claim
                    // the very entries it cannot use, resetting their idle
                    // time and keeping every other processor off them.
                    if claims_unconfirmed() {
                        tokio::time::sleep(refresh_every).await;
                        continue;
                    }
                    // A processor holding all it may hold skips the sweep:
                    // what it reclaimed it could not hold, and reclaiming
                    // resets the entries' idle time, keeping others off them.
                    if Instant::now() >= next_sweep && !saturated.load(AtomicOrdering::Acquire) {
                        next_sweep = Instant::now() + sweep_every;
                        // Follow the cursor over the whole pending list. A page
                        // can come back empty because it covered only entries
                        // that are held and refreshed; idle ones may lie
                        // beyond it.
                        let mut cursor = "0-0".to_string();
                        loop {
                            // Checked before every page, since sending one
                            // can wait on this loop.
                            if claims_unconfirmed() || saturated.load(AtomicOrdering::Acquire) {
                                break;
                            }
                            match database
                                .forward_queue_autoclaim(
                                    &group,
                                    &consumer,
                                    reclaim_idle,
                                    batch_size,
                                    &cursor,
                                )
                                .await
                            {
                                Ok(page) => {
                                    if !page.entries.is_empty() {
                                        debug!(
                                            "Reclaimed {} idle forwarding entries",
                                            page.entries.len()
                                        );
                                        if batch_tx.send(page.entries).await.is_err() {
                                            return;
                                        }
                                    }
                                    match page.next_cursor {
                                        Some(next) => cursor = next,
                                        None => break,
                                    }
                                }
                                Err(e) => {
                                    warn!("Error reclaiming idle FORWARD_Q entries: {e}");
                                    break;
                                }
                            }
                        }
                    }
                    match database
                        .forward_queue_read(&group, &consumer, batch_size, block)
                        .await
                    {
                        Ok(entries) if entries.is_empty() => {}
                        Ok(entries) => {
                            if batch_tx.send(entries).await.is_err() {
                                return;
                            }
                        }
                        Err(e) => {
                            error!("Error reading from FORWARD_Q: {}. Retrying in 1s...", e);
                            tokio::time::sleep(Duration::from_secs(1)).await;
                        }
                    }
                }
            });
        }

        let this = Arc::new(self.clone());
        let mut scheduler = Scheduler::new(&self.config);
        let mut deliveries: JoinSet<BatchOutcome> = JoinSet::new();
        // Which endpoint, and which entries, each delivery task holds.
        let mut running: HashMap<tokio::task::Id, (String, Vec<String>)> = HashMap::new();
        let mut refresh = tokio::time::interval(refresh_every);
        refresh.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            let now_ms = unix_timestamp_millis();
            scheduler.release_due(now_ms);

            while deliveries.len() < scheduler.max_concurrent {
                let Some((endpoint_url, batch)) = scheduler.next_batch() else {
                    break;
                };
                let ids = batch.iter().map(|m| m.stream_id.clone()).collect();
                let processor = this.clone();
                let task_endpoint = endpoint_url.clone();
                let handle = deliveries.spawn(async move {
                    processor
                        .process_endpoint_batch(&task_endpoint, batch)
                        .await
                });
                running.insert(handle.id(), (endpoint_url, ids));
            }

            let wake_in = scheduler
                .next_due_ms()
                .map(|due| Duration::from_millis(due.saturating_sub(now_ms) as u64))
                .unwrap_or(Duration::from_secs(3600));
            let can_read = scheduler.has_room();
            saturated.store(!can_read, AtomicOrdering::Release);

            tokio::select! {
                Some(done) = deliveries.join_next_with_id(), if !deliveries.is_empty() => {
                    let (id, mut outcome) = match done {
                        Ok((id, outcome)) => (id, outcome),
                        Err(e) => {
                            // The entries stay claimed in the store, as they
                            // would after a crash: no longer refreshed, they
                            // go idle and the reclaim sweep hands them back.
                            error!("Forwarding delivery task failed: {e}");
                            (e.id(), BatchOutcome::default())
                        }
                    };
                    if let Some((endpoint_url, ids)) = running.remove(&id) {
                        // Entries taken over while the task ran are not held
                        // again, whatever the task returned.
                        let mut revoked = self.revoked.lock().unwrap_or_else(|e| e.into_inner());
                        outcome
                            .deferred
                            .retain(|(_, entry)| !revoked.contains(&entry.stream_id));
                        for id in &ids {
                            revoked.remove(id);
                        }
                        drop(revoked);
                        scheduler.finished(&endpoint_url, &ids, outcome, unix_timestamp_millis());
                    }
                }
                batch = batch_rx.recv(), if can_read => {
                    let Some(entries) = batch else {
                        return Err("forwarding queue reader stopped".into());
                    };
                    debug!("Read {} entries from FORWARD_Q", entries.len());
                    // The batch may have waited in the channel; hold only what
                    // is still ours, so nothing another processor took over in
                    // the meantime is delivered twice.
                    let ids: Vec<&str> = entries.iter().map(|e| e.stream_id.as_str()).collect();
                    match self.refresh_claims(&ids).await {
                        Ok(lost) => {
                            let lost: HashSet<String> = lost.into_iter().collect();
                            let entries = entries
                                .into_iter()
                                .filter(|e| !lost.contains(&e.stream_id))
                                .collect();
                            scheduler.accept(entries, unix_timestamp_millis());
                        }
                        Err(e) => {
                            // Not held, so they go idle and come back through
                            // the reclaim sweep.
                            warn!("Could not confirm claims on {} FORWARD_Q entries; leaving them for the reclaim sweep: {e}", ids.len());
                        }
                    }
                }
                _ = refresh.tick() => {
                    // Everything held, including entries a delivery task is
                    // sending right now: a send may outlast `reclaim_idle`.
                    let started = unix_timestamp_millis();
                    let held = scheduler.held_ids();
                    let ids: Vec<&str> = held.iter().map(String::as_str).collect();
                    match self.refresh_claims(&ids).await {
                        Ok(lost) => {
                            self.claims_confirmed_at_ms
                                .store(started as u64, AtomicOrdering::Release);
                            if !lost.is_empty() {
                                // Usually entries a task has just finished
                                // with; anything else was taken over.
                                let in_flight = scheduler.forget(&lost);
                                self.revoked
                                    .lock()
                                    .unwrap_or_else(|e| e.into_inner())
                                    .extend(in_flight);
                            }
                        }
                        // Delivery tasks stop sending once the last good
                        // refresh is too old (see `claims_current`).
                        Err(e) => warn!("Could not refresh claims on held FORWARD_Q entries: {e}"),
                    }
                    scheduler.prune_backoffs(started);
                }
                _ = tokio::time::sleep(wake_in) => {}
            }
        }
    }

    /// Refresh this processor's claims on `stream_ids`; see
    /// [`MediatorStore::forward_queue_refresh_claims`].
    async fn refresh_claims(&self, stream_ids: &[&str]) -> Result<Vec<String>, MediatorError> {
        #[cfg(feature = "test-clock")]
        if self
            .refresh_fault
            .as_ref()
            .is_some_and(|fault| fault.load(AtomicOrdering::Acquire))
        {
            return Err(MediatorError::DatabaseError(
                96,
                "forwarding".into(),
                "claim refresh failed (injected)".into(),
            ));
        }
        if stream_ids.is_empty() {
            return Ok(Vec::new());
        }
        self.database
            .forward_queue_refresh_claims(
                &self.config.consumer_group,
                &self.consumer_name,
                stream_ids,
            )
            .await
    }

    /// Whether this processor's claims were confirmed recently enough to act
    /// on them. Refreshes run every quarter of `reclaim_idle_seconds`; if
    /// none has succeeded for half of it, another processor may be about to
    /// take the entries over, so nothing more is sent until one does. A send
    /// already under way when refreshes start failing finishes, and its entry
    /// is then finished only if still ours: such a message can be delivered
    /// twice, never lost.
    fn claims_current(&self) -> bool {
        let confirmed = self.claims_confirmed_at_ms.load(AtomicOrdering::Acquire) as u128;
        let limit = (self.config.reclaim_idle_seconds.max(1) as u128) * 1000 / 2;
        unix_timestamp_millis().saturating_sub(confirmed) <= limit
    }

    /// How long an entry held back for unconfirmed claims waits before it is
    /// looked at again: one refresh interval.
    fn unconfirmed_retry_ms(&self) -> u128 {
        (self.config.reclaim_idle_seconds.max(1) as u128) * 1000 / 4
    }

    /// Finish with `msg` if this processor still holds it (see
    /// [`MediatorStore::forward_queue_finish`]). `Ok(false)` means another
    /// processor has it now and decides its fate.
    async fn finish(
        &self,
        msg: &ForwardQueueEntry,
        requeue: Option<&ForwardQueueEntry>,
    ) -> Result<bool, MediatorError> {
        let finished = self
            .database
            .forward_queue_finish(
                &self.config.consumer_group,
                &self.consumer_name,
                &msg.stream_id,
                requeue,
            )
            .await?;
        if !finished {
            debug!(
                "FORWARD_Q entry {} is no longer held by this processor; leaving it to its holder",
                msg.stream_id
            );
        }
        Ok(finished)
    }

    /// Whether another processor has taken this entry over since it was
    /// handed to a delivery task.
    fn is_revoked(&self, stream_id: &str) -> bool {
        self.revoked
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains(stream_id)
    }

    /// Deliver a batch of entries, all due now, for one endpoint.
    ///
    /// Messages go out one at a time. Each attempted message ends in exactly
    /// one queue update, made as soon as its outcome is known: acked and
    /// deleted (delivered, refused, not permitted, expired or abandoned), or
    /// replaced by a retry entry carrying a not-before and then deleted. Once
    /// an attempt fails the endpoint backs off, and the rest of the batch is
    /// returned unattempted, to be held until the backoff ends — without
    /// spending their retries, since nothing was sent. So a failing endpoint
    /// costs one attempt per backoff window, not one per message.
    async fn process_endpoint_batch(
        &self,
        endpoint_url: &str,
        messages: Vec<ForwardQueueEntry>,
    ) -> BatchOutcome {
        let msg_count = messages.len();
        debug!(
            "Processing {} messages for endpoint: {}",
            msg_count, endpoint_url
        );

        // Check if any messages have expired
        let now_secs = unix_timestamp_secs();

        let (ready, expired): (Vec<_>, Vec<_>) =
            messages.into_iter().partition(|m| m.expires_at > now_secs);

        // Drop expired messages that are still ours.
        for msg in &expired {
            if self.is_revoked(&msg.stream_id) {
                continue;
            }
            match self.finish(msg, None).await {
                Ok(true) => {
                    info!(
                        "FORWARD_EXPIRED: to_did_hash={} from_did_hash={} endpoint={}",
                        msg.to_did_hash, msg.from_did_hash, endpoint_url
                    );
                    self.observe(msg, ForwardOutcome::Expired);
                }
                Ok(false) => {}
                Err(e) => warn!("Failed to drop expired entry {}: {e}", msg.stream_id),
            }
        }

        let mut outcome = BatchOutcome::default();
        if ready.is_empty() {
            return outcome;
        }

        // Decide transport from the rate so far.
        let use_websocket = {
            let mut endpoints = self.endpoints.write().await;
            let state = endpoints
                .entry(endpoint_url.to_string())
                .or_insert_with(|| EndpointState::new(self.config.rate_window_seconds));

            let now = Instant::now();
            state.last_activity = now;

            let rate = state.rate_tracker.current_rate();
            let suppressed = state.ws_suppressed(now);
            debug!(
                "Endpoint {} rate: {:.2} msgs/10s (threshold: {}, ws_suppressed: {})",
                endpoint_url, rate, self.config.ws_threshold_msgs_per_10s, suppressed
            );
            rate >= self.config.ws_threshold_msgs_per_10s as f64 && !suppressed
        };

        // Deliver messages
        let transport = if use_websocket { "WebSocket" } else { "REST" };
        let relayed = ForwardOutcome::Relayed {
            transport: if use_websocket {
                ForwardTransport::Websocket
            } else {
                ForwardTransport::Rest
            },
        };
        debug!(
            "Delivering {} messages to {} via {}",
            ready.len(),
            endpoint_url,
            transport
        );

        let delivery_timeout = Duration::from_secs(self.config.delivery_timeout_seconds.max(1));
        let mut attempted = 0u32;

        for msg in ready {
            if self.is_revoked(&msg.stream_id) {
                debug!(
                    "FORWARD_Q entry {} was taken over by another processor; not sending it",
                    msg.stream_id
                );
                continue;
            }
            // Checked per message, not once per batch: the attempt before this
            // one may just have failed and opened the backoff window.
            if let Some(retry_after_ms) = self.endpoint_backing_off(endpoint_url).await {
                debug!(
                    "Endpoint {} is backing off; holding message {} until it ends",
                    endpoint_url, msg.stream_id
                );
                outcome.deferred.push((retry_after_ms, msg));
                continue;
            }
            // Claims not confirmed lately: another processor may be taking
            // these over, so send nothing until a refresh succeeds. Checked
            // last, just before the send.
            if !self.claims_current() {
                debug!(
                    "Claims not confirmed recently; holding message {} for endpoint {}",
                    msg.stream_id, endpoint_url
                );
                outcome
                    .deferred
                    .push((unix_timestamp_millis() + self.unconfirmed_retry_ms(), msg));
                continue;
            }

            attempted += 1;
            let attempt = tokio::time::timeout(
                delivery_timeout,
                self.deliver_message(endpoint_url, &msg, use_websocket),
            )
            .await
            .unwrap_or_else(|_| {
                Err(RelayFailure::Retryable(format!(
                    "no answer from {endpoint_url} within {}s",
                    delivery_timeout.as_secs()
                )))
            });

            match attempt {
                Ok(()) => {
                    let forward_time_ms =
                        unix_timestamp_millis().saturating_sub(msg.received_at_ms);
                    let delay_info = if msg.delay_milli > 0 {
                        format!(", delay_requested={}ms", msg.delay_milli)
                    } else {
                        String::new()
                    };

                    info!(
                        "FORWARD_DELIVERED: to_did_hash={} from_did_hash={} endpoint={} transport={} forward_time={}ms{}",
                        msg.to_did_hash,
                        msg.from_did_hash,
                        endpoint_url,
                        transport,
                        forward_time_ms,
                        delay_info,
                    );
                    self.observe(&msg, relayed);
                    // Finished at once rather than with the rest of the batch,
                    // so a restart mid-batch does not leave a delivered entry
                    // to be sent again.
                    match self.finish(&msg, None).await {
                        Ok(true) => {}
                        Ok(false) => warn!(
                            "FORWARD_Q entry {} was delivered after another processor took it over; it may be delivered again",
                            msg.stream_id
                        ),
                        Err(e) => warn!("Failed to ACK and delete delivered entry: {e}"),
                    }
                    self.record_endpoint_success(endpoint_url).await;
                }
                // A refusal is final: drop it now and tell the sender. The peer
                // answered, so it says nothing about the endpoint's health and
                // does not count towards backoff.
                Err(RelayFailure::Refused { status, reason }) => {
                    warn!(
                        "FORWARD_REFUSED: to_did_hash={} from_did_hash={} endpoint={} status={} error={}",
                        msg.to_did_hash, msg.from_did_hash, endpoint_url, status, reason
                    );
                    self.drop_final(&msg, endpoint_url, ForwardOutcome::Refused { status })
                        .await;
                }
                // So is an endpoint we will not send to: no retry changes the
                // URL or the policy, and nothing was sent.
                Err(RelayFailure::NotPermitted(reason)) => {
                    warn!(
                        "FORWARD_NOT_PERMITTED: to_did_hash={} from_did_hash={} endpoint={} error={}",
                        msg.to_did_hash, msg.from_did_hash, endpoint_url, reason
                    );
                    self.drop_final(&msg, endpoint_url, ForwardOutcome::NotPermitted)
                        .await;
                }
                // Not sent; not the endpoint's fault. Held, unless another
                // processor has it now.
                Err(RelayFailure::Deferred(reason)) => {
                    attempted -= 1;
                    debug!("{reason}");
                    if !self.is_revoked(&msg.stream_id) {
                        outcome
                            .deferred
                            .push((unix_timestamp_millis() + self.unconfirmed_retry_ms(), msg));
                    }
                }
                Err(e @ RelayFailure::Retryable(_)) => {
                    warn!(
                        "FORWARD_FAILED: to_did_hash={} from_did_hash={} endpoint={} error={} retry_count={}",
                        msg.to_did_hash, msg.from_did_hash, endpoint_url, e, msg.retry_count
                    );
                    let retry_after_ms = self.record_endpoint_failure(endpoint_url).await;

                    // Remove broken WebSocket connection on failure
                    if use_websocket {
                        let mut pool = self.ws_pool.lock().await;
                        if pool.remove(endpoint_url).is_some() {
                            debug!("Removed failed WebSocket connection for {}", endpoint_url);
                        }
                    }

                    self.retry_or_abandon(&msg, endpoint_url, retry_after_ms)
                        .await;
                }
            }
        }

        // Only what was actually sent counts towards the WebSocket threshold:
        // a held-back message would otherwise count again each time it is
        // handed out.
        if attempted > 0 {
            let mut endpoints = self.endpoints.write().await;
            if let Some(state) = endpoints.get_mut(endpoint_url) {
                state.rate_tracker.record_and_rate(attempted);
            }
        }

        outcome.backing_off_until = self.endpoint_backing_off(endpoint_url).await;
        outcome
    }

    /// When the endpoint's backoff ends (unix ms), if it is backing off now.
    async fn endpoint_backing_off(&self, endpoint_url: &str) -> Option<u128> {
        let endpoints = self.endpoints.read().await;
        let retry_after_ms = endpoints.get(endpoint_url)?.retry_after_ms;
        (retry_after_ms > unix_timestamp_millis()).then_some(retry_after_ms)
    }

    async fn record_endpoint_success(&self, endpoint_url: &str) {
        let mut endpoints = self.endpoints.write().await;
        if let Some(state) = endpoints.get_mut(endpoint_url) {
            state.consecutive_failures = 0;
            state.retry_after_ms = 0;
        }
    }

    /// Count a failed attempt against the endpoint and open its backoff
    /// window. Returns when the window ends (unix ms).
    async fn record_endpoint_failure(&self, endpoint_url: &str) -> u128 {
        let mut endpoints = self.endpoints.write().await;
        let state = endpoints
            .entry(endpoint_url.to_string())
            .or_insert_with(|| EndpointState::new(self.config.rate_window_seconds));
        state.consecutive_failures = state.consecutive_failures.saturating_add(1);
        let backoff = self.calculate_backoff(state.consecutive_failures);
        state.retry_after_ms = unix_timestamp_millis() + backoff.as_millis();
        debug!(
            "Endpoint {} backing off {}ms (failures: {})",
            endpoint_url,
            backoff.as_millis(),
            state.consecutive_failures
        );
        state.retry_after_ms
    }

    /// Drop an entry that no retry can deliver, and tell its sender.
    async fn drop_final(
        &self,
        msg: &ForwardQueueEntry,
        endpoint_url: &str,
        outcome: ForwardOutcome,
    ) {
        // Reported only by the processor that actually drops it.
        match self.finish(msg, None).await {
            Ok(true) => {}
            Ok(false) => return,
            Err(e) => {
                warn!("Failed to ACK and delete undeliverable entry: {e}");
                return;
            }
        }
        self.observe(msg, outcome);
        if self.config.report_errors && !msg.from_did.is_empty() {
            let reason = match outcome {
                ForwardOutcome::Refused { status } => ReportReason::Refused(status),
                ForwardOutcome::NotPermitted => ReportReason::NotPermitted,
                _ => ReportReason::Abandoned,
            };
            self.send_forwarding_failure_report(msg, endpoint_url, reason)
                .await;
        }
    }

    /// Queue `msg` again for an attempt no earlier than `not_before_ms`, or
    /// abandon it if its retries are spent.
    async fn retry_or_abandon(
        &self,
        msg: &ForwardQueueEntry,
        endpoint_url: &str,
        not_before_ms: u128,
    ) {
        if msg.retry_count >= self.config.max_retries {
            // Max retries exceeded — drop it if still ours, and report it.
            match self.finish(msg, None).await {
                Ok(true) => {}
                Ok(false) => return,
                Err(e) => {
                    warn!("Failed to ACK and delete abandoned entry: {e}");
                    return;
                }
            }
            warn!(
                "FORWARD_ABANDONED: to_did_hash={} from_did_hash={} endpoint={} retries={}",
                msg.to_did_hash, msg.from_did_hash, endpoint_url, msg.retry_count
            );
            self.observe(
                msg,
                ForwardOutcome::Abandoned {
                    attempts: msg.retry_count + 1,
                },
            );

            // Send problem report to the original sender if we know their DID
            if self.config.report_errors && !msg.from_did.is_empty() {
                self.send_forwarding_failure_report(msg, endpoint_url, ReportReason::Abandoned)
                    .await;
            }
            return;
        }

        // Re-enqueue with incremented retry count. The not-before travels with
        // the entry, so whichever processor reads it next waits out the
        // backoff too.
        let mut retry_entry = msg.clone();
        retry_entry.retry_count += 1;
        retry_entry.not_before_ms = not_before_ms;

        // The retry is enqueued and the old entry acked and deleted in one
        // write, and only if the old entry is still ours: a processor that
        // took it over owns its retry, and a second retry entry would be a
        // second delivery. Unbounded, like the legacy retry path; the inbound
        // enqueue path applies the queue limit instead.
        match self.finish(msg, Some(&retry_entry)).await {
            Ok(true) => self.observe(
                msg,
                ForwardOutcome::Retrying {
                    attempt: msg.retry_count + 1,
                    max_retries: self.config.max_retries,
                },
            ),
            Ok(false) => {}
            Err(e) => {
                // Nothing was written, and the entry stays claimed: its claim
                // goes idle once this processor lets it go, and the reclaim
                // sweep hands it back.
                error!("Failed to queue retry entry; leaving the original claimed: {e}");
            }
        }
    }

    /// How long a forwarding-failure problem report stays in the sender's
    /// inbox before the expiry sweep reclaims it.
    const PROBLEM_REPORT_TTL_SECS: u64 = 300;

    /// Build the DIDComm **plaintext** of the abandonment problem report.
    ///
    /// `from` is the mediator's own DID and is not optional: the report is
    /// packed authcrypt, and the recipient's addressing-consistency check binds
    /// the authcrypt sender to this field. A report with no `from` decrypts and
    /// is then rejected — which is indistinguishable, from the sender's side,
    /// from the bug this replaces.
    /// How to name a forward's destination in diagnostics.
    ///
    /// Usually the VID. For a relayed endpoint-to-endpoint message it is the
    /// hash, because Rev 3 §5.3.3 forbids an intermediary from keeping the VID
    /// and the queue entry therefore does not carry one. The hash still lets an
    /// operator correlate a report with the log lines for the same forward,
    /// which is what these strings are for.
    fn destination_label(msg: &ForwardQueueEntry) -> &str {
        if msg.to_did.is_empty() {
            &msg.to_did_hash
        } else {
            &msg.to_did
        }
    }

    fn build_problem_report(
        msg: &ForwardQueueEntry,
        endpoint_url: &str,
        from: &str,
        now: u64,
    ) -> serde_json::Value {
        let destination = Self::destination_label(msg);
        let problem_body = serde_json::json!({
            "code": "e.p.me.res.forwarding.abandoned",
            "comment": format!(
                "Message forwarding to {} failed after {} retries. Destination endpoint: {}",
                destination, msg.retry_count, endpoint_url
            ),
            "args": [destination, msg.retry_count.to_string(), endpoint_url],
        });
        Self::problem_report_envelope(msg, problem_body, from, now)
    }

    /// The DIDComm plaintext of the report sent when the peer mediator
    /// refused the relay outright (see [`RelayFailure::Refused`]). The peer's
    /// own reason stays in the log: it may describe the recipient's policy,
    /// which the sender is not told.
    fn build_refusal_report(
        msg: &ForwardQueueEntry,
        endpoint_url: &str,
        status: u16,
        from: &str,
        now: u64,
    ) -> serde_json::Value {
        let destination = Self::destination_label(msg);
        let problem_body = serde_json::json!({
            "code": "e.p.me.res.forwarding.refused",
            "comment": format!(
                "The mediator for {} refused the forwarded message (HTTP {}). Destination endpoint: {}",
                destination, status, endpoint_url
            ),
            "args": [destination, status.to_string(), endpoint_url],
        });
        Self::problem_report_envelope(msg, problem_body, from, now)
    }

    /// The DIDComm plaintext of the report sent when the next hop is not an
    /// endpoint this mediator forwards to (see [`RelayFailure::NotPermitted`]).
    /// Which policy rule matched stays in the log.
    fn build_not_permitted_report(
        msg: &ForwardQueueEntry,
        endpoint_url: &str,
        from: &str,
        now: u64,
    ) -> serde_json::Value {
        let destination = Self::destination_label(msg);
        let problem_body = serde_json::json!({
            "code": "e.p.me.res.forwarding.endpoint-not-permitted",
            "comment": format!(
                "The forwarded message for {} was not sent: this mediator does not forward to the destination endpoint {}",
                destination, endpoint_url
            ),
            "args": [destination, endpoint_url],
        });
        Self::problem_report_envelope(msg, problem_body, from, now)
    }

    fn problem_report_envelope(
        msg: &ForwardQueueEntry,
        problem_body: serde_json::Value,
        from: &str,
        now: u64,
    ) -> serde_json::Value {
        serde_json::json!({
            "type": "https://didcomm.org/report-problem/2.0/problem-report",
            "id": Uuid::new_v4().to_string(),
            "body": problem_body,
            "from": from,
            "to": [msg.from_did],
            "created_time": now,
            "expires_time": now + Self::PROBLEM_REPORT_TTL_SECS,
        })
    }

    /// Send a problem report to the original sender when forwarding has been
    /// abandoned.
    ///
    /// The report is authcrypted from the mediator to the sender, like every
    /// other message the mediator puts in an inbox. It used to be stored as the
    /// raw plaintext JSON, which every SDK client on the default receive policy
    /// discards with `envelope wrapping Plaintext is not in the accepted set` —
    /// so from the sender's point of view a forward that the mediator gave up on
    /// simply vanished.
    ///
    /// When the report cannot be packed it is **not** stored. An envelope the
    /// recipient's policy refuses is the defect being fixed, and storing one
    /// merely moves the failure to their client (where it re-fails on every
    /// fetch until it expires) instead of putting it where an operator can act
    /// on it. Anoncrypt is no fallback either — bare anoncrypt is outside the
    /// default accepted set too. So the abandonment surfaces as an operator-side
    /// `ERROR` naming the sender, the destination and the reason.
    ///
    /// `reason` says whether the retries ran out, the peer refused the relay
    /// outright, or the endpoint was not one this mediator sends to.
    async fn send_forwarding_failure_report(
        &self,
        msg: &ForwardQueueEntry,
        endpoint_url: &str,
        reason: ReportReason,
    ) {
        let now = unix_timestamp_secs();

        // An anonymous forward, or one from a sender with no account on this
        // mediator, has no inbox here to hold a report.
        if msg.from_did_hash.is_empty() || msg.from_did.is_empty() {
            warn!(
                "FORWARD_PROBLEM_REPORT_UNSENT: the abandoned forward to {} (endpoint {}) has no \
                 sender with an account on this mediator to report to",
                Self::destination_label(msg),
                endpoint_url
            );
            return;
        }

        let Some(packer) = self.packer.as_ref() else {
            error!(
                "FORWARD_PROBLEM_REPORT_UNSENT: no system message packer configured, so the \
                 abandoned forward to {} (sender {}, endpoint {}) cannot be reported to its sender",
                Self::destination_label(msg),
                msg.from_did_hash,
                endpoint_url
            );
            return;
        };

        let report = match reason {
            ReportReason::Refused(status) => {
                Self::build_refusal_report(msg, endpoint_url, status, packer.mediator_did(), now)
            }
            ReportReason::NotPermitted => {
                Self::build_not_permitted_report(msg, endpoint_url, packer.mediator_did(), now)
            }
            ReportReason::Abandoned => {
                Self::build_problem_report(msg, endpoint_url, packer.mediator_did(), now)
            }
        };

        let packed = match packer.pack(&report, &msg.from_did).await {
            Ok(packed) => packed,
            Err(e) => {
                error!(
                    "FORWARD_PROBLEM_REPORT_UNSENT: couldn't pack the abandonment report for \
                     sender {} (abandoned forward to {}, endpoint {}): {}",
                    msg.from_did_hash,
                    Self::destination_label(msg),
                    endpoint_url,
                    e
                );
                return;
            }
        };

        match self
            .database
            .store_message(
                "forwarding-processor",
                &packed,
                &msg.from_did_hash,
                // The mediator authored this one, so it is the sender of
                // record — the same `from` hash its protocol replies carry.
                // (This slot used to hold the literal string "SYSTEM", which
                // is not a DID hash and gave the report an outbox of its own.)
                Some(&digest(packer.mediator_did())),
                now + Self::PROBLEM_REPORT_TTL_SECS,
                0, // No MAXLEN for system-generated problem reports
            )
            .await
        {
            Ok(hash) => {
                info!(
                    "FORWARD_PROBLEM_REPORT: stored problem report {} for sender {}",
                    hash, msg.from_did_hash
                );
            }
            Err(e) => {
                error!(
                    "Failed to store forwarding problem report for {}: {}",
                    msg.from_did_hash, e
                );
            }
        }
    }

    /// Deliver a single message to a remote mediator endpoint
    async fn deliver_message(
        &self,
        endpoint_url: &str,
        msg: &ForwardQueueEntry,
        use_websocket: bool,
    ) -> Result<(), RelayFailure> {
        // TSP forwards go over REST: they carry raw qb2 binary which the remote
        // mediator's ingress sniffs by its magic byte, whereas the WebSocket relay
        // path is DIDComm-text oriented.
        let use_websocket = use_websocket && decode_tsp_forward(&msg.message).is_none();
        if use_websocket {
            match self.deliver_via_websocket(endpoint_url, msg).await {
                Ok(()) => {
                    self.set_ws_suppression(endpoint_url, None).await;
                    Ok(())
                }
                Err(ws_err) => {
                    // WebSocket failed — fall back to REST for this message,
                    // and stop attempting it for this endpoint for a while
                    // (see `EndpointState::ws_suppressed_until`). A relay-ack
                    // refusal carries a mediator error code, not an HTTP
                    // status, so the REST answer is what classifies it as
                    // final or retryable.
                    let until = Instant::now() + WS_SUPPRESSION_WINDOW;
                    let first = self.set_ws_suppression(endpoint_url, Some(until)).await;
                    if first {
                        warn!(
                            "WebSocket delivery to {} failed ({}). Falling back to REST and \
                             suppressing WebSocket for {}s.",
                            endpoint_url,
                            ws_err,
                            WS_SUPPRESSION_WINDOW.as_secs()
                        );
                    } else {
                        debug!(
                            "WebSocket delivery failed for {}, falling back to REST: {}",
                            endpoint_url, ws_err
                        );
                    }
                    // The WebSocket attempt can take as long as the relay-ack
                    // timeout; the fallback is a new send, so it is held to
                    // the same check as the first.
                    if self.is_revoked(&msg.stream_id) || !self.claims_current() {
                        return Err(RelayFailure::Deferred(format!(
                            "not falling back to REST for {}: its claim is not confirmed",
                            msg.stream_id
                        )));
                    }
                    self.deliver_via_rest(endpoint_url, msg).await
                }
            }
        } else {
            self.deliver_via_rest(endpoint_url, msg).await
        }
    }

    /// Set (or clear) the WebSocket suppression window for an endpoint.
    ///
    /// Returns true when this call started a new suppression window, so the
    /// caller can log the transition once rather than per message.
    async fn set_ws_suppression(&self, endpoint_url: &str, until: Option<Instant>) -> bool {
        let mut endpoints = self.endpoints.write().await;
        let Some(state) = endpoints.get_mut(endpoint_url) else {
            // Reaped between the transport decision and here; the next batch
            // re-creates it unsuppressed, which is the safe direction.
            return false;
        };
        let was_suppressed = state.ws_suppressed(Instant::now());
        state.ws_suppressed_until = until;
        until.is_some() && !was_suppressed
    }

    /// Deliver a message via REST POST to the remote mediator's inbound endpoint
    async fn deliver_via_rest(
        &self,
        endpoint_url: &str,
        msg: &ForwardQueueEntry,
    ) -> Result<(), RelayFailure> {
        let inbound_url = if endpoint_url.ends_with('/') {
            format!("{endpoint_url}inbound")
        } else {
            format!("{endpoint_url}/inbound")
        };

        // Egress guard (literal + scheme half): refuse a next-hop endpoint that
        // is not a public, globally-routable https target before issuing the
        // request. This is the check that sees IP literals (metadata/RFC1918/
        // loopback/link-local), which the client's DNS resolver never sees.
        //
        // Every vet error is final: a refusal by address class or scheme, or a
        // URL that does not parse. Retrying would only spend the retry budget
        // and the backoff on an answer that cannot change.
        self.http_pool.policy.vet(&inbound_url).map_err(|e| {
            RelayFailure::NotPermitted(format!(
                "Refusing to forward to {inbound_url}: blocked by egress policy: {e}"
            ))
        })?;

        // A TSP forward is queued as base64url(qb2) text; send the decoded raw qb2
        // so the remote mediator's ingress recognises the TSP magic byte. A DIDComm
        // message is sent as-is. (DIDComm forwarding is unchanged.)
        let (content_type, body): (&str, Vec<u8>) = match decode_tsp_forward(&msg.message) {
            Some(qb2) => ("application/tsp", qb2),
            None => (
                "application/didcomm-encrypted+json",
                msg.message.clone().into_bytes(),
            ),
        };

        let response = self
            .http_pool
            .client
            .post(&inbound_url)
            .header("Content-Type", content_type)
            .body(body)
            .send()
            .await
            .map_err(|e| {
                RelayFailure::Retryable(format!("Connection error to {inbound_url}: {e}"))
            })?;

        let status = response.status();
        if status.is_success() {
            Ok(())
        } else {
            let body = response.text().await.unwrap_or_default();
            Err(RelayFailure::from_status(
                status.as_u16(),
                format!("Remote mediator {inbound_url} returned HTTP {status}: {body}"),
            ))
        }
    }

    /// Deliver a message via WebSocket to the remote mediator, and wait for the
    /// peer's acknowledgement.
    ///
    /// Connections are pooled per endpoint URL and kept alive for the configured
    /// idle timeout. When the rate drops below the threshold, the idle cleanup
    /// task closes the connection.
    ///
    /// **Delivery semantics are the REST path's.** A frame is only reported
    /// delivered once the peer answers with a positive [`RelayAck`]; a negative
    /// ack, a missing one, or a socket error is an `Err`, which the caller
    /// retries and eventually abandons with a problem report to the sender —
    /// exactly what a non-2xx does on `deliver_via_rest`. Without this a
    /// WebSocket write would report success for a message the peer refused.
    ///
    /// A peer that does not negotiate the `relay-ack` subprotocol gets no
    /// frames over the socket at all: the connection is closed and the error
    /// sends this endpoint back to REST (and, via the suppression window, keeps
    /// it there for a while).
    ///
    /// The whole attempt is bounded by [`ws_limits_for`] the delivery timeout,
    /// so a peer that stalls at any step leaves time for the REST fallback.
    async fn deliver_via_websocket(
        &self,
        endpoint_url: &str,
        msg: &ForwardQueueEntry,
    ) -> Result<(), String> {
        let ws_url = Self::http_to_ws_url(endpoint_url);

        // Egress guard (literal + scheme half): refuse a next-hop that is not a
        // public, globally-routable wss target before dialing — same guarantee
        // the REST path gets, so the WebSocket transport cannot be used to reach
        // a metadata/RFC1918/loopback/link-local literal or a plaintext ws host.
        let vetted = self.http_pool.policy.vet(&ws_url).map_err(|e| {
            format!("Refusing to relay via WebSocket to {ws_url}: blocked by egress policy: {e}")
        })?;

        let frame = msg.message.clone();
        let id = frame_id(frame.as_bytes());
        let resolver = GuardedResolver::new(self.http_pool.policy.clone());
        let limits = ws_limits_for(Duration::from_secs(
            self.config.delivery_timeout_seconds.max(1),
        ));

        relay_frame(
            &self.ws_pool,
            endpoint_url,
            &ws_url,
            || resolve_vetted(resolver, vetted),
            &frame,
            &id,
            limits,
        )
        .await
    }

    /// Convert an HTTP(S) endpoint URL to a WebSocket URL
    fn http_to_ws_url(endpoint_url: &str) -> String {
        let ws_base = endpoint_url
            .replace("https://", "wss://")
            .replace("http://", "ws://");

        if ws_base.ends_with('/') {
            format!("{ws_base}ws")
        } else {
            format!("{ws_base}/ws")
        }
    }

    /// Calculate exponential backoff duration
    fn calculate_backoff(&self, consecutive_failures: u32) -> Duration {
        let base = self.config.initial_backoff_ms;
        let max = self.config.max_backoff_ms;
        let backoff = base.saturating_mul(2u64.saturating_pow(consecutive_failures.min(10)));
        Duration::from_millis(backoff.min(max))
    }
}

// ─── WebSocket relay ────────────────────────────────────────────────────────

type RelaySocket =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

/// Time limits on one WebSocket relay attempt.
#[derive(Clone, Copy, Debug)]
struct WsLimits {
    /// The whole attempt: the pooled socket, a new connection if that one
    /// failed, the send and the peer's [`RelayAck`]. See [`ws_limits_for`].
    attempt: Duration,
    /// Opening a new connection: name resolution, TCP connect, TLS and the
    /// WebSocket upgrade, together.
    connect: Duration,
    /// The least time one resolved address is given before the next is tried
    /// (unless less than that is left). Each address otherwise gets an equal
    /// share of what remains of `connect`.
    per_address_min: Duration,
    /// The close handshake on a socket that is being discarded. It runs on its
    /// own task, so the delivery never waits for it.
    close: Duration,
}

/// The longest a WebSocket attempt may take. Matches the REST client's request
/// timeout, so a stalled peer costs the same on either transport.
const WS_ATTEMPT_MAX: Duration = Duration::from_secs(30);

/// The limits on a WebSocket attempt inside a delivery attempt of
/// `delivery_timeout`.
///
/// The WebSocket attempt gets at most a third of the delivery timeout (and at
/// most [`WS_ATTEMPT_MAX`]), so that however short the delivery timeout is
/// configured, a stalled WebSocket attempt ends with time left for the REST
/// fallback rather than being cancelled with the delivery attempt.
fn ws_limits_for(delivery_timeout: Duration) -> WsLimits {
    let attempt = WS_ATTEMPT_MAX.min(delivery_timeout / 3);
    WsLimits {
        attempt,
        connect: Duration::from_secs(10).min(attempt),
        per_address_min: Duration::from_secs(2),
        close: Duration::from_secs(5),
    }
}

/// Relay one frame over the endpoint's pooled socket, or a new one, and wait
/// for the peer's [`RelayAck`].
///
/// The pooled socket is taken out of `pool` before any network I/O and put
/// back only once the exchange is over, so the pool lock is never held across
/// an await on the network and no two deliveries use one socket at the same
/// time. A socket that failed is not put back.
///
/// `resolve` yields the addresses that were checked against the egress policy;
/// a new connection is made to one of those, never to a fresh lookup of the
/// name. It is only called when there is no usable pooled socket.
async fn relay_frame<R, F>(
    pool: &Mutex<HashMap<String, PooledWebSocket>>,
    endpoint_url: &str,
    ws_url: &str,
    resolve: R,
    frame: &str,
    id: &str,
    limits: WsLimits,
) -> Result<(), String>
where
    R: FnOnce() -> F,
    F: std::future::Future<Output = Result<Vec<std::net::SocketAddr>, String>>,
{
    let deadline = tokio::time::Instant::now() + limits.attempt;

    let pooled = pool.lock().await.remove(endpoint_url);
    if let Some(mut ws) = pooled {
        match send_and_await_ack(&mut ws.stream, frame, id, deadline).await {
            Ok(()) => {
                ws.last_used = Instant::now();
                pool.lock().await.insert(endpoint_url.to_string(), ws);
                debug!("Relayed via pooled WebSocket to {} (acked)", endpoint_url);
                return Ok(());
            }
            Err(AckFailure::Rejected(reason)) => {
                // The peer answered, and refused. The connection is fine; the
                // message is not. Keep the socket, fail the message —
                // retry/abandonment is the caller's job, as on REST.
                ws.last_used = Instant::now();
                pool.lock().await.insert(endpoint_url.to_string(), ws);
                return Err(reason);
            }
            Err(AckFailure::Transport(e)) => {
                discard_socket(ws.stream, endpoint_url, &e, limits.close);
                if tokio::time::Instant::now() >= deadline {
                    return Err(e);
                }
                warn!(
                    "Pooled WebSocket relay to {} failed: {}. Reconnecting...",
                    endpoint_url, e
                );
            }
        }
    }

    // No usable connection — open one to a vetted address, negotiating
    // `relay-ack`.
    let connect_started = tokio::time::Instant::now();
    let connect_deadline = deadline.min(connect_started + limits.connect);
    let (mut stream, response) = tokio::time::timeout_at(
        connect_deadline,
        open_relay_socket(ws_url, resolve, connect_deadline, limits.per_address_min),
    )
    .await
    .map_err(|_| {
        format!(
            "WebSocket connect to {ws_url} did not complete within the {} ms allowed",
            connect_deadline
                .saturating_duration_since(connect_started)
                .as_millis()
        )
    })??;

    // The subprotocol IS the negotiation: a peer that doesn't echo it cannot
    // acknowledge frames, so it must not be relayed to over this socket. (An
    // anonymous relay upgrade is also only admitted by a peer that offers it,
    // so in practice a non-echoing peer has refused the upgrade outright and
    // we never reach here.)
    let negotiated = response
        .headers()
        .get(tungstenite::http::header::SEC_WEBSOCKET_PROTOCOL)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_string();
    if negotiated != RELAY_ACK_SUBPROTOCOL {
        let reason = format!(
            "peer at {ws_url} did not negotiate the `{RELAY_ACK_SUBPROTOCOL}` subprotocol \
             (got {negotiated:?}); relaying over REST instead"
        );
        discard_socket(stream, endpoint_url, &reason, limits.close);
        return Err(reason);
    }

    info!("WebSocket connected to {} (relay-ack, pool)", endpoint_url);

    // A transport failure means the socket is not worth keeping; a rejection
    // is about the message and leaves the connection usable.
    match send_and_await_ack(&mut stream, frame, id, deadline).await {
        Ok(()) => {
            pool.lock().await.insert(
                endpoint_url.to_string(),
                PooledWebSocket {
                    stream,
                    last_used: Instant::now(),
                },
            );
            Ok(())
        }
        Err(AckFailure::Rejected(reason)) => {
            pool.lock().await.insert(
                endpoint_url.to_string(),
                PooledWebSocket {
                    stream,
                    last_used: Instant::now(),
                },
            );
            Err(reason)
        }
        Err(AckFailure::Transport(e)) => {
            discard_socket(stream, endpoint_url, &e, limits.close);
            Err(e)
        }
    }
}

/// Resolve `ws_url`'s host to addresses and open the relay socket on the first
/// of them that completes TCP connect, TLS and the WebSocket upgrade by
/// `deadline`.
///
/// Each address gets an equal share of the time left (at least
/// `per_address_min`, unless less than that is left), so an address that
/// never answers — an unreachable IPv6 address listed first, say — does not
/// use up the time the others need.
///
/// The request still names the host, so TLS SNI, certificate validation and
/// the `Host` header are those of the name; only the address is pinned. The
/// caller must bound the whole of this by `deadline`.
async fn open_relay_socket<R, F>(
    ws_url: &str,
    resolve: R,
    deadline: tokio::time::Instant,
    per_address_min: Duration,
) -> Result<(RelaySocket, tungstenite::handshake::client::Response), String>
where
    R: FnOnce() -> F,
    F: std::future::Future<Output = Result<Vec<std::net::SocketAddr>, String>>,
{
    let request = || {
        let mut request = ws_url
            .into_client_request()
            .map_err(|e| format!("WebSocket request for {ws_url} is not valid: {e}"))?;
        request.headers_mut().insert(
            tungstenite::http::header::SEC_WEBSOCKET_PROTOCOL,
            tungstenite::http::HeaderValue::from_static(RELAY_ACK_SUBPROTOCOL),
        );
        Ok::<_, String>(request)
    };
    // Checked before anything is dialed.
    request()?;

    let addrs = resolve().await?;
    let mut last_error = None;
    for (i, addr) in addrs.iter().enumerate() {
        let now = tokio::time::Instant::now();
        let left = deadline.saturating_duration_since(now);
        if left.is_zero() {
            break;
        }
        let share = (left / (addrs.len() - i) as u32)
            .max(per_address_min)
            .min(left);
        let attempt = async {
            let tcp = tokio::net::TcpStream::connect(addr)
                .await
                .map_err(|e| e.to_string())?;
            let _ = tcp.set_nodelay(true);
            tokio_tungstenite::client_async_tls_with_config(request()?, tcp, None, None)
                .await
                .map_err(|e| e.to_string())
        };
        // An address given all the time that is left runs to the caller's
        // deadline, which bounds this whole function and reports the time
        // allowed.
        let outcome = if share >= left {
            Ok(attempt.await)
        } else {
            tokio::time::timeout(share, attempt).await
        };
        match outcome {
            Ok(Ok(opened)) => return Ok(opened),
            Ok(Err(e)) => last_error = Some(format!("{addr}: {e}")),
            Err(_) => {
                last_error = Some(format!("{addr}: no answer within {} ms", share.as_millis()))
            }
        }
        debug!("WebSocket connect to {ws_url} via {addr} failed; trying the next address");
    }
    Err(format!(
        "WebSocket connect to {ws_url} failed: {}",
        last_error.unwrap_or_else(|| "no addresses".into())
    ))
}

/// The addresses a vetted WebSocket URL may be dialed at.
///
/// An IP-literal host was address-checked by `vet`. A name is resolved through
/// the same guarded resolver the REST client uses: any answer the policy does
/// not admit fails the whole name, and the connection is then made to exactly
/// the addresses returned here, so there is no second lookup to answer
/// differently.
async fn resolve_vetted(
    resolver: GuardedResolver,
    vetted: affinidi_net_guard::VettedUrl,
) -> Result<Vec<std::net::SocketAddr>, String> {
    use reqwest::dns::Resolve;

    let url = vetted.as_url();
    let port = url
        .port_or_known_default()
        .ok_or_else(|| format!("WebSocket URL {url} has no port"))?;
    match url.host() {
        Some(url::Host::Ipv4(ip)) => Ok(vec![std::net::SocketAddr::new(ip.into(), port)]),
        Some(url::Host::Ipv6(ip)) => Ok(vec![std::net::SocketAddr::new(ip.into(), port)]),
        Some(url::Host::Domain(name)) => {
            let host: reqwest::dns::Name = name
                .parse()
                .map_err(|e| format!("WebSocket host {name} is not a valid name: {e}"))?;
            let addrs = resolver
                .resolve(host)
                .await
                .map_err(|e| format!("Refusing WebSocket relay to {name}: {e}"))?;
            Ok(addrs
                .map(|mut addr| {
                    addr.set_port(port);
                    addr
                })
                .collect())
        }
        None => Err(format!("WebSocket URL {url} has no host")),
    }
}

/// Write one relayed frame and wait for the peer's [`RelayAck`] for it, all by
/// `deadline`.
///
/// Frames that are not this frame's ack — a ping, a stray text frame, an ack
/// for something else — are skipped rather than mistaken for the answer, until
/// the ack arrives or the deadline passes.
async fn send_and_await_ack(
    stream: &mut RelaySocket,
    frame: &str,
    id: &str,
    deadline: tokio::time::Instant,
) -> Result<(), AckFailure> {
    match tokio::time::timeout_at(
        deadline,
        stream.send(tungstenite::Message::Text(frame.to_string().into())),
    )
    .await
    {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            return Err(AckFailure::Transport(format!("WebSocket send failed: {e}")));
        }
        Err(_) => {
            return Err(AckFailure::Transport(
                "WebSocket send did not complete in time".to_string(),
            ));
        }
    }

    loop {
        let incoming = match tokio::time::timeout_at(deadline, stream.next()).await {
            Ok(incoming) => incoming,
            Err(_) => {
                return Err(AckFailure::Transport(
                    "no relay-ack before the attempt's deadline".to_string(),
                ));
            }
        };
        match incoming {
            Some(Ok(tungstenite::Message::Text(text))) => {
                let Ok(ack) = serde_json::from_str::<RelayAck>(&text) else {
                    debug!("Ignoring a non-ack text frame on the relay socket");
                    continue;
                };
                if !ack.answers(id) {
                    debug!("Ignoring a relay-ack for another frame ({})", ack.id);
                    continue;
                }
                return if ack.ok {
                    Ok(())
                } else {
                    Err(AckFailure::Rejected(format!(
                        "peer refused the relayed message: {} (code {})",
                        ack.reason.as_deref().unwrap_or("no reason given"),
                        ack.code
                            .map(|c| c.to_string())
                            .unwrap_or_else(|| "-".into()),
                    )))
                };
            }
            Some(Ok(tungstenite::Message::Close(frame))) => {
                return Err(AckFailure::Transport(format!(
                    "peer closed the relay socket before acknowledging ({frame:?})"
                )));
            }
            // Ping/Pong/Binary on a relay socket are not ours to interpret;
            // tungstenite answers pings itself.
            Some(Ok(_)) => continue,
            Some(Err(e)) => {
                return Err(AckFailure::Transport(format!(
                    "WebSocket error awaiting relay-ack: {e}"
                )));
            }
            None => {
                return Err(AckFailure::Transport(
                    "relay socket ended before acknowledging".to_string(),
                ));
            }
        }
    }
}

/// Drop a relay socket that is no longer usable, after a bounded close
/// handshake on a task of its own so the caller never waits on the peer.
fn discard_socket(mut stream: RelaySocket, endpoint_url: &str, reason: &str, close: Duration) {
    info!("Discarding WebSocket relay connection to {endpoint_url}: {reason}");
    tokio::spawn(async move {
        let _ = tokio::time::timeout(close, stream.close(None)).await;
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- build_problem_report tests ---

    /// Rev 3 §5.3.3: an entry whose destination was withheld still produces a
    /// usable report, and does not invent a destination it was not given.
    ///
    /// The withholding happens where the queue entry is built — the mediator
    /// leaves `to_did` empty when relaying an endpoint-to-endpoint message —
    /// so what is checked here is the other half: that the reporting path
    /// degrades to the hash rather than emitting an empty string into a message
    /// sent to the sender, and that nothing reintroduces the VID.
    #[test]
    fn a_withheld_destination_reports_as_its_hash() {
        let mut entry = abandoned_entry();
        entry.to_did = String::new();

        let report = ForwardingProcessor::build_problem_report(
            &entry,
            "https://example/inbound",
            "did:med",
            0,
        );
        let body = &report["body"];

        let comment = body["comment"].as_str().expect("a comment");
        assert!(
            comment.contains("to-hash"),
            "the hash stands in for the VID: {comment}"
        );
        assert!(
            !comment.contains("forwarding to  failed"),
            "and does not leave a hole where the destination should be: {comment}"
        );
        assert_eq!(body["args"][0], "to-hash");
    }

    /// An ordinary forward is unaffected: a routing-layer VID is the
    /// intermediary's own business and is still named in full.
    #[test]
    fn an_ordinary_destination_is_still_named() {
        let entry = abandoned_entry();
        let report = ForwardingProcessor::build_problem_report(
            &entry,
            "https://example/inbound",
            "did:med",
            0,
        );
        assert_eq!(report["body"]["args"][0], "did:example:recipient");
        assert!(
            report["body"]["comment"]
                .as_str()
                .expect("a comment")
                .contains("did:example:recipient")
        );
    }

    fn abandoned_entry() -> ForwardQueueEntry {
        ForwardQueueEntry {
            stream_id: "1-0".into(),
            message: "encrypted-forward".into(),
            to_did_hash: "to-hash".into(),
            from_did_hash: "from-hash".into(),
            from_did: "did:example:sender".into(),
            to_did: "did:example:recipient".into(),
            endpoint_url: "https://remote.example.com".into(),
            received_at_ms: 0,
            delay_milli: 0,
            expires_at: 0,
            retry_count: 5,
            hop_count: 1,
            not_before_ms: 0,
        }
    }

    /// The report is addressed *from* the mediator. This is the field the
    /// recipient's addressing-consistency check binds the authcrypt sender to;
    /// without it the report decrypts and is then thrown away, which is the
    /// same silent outcome as never sending one.
    #[test]
    fn problem_report_names_the_mediator_as_sender() {
        let report = ForwardingProcessor::build_problem_report(
            &abandoned_entry(),
            "https://remote.example.com",
            "did:example:mediator",
            1_000,
        );

        assert_eq!(report["from"], "did:example:mediator");
        assert_eq!(report["to"], serde_json::json!(["did:example:sender"]));
    }

    /// The wire contract clients match on: the report-problem 2.0 type, the
    /// `e.p.me.res.forwarding.abandoned` code, and the `[to_did, retries,
    /// endpoint]` args a client needs to identify which forward was dropped.
    #[test]
    fn problem_report_carries_the_abandonment_code_and_args() {
        let entry = abandoned_entry();
        let report = ForwardingProcessor::build_problem_report(
            &entry,
            "https://remote.example.com",
            "did:example:mediator",
            1_000,
        );

        assert_eq!(
            report["type"],
            "https://didcomm.org/report-problem/2.0/problem-report"
        );
        assert_eq!(report["body"]["code"], "e.p.me.res.forwarding.abandoned");
        assert_eq!(
            report["body"]["args"],
            serde_json::json!(["did:example:recipient", "5", "https://remote.example.com"])
        );
        assert_eq!(report["created_time"], 1_000);
        assert_eq!(
            report["expires_time"],
            1_000 + ForwardingProcessor::PROBLEM_REPORT_TTL_SECS
        );
        assert!(
            report["id"].as_str().is_some_and(|id| !id.is_empty()),
            "every report needs its own message id"
        );
    }

    /// A peer's refusal is final; a timeout, rate limit or server error is not.
    #[test]
    fn a_client_error_is_a_refusal_and_the_rest_are_retried() {
        for status in [400, 401, 403, 404, 413, 422] {
            assert!(
                matches!(
                    RelayFailure::from_status(status, String::new()),
                    RelayFailure::Refused { status: s, .. } if s == status
                ),
                "{status} is final"
            );
        }
        for status in [408, 425, 429, 500, 502, 503, 504, 302] {
            assert!(
                matches!(
                    RelayFailure::from_status(status, String::new()),
                    RelayFailure::Retryable(_)
                ),
                "{status} is retried"
            );
        }
    }

    /// The refusal report has its own code, and carries the peer's HTTP
    /// status rather than a retry count it never accumulated.
    #[test]
    fn refusal_report_carries_the_refused_code_and_status() {
        let entry = abandoned_entry();
        let report = ForwardingProcessor::build_refusal_report(
            &entry,
            "https://remote.example.com",
            403,
            "did:example:mediator",
            1_000,
        );

        assert_eq!(report["body"]["code"], "e.p.me.res.forwarding.refused");
        assert_eq!(
            report["body"]["args"],
            serde_json::json!(["did:example:recipient", "403", "https://remote.example.com"])
        );
        assert_eq!(report["from"], "did:example:mediator");
        assert_eq!(report["to"], serde_json::json!(["did:example:sender"]));
    }

    /// The report for an endpoint this mediator will not send to has its own
    /// code, distinct from a peer's refusal and from running out of retries.
    #[test]
    fn not_permitted_report_carries_its_own_code() {
        let entry = abandoned_entry();
        let report = ForwardingProcessor::build_not_permitted_report(
            &entry,
            "https://169.254.169.254",
            "did:example:mediator",
            1_000,
        );

        assert_eq!(
            report["body"]["code"],
            "e.p.me.res.forwarding.endpoint-not-permitted"
        );
        assert_eq!(
            report["body"]["args"],
            serde_json::json!(["did:example:recipient", "https://169.254.169.254"])
        );
        assert_eq!(report["from"], "did:example:mediator");
        assert_eq!(report["to"], serde_json::json!(["did:example:sender"]));
    }

    // --- Scheduler tests ---

    fn scheduler(batch_size: usize, max_concurrent_endpoints: usize) -> Scheduler {
        Scheduler::new(&ForwardingConfig {
            batch_size,
            max_concurrent_endpoints,
            initial_backoff_ms: 1_000,
            max_backoff_ms: 60_000,
            ..Default::default()
        })
    }

    fn queued(id: &str, endpoint_url: &str) -> ForwardQueueEntry {
        ForwardQueueEntry {
            stream_id: id.into(),
            endpoint_url: endpoint_url.into(),
            received_at_ms: 1_000,
            retry_count: 0,
            ..abandoned_entry()
        }
    }

    /// While one endpoint's delivery is still running, another endpoint's
    /// entries are handed out regardless.
    #[test]
    fn a_busy_endpoint_does_not_hold_up_another() {
        let mut s = scheduler(10, 4);
        s.accept(
            vec![queued("1-0", "https://slow"), queued("2-0", "https://fast")],
            5_000,
        );

        let (first, _) = s.next_batch().expect("a batch for the first endpoint");
        assert_eq!(first, "https://slow");
        // More for the busy endpoint arrives; it waits for that task to end.
        s.accept(vec![queued("3-0", "https://slow")], 5_000);

        let (second, batch) = s.next_batch().expect("a batch for the other endpoint");
        assert_eq!(second, "https://fast");
        assert_eq!(batch.len(), 1);
        assert!(
            s.next_batch().is_none(),
            "the busy endpoint gets no second task"
        );

        s.finished(
            "https://slow",
            &["1-0".to_string()],
            BatchOutcome::default(),
            5_000,
        );
        let (again, batch) = s.next_batch().expect("its queued entry, once it is free");
        assert_eq!(again, "https://slow");
        assert_eq!(batch[0].stream_id, "3-0");
    }

    /// A retry is held back until its not-before, then released.
    #[test]
    fn a_retry_waits_for_its_not_before() {
        let mut s = scheduler(10, 4);
        let mut retry = queued("1-0", "https://peer");
        retry.not_before_ms = 9_000;
        s.accept(vec![retry], 5_000);

        assert!(s.next_batch().is_none(), "not due yet");
        assert_eq!(s.next_due_ms(), Some(9_000));

        s.release_due(8_999);
        assert!(s.next_batch().is_none(), "still not due");

        s.release_due(9_000);
        let (_, batch) = s.next_batch().expect("due now");
        assert_eq!(batch[0].stream_id, "1-0");
    }

    /// An entry read twice is held once, so it cannot be delivered (or
    /// deleted) twice by this processor.
    #[test]
    fn a_repeated_read_is_held_once() {
        let mut s = scheduler(10, 4);
        s.accept(vec![queued("1-0", "https://peer")], 5_000);
        s.accept(vec![queued("1-0", "https://peer")], 5_000);

        let (_, batch) = s.next_batch().expect("a batch");
        assert_eq!(batch.len(), 1);
        assert!(s.next_batch().is_none());
    }

    /// Reading stops once the held entries reach the limit, and resumes as
    /// deliveries finish.
    #[test]
    fn reading_pauses_while_the_hold_is_full() {
        let mut s = scheduler(1, 2);
        s.accept(
            vec![queued("1-0", "https://a"), queued("2-0", "https://b")],
            5_000,
        );
        assert!(!s.has_room());

        let (endpoint, batch) = s.next_batch().expect("a batch");
        let ids: Vec<String> = batch.iter().map(|m| m.stream_id.clone()).collect();
        s.finished(&endpoint, &ids, BatchOutcome::default(), 5_000);
        assert!(s.has_room());
    }

    /// One endpoint holds at most its share, so entries for others are still
    /// taken while it is backlogged.
    #[test]
    fn a_backlogged_endpoint_holds_only_its_share() {
        // 2 x 2 = 4 held at most, 2 of them for any one endpoint.
        let mut s = scheduler(2, 2);
        let backlog: Vec<_> = (0..10)
            .map(|i| queued(&format!("{i}-0"), "https://backlogged"))
            .collect();
        s.accept(backlog, 5_000);
        assert_eq!(s.held.len(), 2, "the rest is left to the reclaim sweep");
        assert!(s.has_room(), "room remains for other endpoints");

        s.accept(vec![queued("99-0", "https://other")], 5_000);
        let mut endpoints = Vec::new();
        while let Some((endpoint, _)) = s.next_batch() {
            endpoints.push(endpoint);
        }
        assert!(endpoints.contains(&"https://other".to_string()));
    }

    /// While an endpoint backs off it holds at most a batch: the rest of what
    /// it returns, and what arrives for it, is left for the reclaim sweep, so
    /// two endpoints that are down cannot take the whole budget.
    #[test]
    fn an_endpoint_backing_off_holds_only_a_batch() {
        // 4 x 4 = 16 held at most; 8 for an endpoint, 4 while it backs off.
        let mut s = scheduler(4, 4);
        let dead: Vec<_> = (0..8)
            .map(|i| queued(&format!("{i}-0"), "https://dead"))
            .collect();
        s.accept(dead, 5_000);
        assert_eq!(s.held.len(), 8);

        let (endpoint, batch) = s.next_batch().expect("a batch");
        let ids: Vec<String> = batch.iter().map(|m| m.stream_id.clone()).collect();
        let deferred = batch.into_iter().map(|m| (60_000, m)).collect();
        s.finished(
            &endpoint,
            &ids,
            BatchOutcome {
                deferred,
                backing_off_until: Some(60_000),
            },
            5_000,
        );
        assert_eq!(
            s.held_for("https://dead"),
            4,
            "still queued 4, none re-held"
        );

        s.accept(vec![queued("50-0", "https://dead")], 5_000);
        assert_eq!(
            s.held_for("https://dead"),
            4,
            "nothing more while backing off"
        );

        s.prune_backoffs(60_001);
        s.accept(vec![queued("51-0", "https://dead")], 60_001);
        assert_eq!(
            s.held_for("https://dead"),
            5,
            "its full share once the backoff ends"
        );
    }

    /// Reading never takes the processor past its hold limit, even within
    /// one batch.
    #[test]
    fn a_batch_does_not_overshoot_the_hold_limit() {
        let mut s = scheduler(2, 2);
        let mixed: Vec<_> = (0..6)
            .map(|i| queued(&format!("{i}-0"), &format!("https://peer-{i}")))
            .collect();
        s.accept(mixed, 5_000);
        assert_eq!(s.held.len(), 4);
    }

    /// Entries a delivery task held back stay held and parked until the
    /// endpoint's backoff ends, unchanged: same id, same retry count.
    #[test]
    fn held_back_entries_wait_for_the_backoff_unchanged() {
        let mut s = scheduler(10, 4);
        s.accept(
            vec![queued("1-0", "https://peer"), queued("2-0", "https://peer")],
            5_000,
        );
        let (endpoint, batch) = s.next_batch().expect("a batch");
        let ids: Vec<String> = batch.iter().map(|m| m.stream_id.clone()).collect();
        // The first was attempted and failed; the second was held back.
        let held_back = batch[1].clone();
        s.finished(
            &endpoint,
            &ids,
            BatchOutcome {
                deferred: vec![(9_000, held_back)],
                backing_off_until: Some(9_000),
            },
            5_000,
        );

        assert_eq!(s.held.len(), 1);
        assert!(s.next_batch().is_none(), "not before the backoff ends");
        s.release_due(9_000);
        let (_, batch) = s.next_batch().expect("due now");
        assert_eq!(batch[0].stream_id, "2-0");
        assert_eq!(batch[0].retry_count, 0, "its retry budget is untouched");
    }

    /// Entries another processor took over are dropped if parked or queued,
    /// and reported if a delivery task has them.
    #[test]
    fn entries_taken_over_are_let_go() {
        let mut s = scheduler(1, 4);
        let mut later = queued("2-0", "https://parked");
        later.not_before_ms = 9_000;
        s.accept(
            vec![
                queued("1-0", "https://busy"),
                later,
                queued("3-0", "https://queued"),
            ],
            5_000,
        );
        let (busy, _) = s.next_batch().expect("a batch");
        assert_eq!(busy, "https://busy");

        let in_flight = s.forget(&["1-0".to_string(), "2-0".to_string(), "3-0".to_string()]);
        assert_eq!(in_flight, vec!["1-0".to_string()]);
        assert_eq!(
            s.held.len(),
            1,
            "only the in-flight one, until its task ends"
        );
        assert!(s.next_due_ms().is_none());
        assert!(s.next_batch().is_none());
    }

    /// A delay the sender asked for that is beyond what the processor parks
    /// is left claimed in the store, as before; it is not held in memory.
    #[test]
    fn a_long_requested_delay_is_not_parked() {
        let mut s = scheduler(10, 4);
        let mut delayed = queued("1-0", "https://peer");
        delayed.delay_milli = 3_600_000;
        s.accept(vec![delayed], 5_000);

        assert!(s.next_due_ms().is_none());
        assert!(s.next_batch().is_none());
        assert!(s.held.is_empty());
    }

    #[test]
    fn due_time_honours_both_requested_delay_and_retry_not_before() {
        let mut entry = queued("1-0", "https://peer");
        assert_eq!(due_at_ms(&entry), 0);
        entry.delay_milli = 500;
        assert_eq!(due_at_ms(&entry), 1_500);
        entry.not_before_ms = 2_000;
        assert_eq!(due_at_ms(&entry), 2_000);
    }

    // --- decode_tsp_forward tests ---

    #[test]
    fn decode_tsp_forward_recovers_qb2_and_passes_didcomm_through() {
        use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};

        // A TSP message (leads with the 0xF8 -E count-code magic byte) queued as base64url(qb2).
        let qb2 = [0xF8u8, 0x40, 0x13, 1, 2, 3, 4];
        let queued = BASE64_URL_SAFE_NO_PAD.encode(qb2);
        assert!(queued.starts_with("-E"), "qb64 envelope-code prefix");
        assert_eq!(
            decode_tsp_forward(&queued).as_deref(),
            Some(&qb2[..]),
            "a TSP forward decodes back to the exact qb2 bytes"
        );

        // DIDComm messages (JSON or compact) are not TSP — sent verbatim.
        assert!(decode_tsp_forward("{\"protected\":\"...\"}").is_none());
        assert!(decode_tsp_forward("eyJhbGciOiJ...").is_none());
        assert!(decode_tsp_forward("").is_none());
    }

    // --- http_to_ws_url tests ---

    #[test]
    fn test_http_to_ws_url_https() {
        assert_eq!(
            ForwardingProcessor::http_to_ws_url("https://example.com/path"),
            "wss://example.com/path/ws"
        );
    }

    #[test]
    fn test_http_to_ws_url_http() {
        assert_eq!(
            ForwardingProcessor::http_to_ws_url("http://example.com/path"),
            "ws://example.com/path/ws"
        );
    }

    #[test]
    fn test_http_to_ws_url_with_trailing_slash() {
        assert_eq!(
            ForwardingProcessor::http_to_ws_url("https://example.com/"),
            "wss://example.com/ws"
        );
    }

    #[test]
    fn test_http_to_ws_url_plain_domain() {
        assert_eq!(
            ForwardingProcessor::http_to_ws_url("https://mediator.example.com"),
            "wss://mediator.example.com/ws"
        );
    }

    #[test]
    fn test_http_to_ws_url_with_port() {
        assert_eq!(
            ForwardingProcessor::http_to_ws_url("http://localhost:8080/didcomm"),
            "ws://localhost:8080/didcomm/ws"
        );
    }

    // --- EndpointRateTracker tests ---

    #[test]
    fn test_rate_tracker_new_has_zero_rate() {
        let mut tracker = EndpointRateTracker::new(60);
        assert_eq!(tracker.current_rate(), 0.0);
    }

    #[test]
    fn test_rate_tracker_record_increases_rate() {
        let mut tracker = EndpointRateTracker::new(60);
        let rate = tracker.record_and_rate(1);
        // 1 message in 60 seconds = 1/60 * 10 = 0.1667 msgs/10s
        assert!(rate > 0.0);
    }

    #[test]
    fn test_rate_tracker_batch_record() {
        let mut tracker = EndpointRateTracker::new(60);
        let rate = tracker.record_and_rate(10);
        // 10 messages in 60 second window = 10/60 * 10 = ~1.667 msgs/10s
        assert!(rate > 1.0, "rate should be > 1.0, got {rate}");
        assert!(rate < 2.0, "rate should be < 2.0, got {rate}");
    }

    #[test]
    fn test_rate_tracker_multiple_records() {
        let mut tracker = EndpointRateTracker::new(60);
        tracker.record_and_rate(5);
        tracker.record_and_rate(5);
        let rate = tracker.current_rate();
        // 10 messages in 60 second window
        assert!(rate > 1.0, "rate should be > 1.0, got {rate}");
        assert!(rate < 2.0, "rate should be < 2.0, got {rate}");
    }

    #[test]
    fn test_rate_tracker_zero_window_returns_zero() {
        let mut tracker = EndpointRateTracker::new(0);
        let rate = tracker.record_and_rate(1);
        assert_eq!(rate, 0.0);
    }

    // --- calculate_backoff tests ---

    /// Helper to test calculate_backoff without needing a full ForwardingProcessor.
    /// Replicates the same formula: base * 2^min(failures, 10), capped at max.
    fn compute_backoff(
        initial_backoff_ms: u64,
        max_backoff_ms: u64,
        consecutive_failures: u32,
    ) -> Duration {
        let base = initial_backoff_ms;
        let max = max_backoff_ms;
        let backoff = base.saturating_mul(2u64.saturating_pow(consecutive_failures.min(10)));
        Duration::from_millis(backoff.min(max))
    }

    #[test]
    fn test_backoff_zero_failures() {
        // 2^0 = 1, so backoff = initial_backoff_ms * 1 = 1000ms
        let backoff = compute_backoff(1000, 60000, 0);
        assert_eq!(backoff, Duration::from_millis(1000));
    }

    #[test]
    fn test_backoff_one_failure() {
        // 2^1 = 2, so backoff = 1000 * 2 = 2000ms
        let backoff = compute_backoff(1000, 60000, 1);
        assert_eq!(backoff, Duration::from_millis(2000));
    }

    #[test]
    fn test_backoff_three_failures() {
        // 2^3 = 8, so backoff = 1000 * 8 = 8000ms
        let backoff = compute_backoff(1000, 60000, 3);
        assert_eq!(backoff, Duration::from_millis(8000));
    }

    #[test]
    fn test_backoff_capped_at_max() {
        // 2^6 = 64, so 1000 * 64 = 64000ms, but max is 60000ms
        let backoff = compute_backoff(1000, 60000, 6);
        assert_eq!(backoff, Duration::from_millis(60000));
    }

    #[test]
    fn test_backoff_high_failures_capped_exponent_at_10() {
        // Failures > 10 should be clamped to 10: 2^10 = 1024
        // 1000 * 1024 = 1024000, but max is 60000
        let backoff = compute_backoff(1000, 60000, 20);
        assert_eq!(backoff, Duration::from_millis(60000));
    }

    #[test]
    fn test_backoff_custom_initial_and_max() {
        // initial=500, max=5000, failures=2 => 500 * 4 = 2000
        let backoff = compute_backoff(500, 5000, 2);
        assert_eq!(backoff, Duration::from_millis(2000));

        // failures=4 => 500 * 16 = 8000, capped at 5000
        let backoff = compute_backoff(500, 5000, 4);
        assert_eq!(backoff, Duration::from_millis(5000));
    }

    #[test]
    fn test_backoff_saturating_prevents_overflow() {
        // Very large initial_backoff_ms should not panic
        let backoff = compute_backoff(u64::MAX / 2, 60000, 5);
        // Should be capped at max_backoff_ms
        assert_eq!(backoff, Duration::from_millis(60000));
    }

    // --- WebSocket suppression tests ---

    fn endpoint_state(ws_suppressed_until: Option<Instant>) -> EndpointState {
        EndpointState {
            rate_tracker: EndpointRateTracker::new(300),
            last_activity: Instant::now(),
            consecutive_failures: 0,
            retry_after_ms: 0,
            ws_suppressed_until,
        }
    }

    #[test]
    fn ws_is_not_suppressed_by_default() {
        assert!(!endpoint_state(None).ws_suppressed(Instant::now()));
    }

    #[test]
    fn ws_is_suppressed_inside_the_window_and_free_after_it() {
        let now = Instant::now();
        let state = endpoint_state(Some(now + WS_SUPPRESSION_WINDOW));

        assert!(state.ws_suppressed(now));
        assert!(state.ws_suppressed(now + WS_SUPPRESSION_WINDOW - Duration::from_secs(1)));
        // The window is half-open: at the deadline the endpoint is re-probed.
        assert!(!state.ws_suppressed(now + WS_SUPPRESSION_WINDOW));
        assert!(!state.ws_suppressed(now + WS_SUPPRESSION_WINDOW + Duration::from_secs(1)));
    }

    /// The suppression window must outlast the rate tracker's 10s window,
    /// which is what put the endpoint on WebSocket in the first place —
    /// otherwise a busy peer is re-probed on every batch and the suppression
    /// buys nothing. (An endpoint quiet for `ENDPOINT_IDLE_TTL` is reaped
    /// along with its suppression, which is the intended reset: the next
    /// forward to a long-silent peer probes afresh.)
    #[test]
    fn ws_suppression_window_outlasts_the_rate_window() {
        assert!(WS_SUPPRESSION_WINDOW > Duration::from_secs(10));
    }

    // --- WebSocket relay ---

    type Pool = Arc<Mutex<HashMap<String, PooledWebSocket>>>;

    fn limits(attempt_ms: u64, connect_ms: u64) -> WsLimits {
        WsLimits {
            attempt: Duration::from_millis(attempt_ms),
            connect: Duration::from_millis(connect_ms),
            per_address_min: Duration::from_millis(100),
            close: Duration::from_millis(200),
        }
    }

    fn resolved_to(
        addr: std::net::SocketAddr,
    ) -> impl FnOnce() -> std::future::Ready<Result<Vec<std::net::SocketAddr>, String>> {
        move || std::future::ready(Ok(vec![addr]))
    }

    /// Accepts TCP connections and never says anything on them.
    async fn silent_listener() -> std::net::SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("local addr");
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((socket, _)) = listener.accept().await {
                held.push(socket);
            }
        });
        addr
    }

    /// A peer that speaks `relay-ack`.
    struct RelayPeer {
        addr: std::net::SocketAddr,
        /// The `Host` header of each upgrade it accepted.
        hosts: Arc<std::sync::Mutex<Vec<String>>>,
    }

    /// Accepts the upgrade, records its `Host`, and acknowledges each frame
    /// after `ack_delay` — or never, if `None`.
    async fn relay_peer(ack_delay: Option<Duration>) -> RelayPeer {
        relay_peer_closing(ack_delay, false).await
    }

    /// As [`relay_peer`]; with `close_after_ack`, each connection is dropped
    /// right after its first ack.
    async fn relay_peer_closing(ack_delay: Option<Duration>, close_after_ack: bool) -> RelayPeer {
        use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let hosts = Arc::new(std::sync::Mutex::new(Vec::new()));
        let seen = hosts.clone();
        tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                let seen = seen.clone();
                tokio::spawn(async move {
                    // The error type is tungstenite's; this callback never uses it.
                    #[allow(clippy::result_large_err)]
                    let callback = |request: &Request, mut response: Response| {
                        let host = request
                            .headers()
                            .get("host")
                            .and_then(|h| h.to_str().ok())
                            .unwrap_or_default()
                            .to_string();
                        seen.lock().expect("hosts").push(host);
                        response.headers_mut().insert(
                            tungstenite::http::header::SEC_WEBSOCKET_PROTOCOL,
                            tungstenite::http::HeaderValue::from_static(RELAY_ACK_SUBPROTOCOL),
                        );
                        Ok(response)
                    };
                    let Ok(mut ws) = tokio_tungstenite::accept_hdr_async(socket, callback).await
                    else {
                        return;
                    };
                    while let Some(Ok(message)) = ws.next().await {
                        let tungstenite::Message::Text(text) = message else {
                            continue;
                        };
                        let Some(delay) = ack_delay else { continue };
                        tokio::time::sleep(delay).await;
                        let ack = RelayAck::accepted(frame_id(text.as_bytes()));
                        let ack = serde_json::to_string(&ack).expect("ack json");
                        if ws
                            .send(tungstenite::Message::Text(ack.into()))
                            .await
                            .is_err()
                            || close_after_ack
                        {
                            return;
                        }
                    }
                });
            }
        });
        RelayPeer { addr, hosts }
    }

    /// A peer that accepts TCP and never completes the handshake costs only
    /// the connect limit, does not hold the pool, and does not hold up a relay
    /// to another endpoint meanwhile.
    #[tokio::test]
    async fn a_handshake_that_never_completes_times_out_without_holding_anything() {
        let pool: Pool = Arc::new(Mutex::new(HashMap::new()));
        let stalled = silent_listener().await;
        let healthy = relay_peer(Some(Duration::ZERO)).await;

        let stalled_pool = pool.clone();
        let started = Instant::now();
        let stalled_relay = tokio::spawn(async move {
            relay_frame(
                &stalled_pool,
                "stalled",
                &format!("ws://{stalled}/ws"),
                resolved_to(stalled),
                "frame-a",
                &frame_id(b"frame-a"),
                limits(10_000, 1_500),
            )
            .await
        });

        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            pool.try_lock().is_ok(),
            "the pool lock is free while a handshake is under way"
        );

        let ws_url = format!("ws://{}/ws", healthy.addr);
        relay_frame(
            &pool,
            "healthy",
            &ws_url,
            resolved_to(healthy.addr),
            "frame-b",
            &frame_id(b"frame-b"),
            limits(10_000, 1_500),
        )
        .await
        .expect("the other endpoint is relayed to meanwhile");
        assert!(
            !stalled_relay.is_finished(),
            "relayed before the stall ended"
        );

        let err = stalled_relay
            .await
            .expect("join")
            .expect_err("a stalled handshake fails");
        let elapsed = started.elapsed();
        assert!(err.contains("did not complete"), "{err}");
        assert!(elapsed < Duration::from_secs(5), "took {elapsed:?}");
        let pool = pool.lock().await;
        assert!(!pool.contains_key("stalled"));
        assert!(pool.contains_key("healthy"));
    }

    /// While a frame is in flight on a pooled socket, the socket is out of the
    /// pool and the pool lock is free; afterwards the same socket is back.
    #[tokio::test]
    async fn a_pooled_socket_is_out_of_the_pool_while_in_use() {
        let peer = relay_peer(Some(Duration::from_millis(400))).await;
        let pool: Pool = Arc::new(Mutex::new(HashMap::new()));
        let ws_url = format!("ws://{}/ws", peer.addr);

        relay_frame(
            &pool,
            "peer",
            &ws_url,
            resolved_to(peer.addr),
            "first",
            &frame_id(b"first"),
            limits(5_000, 1_000),
        )
        .await
        .expect("first frame acked");
        assert_eq!(pool.lock().await.len(), 1);

        let in_flight = pool.clone();
        let url = ws_url.clone();
        let second = tokio::spawn(async move {
            relay_frame(
                &in_flight,
                "peer",
                &url,
                || async { Err("a pooled socket was available".to_string()) },
                "second",
                &frame_id(b"second"),
                limits(5_000, 1_000),
            )
            .await
        });
        tokio::time::sleep(Duration::from_millis(150)).await;
        {
            let guard = pool.try_lock().expect("pool lock is free during I/O");
            assert!(guard.is_empty(), "the socket in use is not in the pool");
        }
        second.await.expect("join").expect("second frame acked");
        assert_eq!(pool.lock().await.len(), 1);
        assert_eq!(peer.hosts.lock().expect("hosts").len(), 1, "one connection");
    }

    /// The connection goes to the address that was checked, while the request
    /// still names the host.
    #[tokio::test]
    async fn the_socket_is_opened_to_the_resolved_address_under_the_hosts_name() {
        let peer = relay_peer(Some(Duration::ZERO)).await;
        let pool: Pool = Arc::new(Mutex::new(HashMap::new()));
        let port = peer.addr.port();

        relay_frame(
            &pool,
            "named",
            &format!("ws://relay.invalid:{port}/ws"),
            resolved_to(peer.addr),
            "frame",
            &frame_id(b"frame"),
            limits(5_000, 1_000),
        )
        .await
        .expect("acked");
        assert_eq!(
            peer.hosts.lock().expect("hosts").as_slice(),
            [format!("relay.invalid:{port}")]
        );
    }

    /// A peer that never acknowledges fails the frame at the attempt's
    /// deadline, and its socket is not kept.
    #[tokio::test]
    async fn a_missing_ack_fails_at_the_deadline_and_the_socket_is_dropped() {
        let peer = relay_peer(None).await;
        let pool: Pool = Arc::new(Mutex::new(HashMap::new()));
        let started = Instant::now();

        let err = relay_frame(
            &pool,
            "silent",
            &format!("ws://{}/ws", peer.addr),
            resolved_to(peer.addr),
            "frame",
            &frame_id(b"frame"),
            limits(500, 400),
        )
        .await
        .expect_err("no ack, no delivery");
        assert!(err.contains("no relay-ack"), "{err}");
        assert!(started.elapsed() < Duration::from_secs(3));
        assert!(pool.lock().await.is_empty());
    }

    /// No address to connect to is an error, not a hang.
    #[tokio::test]
    async fn a_failed_resolution_fails_the_attempt() {
        let pool: Pool = Arc::new(Mutex::new(HashMap::new()));
        let err = relay_frame(
            &pool,
            "unresolved",
            "ws://relay.invalid/ws",
            || async { Err("resolution refused".to_string()) },
            "frame",
            &frame_id(b"frame"),
            limits(500, 400),
        )
        .await
        .expect_err("nothing to connect to");
        assert!(err.contains("resolution refused"), "{err}");
    }

    /// An IP-literal host is dialed as given; there is nothing to look up.
    #[tokio::test]
    async fn an_ip_literal_resolves_to_itself() {
        let policy = EgressPolicy::public_internet();
        let vetted = policy
            .vet("wss://93.184.216.34/ws")
            .expect("public literal");
        let addrs = resolve_vetted(GuardedResolver::new(policy), vetted)
            .await
            .expect("resolved");
        assert_eq!(addrs, vec!["93.184.216.34:443".parse().unwrap()]);
    }

    /// A name that resolves to an address the policy does not admit is
    /// refused, and nothing is returned to dial.
    #[tokio::test]
    async fn a_name_resolving_to_a_private_address_is_refused() {
        use reqwest::dns::{Addrs, Name, Resolve, Resolving};

        struct Private;
        impl Resolve for Private {
            fn resolve(&self, _: Name) -> Resolving {
                Box::pin(async {
                    let addrs: Vec<std::net::SocketAddr> = vec![
                        "93.184.216.34:0".parse().unwrap(),
                        "10.0.0.7:0".parse().unwrap(),
                    ];
                    Ok(Box::new(addrs.into_iter()) as Addrs)
                })
            }
        }

        let policy = EgressPolicy::public_internet();
        let vetted = policy.vet("wss://relay.example.com/ws").expect("vetted");
        let resolver = GuardedResolver::new(policy).with_inner(Arc::new(Private));
        let err = resolve_vetted(resolver, vetted)
            .await
            .expect_err("a private answer fails the name");
        assert!(err.contains("relay.example.com"), "{err}");
    }

    /// The WebSocket attempt always leaves part of the delivery attempt for
    /// the REST fallback, however short the delivery timeout is.
    #[test]
    fn the_websocket_attempt_leaves_time_for_the_fallback() {
        let default = ws_limits_for(Duration::from_secs(90));
        assert_eq!(default.attempt, Duration::from_secs(30));
        assert_eq!(default.connect, Duration::from_secs(10));

        for secs in [1, 5, 20, 45, 60] {
            let delivery = Duration::from_secs(secs);
            let limits = ws_limits_for(delivery);
            assert!(limits.attempt * 3 <= delivery, "{secs}s: {limits:?}");
            assert!(limits.connect <= limits.attempt, "{secs}s: {limits:?}");
        }
    }

    /// An address that accepts and never completes the handshake gets only
    /// its share of the connect time; the next address is then tried.
    #[tokio::test]
    async fn an_unresponsive_first_address_does_not_use_up_the_connect_time() {
        let stalled = silent_listener().await;
        let peer = relay_peer(Some(Duration::ZERO)).await;
        let pool: Pool = Arc::new(Mutex::new(HashMap::new()));
        let port = peer.addr.port();
        let second = peer.addr;
        let started = Instant::now();

        relay_frame(
            &pool,
            "two-addresses",
            &format!("ws://relay.invalid:{port}/ws"),
            move || std::future::ready(Ok(vec![stalled, second])),
            "frame",
            &frame_id(b"frame"),
            limits(5_000, 2_000),
        )
        .await
        .expect("the second address answers");
        let elapsed = started.elapsed();
        assert!(elapsed < Duration::from_millis(1_800), "{elapsed:?}");
        assert_eq!(peer.hosts.lock().expect("hosts").len(), 1);
    }

    /// The connect error names the time actually allowed, which is what is
    /// left of the attempt when that is less than the connect limit.
    #[tokio::test]
    async fn the_connect_error_reports_the_time_allowed() {
        let stalled = silent_listener().await;
        let pool: Pool = Arc::new(Mutex::new(HashMap::new()));
        let err = relay_frame(
            &pool,
            "stalled",
            &format!("ws://{stalled}/ws"),
            resolved_to(stalled),
            "frame",
            &frame_id(b"frame"),
            limits(300, 10_000),
        )
        .await
        .expect_err("stalled");
        // What was left of the 300 ms attempt, not the 10 s connect limit.
        let allowed: u64 = err
            .split("within the ")
            .nth(1)
            .and_then(|rest| rest.split(" ms allowed").next())
            .and_then(|ms| ms.parse().ok())
            .unwrap_or_else(|| panic!("{err}"));
        assert!((200..=300).contains(&allowed), "{err}");
    }

    /// A pooled socket the peer has since closed is discarded and a new
    /// connection carries the frame.
    #[tokio::test]
    async fn a_closed_pooled_socket_is_replaced_by_a_new_connection() {
        let peer = relay_peer_closing(Some(Duration::ZERO), true).await;
        let pool: Pool = Arc::new(Mutex::new(HashMap::new()));
        let ws_url = format!("ws://{}/ws", peer.addr);

        for frame in ["first", "second"] {
            relay_frame(
                &pool,
                "peer",
                &ws_url,
                resolved_to(peer.addr),
                frame,
                &frame_id(frame.as_bytes()),
                limits(5_000, 1_000),
            )
            .await
            .unwrap_or_else(|e| panic!("{frame}: {e}"));
            // Let the peer's close reach this side.
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert_eq!(
            peer.hosts.lock().expect("hosts").len(),
            2,
            "reconnected once"
        );
        assert_eq!(pool.lock().await.len(), 1);
    }
}

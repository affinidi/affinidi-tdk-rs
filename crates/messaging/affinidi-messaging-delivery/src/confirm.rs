//! End-to-end delivery confirmation (§5a): the `Sent → Delivered | Unconfirmed`
//! transitions.
//!
//! A `Sent` entry is hop-accepted (durably queued at the mediator), **not**
//! delivered. It is watched until either:
//!
//! - **evidence arrives** → [`confirm_delivered`] transitions it `Delivered`
//!   (the strongest evidence — a layer receipt — proves the recipient has and
//!   will process the message; a correlated protocol reply is equivalent); or
//! - **the delivery window passes with no evidence** → the sweep
//!   ([`sweep_confirmations`]) settles it `Unconfirmed`, a truthful "we can't
//!   know", never a false "delivered".
//!
//! This module owns the state machine. The *evidence sources* — the receiver
//! auto-emitting a layer receipt on durable persist, the mediator's receipts
//! for collection, and re-sending over an alternate binding on expiry — layer
//! on top and call [`confirm_delivered`] / drive the sweep. A message merely
//! gone from the mediator's outbox listing is not one of them: it may have
//! been collected or may have expired, and the listing cannot say which.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use affinidi_messaging_core::{DeliveryScope, MessageTransport, OutboxStatus};

use crate::outbox::{OutboxEntry, OutboxError, OutboxState, OutboxStore, UnconfirmedReason};
use crate::reach::ReceiptReach;

/// What one confirmation sweep settled.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ConfirmReport {
    /// Expired `Sent` entries settled `Unconfirmed` — no end-to-end evidence was
    /// possible (no layer, no reply, no pickup).
    pub unconfirmed: usize,
    /// Expired `Sent` entries settled `Failed` — delivery-critical, escalation
    /// exhausted. **Surface these** (metric + operator alert).
    pub failed: usize,
    /// Expired `Sent` entries **re-sent over an alternate binding** and re-armed
    /// with a fresh window (a dead mediator ≠ a dead peer); still watched.
    pub rebound: usize,
    /// Expired relayed entries settled `Unconfirmed` with
    /// [`UnconfirmedReason::NoEvidencePath`]: no class of evidence was available
    /// on the path, so they were recorded *unconfirmable* and not escalated
    /// (VTI-TRN-042, VTI-TRN-064). Not a failure. Also counted in
    /// [`unconfirmed`](Self::unconfirmed).
    pub unconfirmable: usize,
}

/// How an expired, still-unconfirmed `Sent` entry is escalated (§5a) — the
/// window passing is **never** a silent success. Returned by an
/// [`ExpiryEscalator`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Escalation {
    /// The escalator re-resolved the peer and **re-sent over an alternate
    /// binding** (another transport/mediator the DID document offers). Keep
    /// watching until `deliver_by_ms`, correlating the new hop via `hop_id`. The
    /// entry stays `Sent` (re-hop-accepted on the alternate); the previous
    /// outbox observation is reset.
    Rebound {
        /// The fresh delivery window for the re-sent message.
        deliver_by_ms: u64,
        /// The alternate hop's id, for outbox-drain correlation (`None` if the
        /// alternate binding returns no id).
        hop_id: Option<String>,
        /// Whether the alternate binding's mediator holds the message for the
        /// recipient ([`DeliveryScope`]); `Unknown` if the escalator cannot
        /// tell, which is polled as before.
        scope: DeliveryScope,
    },
    /// No alternate binding is possible (a dead mediator with no fallback) → the
    /// delivery-critical send **failed**; surface it. Distinct from a silent
    /// drop and from `Unconfirmed`.
    Failed,
    /// No end-to-end evidence was ever possible for this recipient (no layer, no
    /// reply, never picks up) → a truthful "we can't know", not a failure.
    Unconfirmed,
}

/// The escalation policy the confirmation sweep applies when a `Sent` entry's
/// delivery window expires with no evidence.
///
/// The concrete escalator — which re-resolves the peer's DID document and
/// re-sends over an alternate transport/mediator — is wired by the service that
/// owns the transports (it lands with multi-transport / Phase 4); the delivery
/// layer only applies the [`Escalation`] outcome. The default policy (no
/// escalator, i.e. [`sweep_confirmations`]) settles every expired entry
/// `Unconfirmed`.
#[async_trait::async_trait]
pub trait ExpiryEscalator: Send + Sync {
    /// Decide how the expired, still-unconfirmed `entry` escalates. Any
    /// alternate-binding re-send is the escalator's own work; it reports the
    /// outcome here.
    async fn escalate(&self, entry: &OutboxEntry) -> Escalation;
}

/// The default policy: settle every expired entry `Unconfirmed` (no alternate
/// binding attempted). What [`sweep_confirmations`] uses.
struct SettleUnconfirmed;

#[async_trait::async_trait]
impl ExpiryEscalator for SettleUnconfirmed {
    async fn escalate(&self, _entry: &OutboxEntry) -> Escalation {
        Escalation::Unconfirmed
    }
}

/// Record end-to-end delivery evidence for `idempotency_key`: transition its
/// outbox entry `Sent → Delivered`.
///
/// Returns `Ok(true)` if an entry was transitioned, `Ok(false)` if there was no
/// matching `Sent` entry (absent, or already terminal — evidence is
/// **idempotent**, so a re-delivered receipt for an already-`Delivered` entry is
/// a harmless no-op).
pub async fn confirm_delivered(
    store: &dyn OutboxStore,
    idempotency_key: &str,
) -> Result<bool, OutboxError> {
    if let Some(mut entry) = store.get(idempotency_key).await?
        && entry.state == OutboxState::Sent
    {
        entry.state = OutboxState::Delivered;
        store.put(entry).await?;
        return Ok(true);
    }
    Ok(false)
}

/// Record delivery evidence for `idempotency_key` that came **from `peer`**:
/// transition its outbox entry `Sent → Delivered` only if `peer` is the entry's
/// recipient.
///
/// A layer receipt or an in-thread reply is evidence that *the recipient* has
/// the message; the same bytes from anyone else say nothing about it. `peer`
/// must be the sender the transport authenticated (`ReceivedMessage::sender`
/// with `verified` set), and it is compared with [`OutboxEntry::dest_did`] by
/// DID, ignoring a `did:scid` `src` locator. Evidence from any other peer
/// leaves the entry as it is and returns `Ok(false)`, as for an unknown key.
///
/// [`confirm_delivered`] remains for evidence the caller has already tied to
/// the recipient itself.
pub async fn confirm_delivered_by(
    store: &dyn OutboxStore,
    idempotency_key: &str,
    peer: &str,
) -> Result<bool, OutboxError> {
    if let Some(mut entry) = store.get(idempotency_key).await?
        && entry.state == OutboxState::Sent
        && affinidi_did_common::scid::same_reference(peer, &entry.dest_did)
    {
        entry.state = OutboxState::Delivered;
        store.put(entry).await?;
        return Ok(true);
    }
    Ok(false)
}

/// One confirmation sweep at logical time `now_ms`: any `Sent` entry whose
/// delivery window has passed without evidence settles `Unconfirmed`.
///
/// `Unconfirmed` is deliberately distinct from `Failed`: the message *was*
/// hop-accepted (the mediator took it), we just never got end-to-end evidence —
/// a truthful "we can't know", not "delivery failed". (A `Queued` entry that
/// expires before it can even hop-accept is the drain's `Failed` case.)
///
/// To escalate expired entries — re-send over an alternate binding, or fail
/// visibly — instead of always settling `Unconfirmed`, use
/// [`sweep_confirmations_with`].
pub async fn sweep_confirmations(
    store: &dyn OutboxStore,
    now_ms: u64,
) -> Result<ConfirmReport, OutboxError> {
    sweep_confirmations_with(store, now_ms, &SettleUnconfirmed).await
}

/// One confirmation sweep that **escalates** each expired `Sent` entry through
/// `escalator` (§5a) rather than always settling `Unconfirmed`, knowing no
/// recipient to send receipts.
///
/// [`sweep_confirmations_with_reach`] with an empty [`ReceiptReach`]: every
/// expired [`DeliveryScope::Relayed`] entry is recorded unconfirmable without
/// consulting `escalator`. A service that runs a [`MessagingService`] passes
/// its [`receipt_reach`] to [`sweep_confirmations_with_reach`] instead, so a
/// recipient known to send receipts is escalated.
///
/// [`MessagingService`]: crate::MessagingService
/// [`receipt_reach`]: crate::MessagingService::receipt_reach
pub async fn sweep_confirmations_with(
    store: &dyn OutboxStore,
    now_ms: u64,
    escalator: &dyn ExpiryEscalator,
) -> Result<ConfirmReport, OutboxError> {
    sweep_confirmations_with_reach(store, now_ms, escalator, &ReceiptReach::new()).await
}

/// One confirmation sweep that **escalates** each expired `Sent` entry through
/// `escalator` (§5a) rather than always settling `Unconfirmed`: the window
/// passing is never a silent success.
///
/// An expired [`DeliveryScope::Relayed`] entry whose recipient `reach` does not
/// know to send receipts had no evidence path at all: its sender's mediator
/// relayed it away and cannot answer, and no receipt was coming. It settles
/// `Unconfirmed` with [`UnconfirmedReason::NoEvidencePath`], logged at `info`,
/// and `escalator` is not asked — re-sending over another binding would hand
/// the recipient a second copy of a message it may have had for an hour
/// (VTI-TRN-042, amended). A relayed entry to a recipient known to send
/// receipts is escalated like any other: for it, silence means something.
///
/// Every other expired entry takes the [`Escalation`] outcome:
/// - [`Escalation::Rebound`] → re-armed with the fresh window, hop and scope,
///   still `Sent` (the escalator already re-sent over the alternate binding),
///   the earlier outbox observation reset so a later drain is unambiguous;
/// - [`Escalation::Failed`] → `Failed` (surface it);
/// - [`Escalation::Unconfirmed`] → `Unconfirmed`, with
///   [`UnconfirmedReason::WindowPassed`].
pub async fn sweep_confirmations_with_reach(
    store: &dyn OutboxStore,
    now_ms: u64,
    escalator: &dyn ExpiryEscalator,
    reach: &ReceiptReach,
) -> Result<ConfirmReport, OutboxError> {
    let mut report = ConfirmReport::default();
    for mut entry in store.awaiting_confirmation().await? {
        if now_ms < entry.deliver_by_ms {
            continue;
        }
        if entry.scope == DeliveryScope::Relayed && !reach.sends_receipts(&entry.dest_did, now_ms) {
            tracing::info!(
                idempotency_key = %entry.idempotency_key,
                dest = %entry.dest_did,
                "delivery unconfirmable: relayed to the recipient's own mediator, and the \
                 recipient is not known to send receipts; not escalated"
            );
            entry.state = OutboxState::Unconfirmed;
            entry.unconfirmed_reason = Some(UnconfirmedReason::NoEvidencePath);
            store.put(entry).await?;
            report.unconfirmed += 1;
            report.unconfirmable += 1;
            continue;
        }
        match escalator.escalate(&entry).await {
            Escalation::Rebound {
                deliver_by_ms,
                hop_id,
                scope,
            } => {
                entry.deliver_by_ms = deliver_by_ms;
                entry.hop_id = hop_id;
                entry.scope = scope;
                entry.outbox_observed = false;
                // Stays Sent: the escalator re-sent over the alternate binding
                // and it hop-accepted; we keep watching for evidence.
                store.put(entry).await?;
                report.rebound += 1;
            }
            Escalation::Failed => {
                entry.state = OutboxState::Failed;
                store.put(entry).await?;
                report.failed += 1;
            }
            Escalation::Unconfirmed => {
                entry.state = OutboxState::Unconfirmed;
                entry.unconfirmed_reason = Some(UnconfirmedReason::WindowPassed);
                store.put(entry).await?;
                report.unconfirmed += 1;
            }
        }
    }
    Ok(report)
}

/// Run [`sweep_confirmations`] every `interval`, forever (until the task is
/// dropped), using the wall clock. A store error on one tick is logged and
/// retried on the next.
pub async fn confirmation_loop(store: Arc<dyn OutboxStore>, interval: Duration) {
    confirmation_loop_with(store, interval, Arc::new(SettleUnconfirmed)).await
}

/// Run [`sweep_confirmations_with`] every `interval`, forever, escalating
/// expired entries through `escalator`. Logs a warning tick whenever entries
/// `Failed` (the operator-alert surface) and a debug tick for rebinds. A store
/// error on one tick is logged and retried on the next.
pub async fn confirmation_loop_with(
    store: Arc<dyn OutboxStore>,
    interval: Duration,
    escalator: Arc<dyn ExpiryEscalator>,
) {
    confirmation_loop_with_reach(store, interval, escalator, Arc::new(ReceiptReach::new())).await
}

/// [`confirmation_loop_with`], escalating a relayed entry only when `reach`
/// knows its recipient to send receipts (see
/// [`sweep_confirmations_with_reach`]). Pass the
/// [`MessagingService::receipt_reach`](crate::MessagingService::receipt_reach)
/// of the service whose dispatcher sees the receipts.
pub async fn confirmation_loop_with_reach(
    store: Arc<dyn OutboxStore>,
    interval: Duration,
    escalator: Arc<dyn ExpiryEscalator>,
    reach: Arc<ReceiptReach>,
) {
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        ticker.tick().await;
        match sweep_confirmations_with_reach(
            store.as_ref(),
            now_unix_ms(),
            escalator.as_ref(),
            reach.as_ref(),
        )
        .await
        {
            Ok(report) if report.failed > 0 => {
                tracing::warn!(
                    failed = report.failed,
                    unconfirmed = report.unconfirmed,
                    rebound = report.rebound,
                    "delivery window expired with no evidence and no alternate binding — messages FAILED",
                );
            }
            Ok(report) if report != ConfirmReport::default() => {
                tracing::debug!(
                    unconfirmed = report.unconfirmed,
                    unconfirmable = report.unconfirmable,
                    rebound = report.rebound,
                    "confirmation sweep escalated expired entries",
                );
            }
            Ok(_) => {}
            Err(e) => {
                tracing::warn!(error = %e, "confirmation sweep failed; retrying next tick")
            }
        }
    }
}

/// What one [`poll_outbox_drain`] pass observed.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct DrainPollReport {
    /// `Sent` entries confirmed `Delivered` because the mediator's receipt says
    /// the recipient collected them ([`MessageTransport::outbox_status`]).
    pub delivered: usize,
    /// `Sent` entries seen still present in the outbox this pass (awaiting pickup).
    pub observed: usize,
    /// `Sent` entries settled `Failed` because the mediator's receipt says the
    /// message was removed before the recipient took it (discarded or
    /// withdrawn). Only [`MessageTransport::outbox_status`] can report this.
    pub lost: usize,
    /// `Sent` entries seen in the outbox listing earlier and absent from it
    /// now. Collected or expired: the listing cannot tell which, so they stay
    /// `Sent` and settle by their window (`Unconfirmed`, or whatever an
    /// [`ExpiryEscalator`] decides). Only the listing fallback counts these.
    pub drained: usize,
}

/// How many hop-ids one [`MessageTransport::outbox_status`] call asks about —
/// the `messaging/message/status/0.1` per-request cap.
const STATUS_BATCH: usize = 100;

/// Poll the transport's outbox for §5a **outbox-drain** evidence.
///
/// When the transport reports the mediator's receipts
/// ([`MessageTransport::outbox_status`]), those settle each entry and nothing
/// below applies — see [`poll_outbox_status`]. What follows is the fallback
/// for a transport or mediator without them.
///
/// The mediator holds a sent message in the sender's outbox until the recipient
/// acks pickup or the message expires, then deletes it. A `Sent` entry whose
/// `hop_id` is present in [`MessageTransport::outbox_message_ids`] is marked
/// observed. One that was observed and is now absent is counted
/// [`drained`](DrainPollReport::drained) but **not** settled: absence is the
/// same for a pickup and an expiry, so it is no evidence of delivery. The
/// entry stays `Sent` and settles by its window. The same holds for a listing
/// that is capped or paged and leaves the entry out.
///
/// A transport that gives no outbox signal (`outbox_message_ids` returns `None`,
/// e.g. a stateless REST POST) yields an empty report.
pub async fn poll_outbox_drain(
    transport: &dyn MessageTransport,
    store: &dyn OutboxStore,
) -> Result<DrainPollReport, OutboxError> {
    poll_outbox_drain_inner(transport, store, None).await
}

/// [`poll_outbox_drain`], asking the mediator about each `Sent` entry only as
/// often as [`StatusPacer`] says — what [`outbox_drain_loop`] runs.
pub async fn poll_outbox_drain_paced(
    transport: &dyn MessageTransport,
    store: &dyn OutboxStore,
    pacer: &mut StatusPacer,
    now_ms: u64,
) -> Result<DrainPollReport, OutboxError> {
    poll_outbox_drain_inner(transport, store, Some((pacer, now_ms))).await
}

/// How often the receipt poll asks about one `Sent` entry.
///
/// A message is collected soon after it is sent or not for a long while: a
/// live recipient takes it in milliseconds, and one that is offline collects
/// when it comes back, which may be days. Asking about every waiting entry on
/// every tick costs `ceil(sent / 100)` requests per tick for as long as the
/// longest window runs — a thirty-day notice to an identity that never returns
/// is asked about every ten seconds for thirty days. So an entry is asked about
/// less often the longer it has waited: every tick for its first five minutes,
/// then every minute to an hour, every ten minutes to a day, and hourly after.
///
/// An entry whose window closes within its period is asked about every tick
/// again, so a collection just before the deadline settles `Delivered` rather
/// than running out the window `Unconfirmed` — which an escalator would read as
/// a reason to send it another way.
///
/// The pacing is in memory: a restart asks about every entry once and paces
/// from there. It applies to receipts ([`MessageTransport::outbox_status`]),
/// which are per entry; the outbox listing fallback is one call however many
/// entries wait, and is not paced.
#[derive(Debug, Default)]
pub struct StatusPacer {
    last_asked: HashMap<String, u64>,
}

impl StatusPacer {
    /// A pacer that has asked about nothing yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// The minimum gap between two questions about `entry` at `now_ms`, or zero
    /// for "every tick".
    fn period_ms(entry: &OutboxEntry, now_ms: u64) -> u64 {
        const MIN: u64 = 60 * 1000;
        let waited = now_ms.saturating_sub(entry.created_at_ms);
        let period = if waited < 5 * MIN {
            0
        } else if waited < 60 * MIN {
            MIN
        } else if waited < 24 * 60 * MIN {
            10 * MIN
        } else {
            60 * MIN
        };
        if entry.deliver_by_ms.saturating_sub(now_ms) <= period {
            0
        } else {
            period
        }
    }

    fn is_due(&self, entry: &OutboxEntry, now_ms: u64) -> bool {
        match self.last_asked.get(entry.idempotency_key.as_str()) {
            None => true,
            Some(&last) => now_ms.saturating_sub(last) >= Self::period_ms(entry, now_ms),
        }
    }
}

async fn poll_outbox_drain_inner(
    transport: &dyn MessageTransport,
    store: &dyn OutboxStore,
    pacer: Option<(&mut StatusPacer, u64)>,
) -> Result<DrainPollReport, OutboxError> {
    if let Some(report) = poll_outbox_status(transport, store, pacer).await? {
        return Ok(report);
    }
    let entries: Vec<OutboxEntry> = store
        .awaiting_confirmation()
        .await?
        .into_iter()
        .filter(is_pollable)
        .collect();
    if entries.is_empty() {
        return Ok(DrainPollReport::default());
    }
    let Some(ids) = transport
        .outbox_message_ids()
        .await
        .map_err(|e| OutboxError::Backend(format!("outbox list failed: {e}")))?
    else {
        return Ok(DrainPollReport::default());
    };
    let present: HashSet<&str> = ids.iter().map(String::as_str).collect();

    let mut report = DrainPollReport::default();
    for mut entry in entries {
        let Some(hop_id) = entry.hop_id.clone() else {
            continue;
        };
        if present.contains(hop_id.as_str()) {
            // Still queued at the mediator — awaiting pickup. Record that we've
            // now seen it, so a later drain is unambiguous.
            if !entry.outbox_observed {
                entry.outbox_observed = true;
                store.put(entry).await?;
            }
            report.observed += 1;
        } else if entry.outbox_observed {
            // Was present, now gone: collected or expired, and the listing
            // cannot say which. Left `Sent` to settle by its window.
            report.drained += 1;
        }
        // else: absent and never observed → too early (eventual consistency); skip.
    }
    Ok(report)
}

/// Settle `Sent` entries from the mediator's receipts, when the transport can
/// report them. `None` when it cannot, and the caller falls back to the outbox
/// listing. A transport that stops answering partway (`None` for a later
/// batch) keeps what the earlier batches settled; the rest wait for the next
/// poll.
///
/// Receipts carry the same trust as the listing they replace — the mediator's
/// word (see [`MessageTransport::outbox_status`]) — and remove the two ways the
/// listing misread it.
///
/// Receipts replace that inference rather than supplement it. "Drained after
/// being observed" reads an expiry as a delivery, and a recipient that
/// collects before the first poll is never observed at all. A receipt says who
/// removed the message, so neither mistake is possible here. An entry the
/// mediator answers `Unknown` for is left alone — no receipt is no evidence —
/// and settles by its window as before.
async fn poll_outbox_status(
    transport: &dyn MessageTransport,
    store: &dyn OutboxStore,
    mut pacer: Option<(&mut StatusPacer, u64)>,
) -> Result<Option<DrainPollReport>, OutboxError> {
    let mut entries: Vec<OutboxEntry> = store
        .awaiting_confirmation()
        .await?
        .into_iter()
        .filter(is_pollable)
        .collect();
    if entries.is_empty() {
        if let Some((pacer, _)) = pacer.as_mut() {
            pacer.last_asked.clear();
        }
        return Ok(None);
    }
    if let Some((pacer, now_ms)) = pacer.as_mut() {
        // Forget entries no longer waiting, so the map holds what is in flight.
        let waiting: HashSet<&str> = entries.iter().map(|e| e.idempotency_key.as_str()).collect();
        pacer.last_asked.retain(|k, _| waiting.contains(k.as_str()));
        entries.retain(|e| pacer.is_due(e, *now_ms));
        if entries.is_empty() {
            // Entries wait, none is due: nothing to ask, and no reason to fall
            // back to the listing either.
            return Ok(Some(DrainPollReport::default()));
        }
    }

    let mut report = DrainPollReport::default();
    for (index, batch) in entries.chunks(STATUS_BATCH).enumerate() {
        let hop_ids: Vec<String> = batch
            .iter()
            .filter_map(|entry| entry.hop_id.clone())
            .collect();
        let answer = match transport.outbox_status(&hop_ids).await {
            Ok(answer) => answer,
            Err(e) if index == 0 => {
                return Err(OutboxError::Backend(format!("outbox status failed: {e}")));
            }
            Err(e) => {
                // Earlier batches were answered and settled; keep their
                // report. The rest are asked about on the next poll.
                tracing::warn!(error = %e, "outbox status failed partway; retrying the rest next tick");
                return Ok(Some(report));
            }
        };
        let Some(statuses) = answer else {
            if index == 0 {
                // No signal: use the outbox listing instead.
                return Ok(None);
            }
            // Earlier batches were answered and settled; report them.
            return Ok(Some(report));
        };
        // Each entry takes the status recorded under its own hop id, and
        // nothing else: an id the answer omits is no evidence, and a status
        // under an id not asked about settles nothing.
        if let Some((pacer, now_ms)) = pacer.as_mut() {
            for entry in batch {
                pacer
                    .last_asked
                    .insert(entry.idempotency_key.to_string(), *now_ms);
            }
        }
        for entry in batch.iter().cloned() {
            let status = entry
                .hop_id
                .as_ref()
                .and_then(|hop| statuses.get(hop).copied())
                .unwrap_or(OutboxStatus::Unknown);
            settle_from_status(store, entry, status, &mut report).await?;
        }
    }
    Ok(Some(report))
}

/// Whether the sender's mediator can say anything about `entry`: it has a hop
/// id, and it was not relayed to another mediator. A relayed entry is never
/// asked about — that mediator no longer holds it and can only answer
/// `unknown` (VTI-TRN-064: a sender MUST NOT poll for evidence it has
/// established is unavailable). An `Unknown` scope is polled, as every entry
/// was before scopes existed.
fn is_pollable(entry: &OutboxEntry) -> bool {
    entry.hop_id.is_some() && entry.scope != DeliveryScope::Relayed
}

async fn settle_from_status(
    store: &dyn OutboxStore,
    mut entry: OutboxEntry,
    status: OutboxStatus,
    report: &mut DrainPollReport,
) -> Result<(), OutboxError> {
    match status {
        OutboxStatus::Collected => {
            confirm_delivered(store, &entry.idempotency_key).await?;
            report.delivered += 1;
        }
        OutboxStatus::Discarded | OutboxStatus::Withdrawn => {
            entry.state = OutboxState::Failed;
            store.put(entry).await?;
            report.lost += 1;
        }
        OutboxStatus::Queued | OutboxStatus::Delivered => {
            if !entry.outbox_observed {
                entry.outbox_observed = true;
                store.put(entry).await?;
            }
            report.observed += 1;
        }
        // `Unknown`, or a state this build does not know: no evidence.
        _ => {}
    }
    Ok(())
}

/// Run [`poll_outbox_drain`] every `interval`, forever (until the task is
/// dropped). A store/transport error on one tick is logged and retried next.
pub async fn outbox_drain_loop(
    transport: Arc<dyn MessageTransport>,
    store: Arc<dyn OutboxStore>,
    interval: Duration,
) {
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut pacer = StatusPacer::new();
    loop {
        ticker.tick().await;
        match poll_outbox_drain_paced(
            transport.as_ref(),
            store.as_ref(),
            &mut pacer,
            now_unix_ms(),
        )
        .await
        {
            Ok(report) if report.lost > 0 => {
                tracing::warn!(
                    lost = report.lost,
                    delivered = report.delivered,
                    observed = report.observed,
                    "the mediator removed messages before their recipients collected them",
                );
            }
            Ok(report) if report.delivered > 0 || report.drained > 0 => {
                tracing::debug!(
                    delivered = report.delivered,
                    drained = report.drained,
                    observed = report.observed,
                    "outbox-drain poll",
                );
            }
            Ok(_) => {}
            Err(e) => tracing::warn!(error = %e, "outbox-drain poll failed; retrying next tick"),
        }
    }
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::outbox::{InMemoryOutboxStore, OutboxEntry};

    /// A `Sent` entry with `deliver_by = created + 60s`.
    async fn sent_entry(store: &InMemoryOutboxStore, key: &str, created: u64) {
        let mut e = OutboxEntry::new(key, "did:example:bob", vec![1], created, created + 60_000);
        e.state = OutboxState::Sent;
        store.put(e).await.unwrap();
    }

    #[tokio::test]
    async fn evidence_confirms_a_sent_entry_and_is_idempotent() {
        let store = InMemoryOutboxStore::new();
        sent_entry(&store, "k1", 1_000).await;

        assert!(confirm_delivered(&store, "k1").await.unwrap());
        assert_eq!(
            store.get("k1").await.unwrap().unwrap().state,
            OutboxState::Delivered
        );

        // Evidence is idempotent: a second (re-delivered) receipt is a no-op.
        assert!(!confirm_delivered(&store, "k1").await.unwrap());
        // Unknown key → no-op, not an error.
        assert!(!confirm_delivered(&store, "nope").await.unwrap());
    }

    #[tokio::test]
    async fn evidence_from_the_recipient_confirms_and_from_anyone_else_does_not() {
        let store = InMemoryOutboxStore::new();
        sent_entry(&store, "k1", 1_000).await;

        assert!(
            !confirm_delivered_by(&store, "k1", "did:example:carol")
                .await
                .unwrap()
        );
        assert_eq!(
            store.get("k1").await.unwrap().unwrap().state,
            OutboxState::Sent
        );

        assert!(
            confirm_delivered_by(&store, "k1", "did:example:bob")
                .await
                .unwrap()
        );
        assert_eq!(
            store.get("k1").await.unwrap().unwrap().state,
            OutboxState::Delivered
        );
    }

    #[tokio::test]
    async fn the_recipient_is_matched_by_did_ignoring_a_scid_source() {
        let store = InMemoryOutboxStore::new();
        let mut entry = OutboxEntry::new(
            "k1",
            "did:scid:vh:1:Qm?src=example.com/bob",
            vec![1],
            1_000,
            61_000,
        );
        entry.state = OutboxState::Sent;
        store.put(entry).await.unwrap();

        assert!(
            confirm_delivered_by(&store, "k1", "did:scid:vh:1:Qm")
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn confirm_does_not_touch_a_queued_entry() {
        let store = InMemoryOutboxStore::new();
        // Queued (not yet hop-accepted) — evidence for it shouldn't apply.
        store
            .put(OutboxEntry::new("k1", "did:x", vec![1], 1_000, 61_000))
            .await
            .unwrap();
        assert!(!confirm_delivered(&store, "k1").await.unwrap());
        assert_eq!(
            store.get("k1").await.unwrap().unwrap().state,
            OutboxState::Queued
        );
    }

    #[tokio::test]
    async fn sweep_settles_expired_sent_entries_unconfirmed() {
        let store = InMemoryOutboxStore::new();
        sent_entry(&store, "expired", 1_000).await; // deliver_by = 61_000
        sent_entry(&store, "in_window", 1_000).await;
        // Confirm one so it's terminal (Delivered) — the sweep ignores it.
        confirm_delivered(&store, "in_window").await.unwrap();

        // Before expiry: nothing settled.
        assert_eq!(
            sweep_confirmations(&store, 30_000)
                .await
                .unwrap()
                .unconfirmed,
            0
        );

        // Past the window: the still-Sent entry settles Unconfirmed.
        let report = sweep_confirmations(&store, 61_000).await.unwrap();
        assert_eq!(report.unconfirmed, 1);
        assert_eq!(
            store.get("expired").await.unwrap().unwrap().state,
            OutboxState::Unconfirmed
        );
        // The Delivered entry is untouched.
        assert_eq!(
            store.get("in_window").await.unwrap().unwrap().state,
            OutboxState::Delivered
        );
    }

    // ── Escalation on window expiry (§5a) ────────────────────────────────

    /// An escalator that returns a fixed decision, for driving the sweep.
    struct FixedEscalator(Escalation);
    #[async_trait::async_trait]
    impl ExpiryEscalator for FixedEscalator {
        async fn escalate(&self, _entry: &OutboxEntry) -> Escalation {
            self.0.clone()
        }
    }

    #[tokio::test]
    async fn escalate_rebound_rearms_the_window_and_keeps_watching() {
        let store = InMemoryOutboxStore::new();
        sent_entry(&store, "k", 1_000).await; // deliver_by = 61_000, Sent
        // Mark it observed so we can prove the rebind resets that observation.
        let mut e = store.get("k").await.unwrap().unwrap();
        e.outbox_observed = true;
        store.put(e).await.unwrap();

        let esc = FixedEscalator(Escalation::Rebound {
            deliver_by_ms: 200_000,
            hop_id: Some("h2".into()),
            scope: DeliveryScope::Local,
        });
        let report = sweep_confirmations_with(&store, 61_000, &esc)
            .await
            .unwrap();
        assert_eq!(report.rebound, 1);
        assert_eq!(report.failed, 0);
        assert_eq!(report.unconfirmed, 0);

        let e = store.get("k").await.unwrap().unwrap();
        assert_eq!(e.state, OutboxState::Sent); // still watched
        assert_eq!(e.deliver_by_ms, 200_000); // fresh window
        assert_eq!(e.hop_id.as_deref(), Some("h2")); // alternate hop
        assert_eq!(e.scope, DeliveryScope::Local); // the alternate's scope
        assert!(!e.outbox_observed); // reset for the alternate binding

        // Before the NEW window expires, another sweep leaves it alone.
        let report = sweep_confirmations_with(&store, 100_000, &esc)
            .await
            .unwrap();
        assert_eq!(report, ConfirmReport::default());
        assert_eq!(
            store.get("k").await.unwrap().unwrap().state,
            OutboxState::Sent
        );
    }

    #[tokio::test]
    async fn escalate_failed_settles_failed_and_is_reported() {
        let store = InMemoryOutboxStore::new();
        sent_entry(&store, "k", 1_000).await;
        let report = sweep_confirmations_with(&store, 61_000, &FixedEscalator(Escalation::Failed))
            .await
            .unwrap();
        assert_eq!(report.failed, 1);
        assert_eq!(
            store.get("k").await.unwrap().unwrap().state,
            OutboxState::Failed
        );
    }

    #[tokio::test]
    async fn escalate_unconfirmed_matches_the_default_sweep() {
        let store = InMemoryOutboxStore::new();
        sent_entry(&store, "k", 1_000).await;
        let report =
            sweep_confirmations_with(&store, 61_000, &FixedEscalator(Escalation::Unconfirmed))
                .await
                .unwrap();
        assert_eq!(report.unconfirmed, 1);
        assert_eq!(
            store.get("k").await.unwrap().unwrap().state,
            OutboxState::Unconfirmed
        );
    }

    #[tokio::test]
    async fn escalator_is_not_called_before_expiry() {
        // An in-window entry must never be escalated (it would fail a live send).
        let store = InMemoryOutboxStore::new();
        sent_entry(&store, "k", 1_000).await; // deliver_by = 61_000
        let report = sweep_confirmations_with(&store, 30_000, &FixedEscalator(Escalation::Failed))
            .await
            .unwrap();
        assert_eq!(report, ConfirmReport::default());
        assert_eq!(
            store.get("k").await.unwrap().unwrap().state,
            OutboxState::Sent
        );
    }

    // ── Outbox-drain evidence (§5a) ──────────────────────────────────────

    use affinidi_messaging_core::{ConnState, Inbound, InboundAck, SendReceipt, TransportKind};
    use futures_util::stream::{self, BoxStream};
    use std::sync::Mutex;
    use tokio::sync::watch;

    /// A transport whose `outbox_message_ids` the test drives.
    struct DrainMockTransport {
        outbox: Mutex<Option<Vec<String>>>,
        /// The mediator's receipts, when the test gives it any. `None` is a
        /// mediator without them.
        status: Mutex<Option<std::collections::HashMap<String, OutboxStatus>>>,
        /// The hop ids each `outbox_status` call asked about.
        asked: Mutex<Vec<Vec<String>>>,
        /// How many more `outbox_status` calls get an answer before it
        /// answers `None` (or fails, with `status_then_fails`); `None` for
        /// every call.
        status_answers: Mutex<Option<usize>>,
        status_then_fails: std::sync::atomic::AtomicBool,
        conn_rx: watch::Receiver<ConnState>,
        _conn_tx: watch::Sender<ConnState>,
    }

    impl DrainMockTransport {
        fn new(outbox: Option<Vec<String>>) -> Self {
            let (tx, rx) = watch::channel(ConnState::Connected);
            Self {
                outbox: Mutex::new(outbox),
                status: Mutex::new(None),
                asked: Mutex::new(Vec::new()),
                status_answers: Mutex::new(None),
                status_then_fails: std::sync::atomic::AtomicBool::new(false),
                conn_rx: rx,
                _conn_tx: tx,
            }
        }
        fn with_status(outbox: Option<Vec<String>>, status: &[(&str, OutboxStatus)]) -> Self {
            let transport = Self::new(outbox);
            *transport.status.lock().unwrap() = Some(
                status
                    .iter()
                    .map(|(id, state)| (id.to_string(), *state))
                    .collect(),
            );
            transport
        }
        fn set_outbox(&self, ids: Vec<String>) {
            *self.outbox.lock().unwrap() = Some(ids);
        }
    }

    #[async_trait::async_trait]
    impl MessageTransport for DrainMockTransport {
        fn kind(&self) -> TransportKind {
            TransportKind::Didcomm
        }
        async fn send(
            &self,
            _dest: &str,
            _packed: Vec<u8>,
        ) -> Result<SendReceipt, affinidi_messaging_core::MessagingError> {
            Ok(SendReceipt {
                via: TransportKind::Didcomm,
                hop_id: None,
            })
        }
        fn connection_state(&self) -> watch::Receiver<ConnState> {
            self.conn_rx.clone()
        }
        fn inbound(&self) -> BoxStream<'static, Inbound> {
            Box::pin(stream::empty())
        }
        async fn ack(
            &self,
            _ack: InboundAck,
        ) -> Result<(), affinidi_messaging_core::MessagingError> {
            Ok(())
        }
        async fn outbox_message_ids(
            &self,
        ) -> Result<Option<Vec<String>>, affinidi_messaging_core::MessagingError> {
            Ok(self.outbox.lock().unwrap().clone())
        }
        async fn outbox_status(
            &self,
            hop_ids: &[String],
        ) -> Result<
            Option<std::collections::HashMap<String, OutboxStatus>>,
            affinidi_messaging_core::MessagingError,
        > {
            self.asked.lock().unwrap().push(hop_ids.to_vec());
            if let Some(remaining) = self.status_answers.lock().unwrap().as_mut() {
                if *remaining == 0 {
                    if self
                        .status_then_fails
                        .load(std::sync::atomic::Ordering::SeqCst)
                    {
                        return Err(affinidi_messaging_core::MessagingError::Transport(
                            "status timed out".into(),
                        ));
                    }
                    return Ok(None);
                }
                *remaining -= 1;
            }
            Ok(self.status.lock().unwrap().clone())
        }
    }

    const MIN: u64 = 60 * 1000;

    /// A `Sent` entry created at `created`, its window closing at `deliver_by`.
    async fn waiting(store: &InMemoryOutboxStore, key: &str, created: u64, deliver_by: u64) {
        let mut e = OutboxEntry::new(key, "did:example:bob", vec![1], created, deliver_by);
        e.state = OutboxState::Sent;
        e.hop_id = Some(format!("hop-{key}"));
        store.put(e).await.unwrap();
    }

    fn asked_about(transport: &DrainMockTransport) -> Vec<String> {
        let asked = std::mem::take(&mut *transport.asked.lock().unwrap());
        let mut ids: Vec<String> = asked.into_iter().flatten().collect();
        ids.sort();
        ids
    }

    /// A fresh entry is asked about on every tick; one that has waited longer
    /// is asked about less often, and again once its period has passed.
    #[tokio::test]
    async fn the_receipt_poll_asks_about_long_waiting_entries_less_often() {
        let store = InMemoryOutboxStore::new();
        let now = 1_000 * 24 * 60 * MIN;
        waiting(&store, "fresh", now - MIN, now + 30 * 24 * 60 * MIN).await;
        waiting(
            &store,
            "old",
            now - 2 * 24 * 60 * MIN,
            now + 28 * 24 * 60 * MIN,
        )
        .await;
        let transport = DrainMockTransport::with_status(Some(vec![]), &[]);
        let mut pacer = StatusPacer::new();

        poll_outbox_drain_paced(&transport, &store, &mut pacer, now)
            .await
            .unwrap();
        assert_eq!(asked_about(&transport), vec!["hop-fresh", "hop-old"]);

        let tick = now + 10_000;
        poll_outbox_drain_paced(&transport, &store, &mut pacer, tick)
            .await
            .unwrap();
        assert_eq!(
            asked_about(&transport),
            vec!["hop-fresh"],
            "the old one waits its hour"
        );

        let hour = now + 60 * MIN;
        poll_outbox_drain_paced(&transport, &store, &mut pacer, hour)
            .await
            .unwrap();
        assert!(asked_about(&transport).contains(&"hop-old".to_string()));
    }

    /// An entry whose window is about to close is asked about every tick, so a
    /// late collection settles `Delivered`, not `Unconfirmed`.
    #[tokio::test]
    async fn an_entry_near_its_deadline_is_asked_about_every_tick() {
        let store = InMemoryOutboxStore::new();
        let now = 1_000 * 24 * 60 * MIN;
        waiting(&store, "closing", now - 2 * 24 * 60 * MIN, now + 5 * MIN).await;
        let transport = DrainMockTransport::with_status(Some(vec![]), &[]);
        let mut pacer = StatusPacer::new();
        for t in 0..3 {
            poll_outbox_drain_paced(&transport, &store, &mut pacer, now + t * 10_000)
                .await
                .unwrap();
            assert_eq!(asked_about(&transport), vec!["hop-closing"], "tick {t}");
        }
    }

    /// With entries waiting and none due, nothing is asked — not even the
    /// outbox listing the unpaced poll falls back to.
    #[tokio::test]
    async fn nothing_due_asks_nothing() {
        let store = InMemoryOutboxStore::new();
        let now = 1_000 * 24 * 60 * MIN;
        waiting(
            &store,
            "old",
            now - 2 * 24 * 60 * MIN,
            now + 28 * 24 * 60 * MIN,
        )
        .await;
        let transport = DrainMockTransport::with_status(None, &[]);
        *transport.status.lock().unwrap() = Some(Default::default());
        let mut pacer = StatusPacer::new();
        poll_outbox_drain_paced(&transport, &store, &mut pacer, now)
            .await
            .unwrap();
        assert_eq!(asked_about(&transport).len(), 1);
        let r = poll_outbox_drain_paced(&transport, &store, &mut pacer, now + 10_000)
            .await
            .unwrap();
        assert!(asked_about(&transport).is_empty());
        assert_eq!((r.delivered, r.observed, r.lost), (0, 0, 0));
    }

    async fn sent_with_hop(store: &InMemoryOutboxStore, key: &str, hop: &str) {
        let mut e = OutboxEntry::new(key, "did:example:bob", vec![1], 1_000, 61_000);
        e.state = OutboxState::Sent;
        e.hop_id = Some(hop.to_string());
        store.put(e).await.unwrap();
    }

    /// Gone from the listing after being seen there is a pickup or an expiry,
    /// and the listing cannot tell which: the entry stays `Sent` and its
    /// window settles it `Unconfirmed`, never `Delivered`.
    #[tokio::test]
    async fn a_drain_from_the_listing_alone_is_not_a_delivery() {
        let store = InMemoryOutboxStore::new();
        sent_with_hop(&store, "k1", "h1").await;
        let transport = DrainMockTransport::new(Some(vec!["h1".to_string()]));

        // Pass 1: h1 is present → observed.
        let r = poll_outbox_drain(&transport, &store).await.unwrap();
        assert_eq!((r.observed, r.delivered, r.drained), (1, 0, 0));
        let e = store.get("k1").await.unwrap().unwrap();
        assert!(e.outbox_observed);
        assert_eq!(e.state, OutboxState::Sent);

        // h1 leaves the outbox: collected, or expired at the mediator.
        transport.set_outbox(vec![]);

        // Pass 2: counted as drained, still Sent.
        let r = poll_outbox_drain(&transport, &store).await.unwrap();
        assert_eq!((r.observed, r.delivered, r.drained), (0, 0, 1));
        assert_eq!(
            store.get("k1").await.unwrap().unwrap().state,
            OutboxState::Sent
        );

        // The window closes with no evidence → Unconfirmed.
        let r = sweep_confirmations(&store, 61_000).await.unwrap();
        assert_eq!(r.unconfirmed, 1);
        assert_eq!(
            store.get("k1").await.unwrap().unwrap().state,
            OutboxState::Unconfirmed
        );
    }

    /// A transport that answers the first status batch and then gives no
    /// signal keeps what the first batch settled, and does not fall back to
    /// the listing for the rest.
    #[tokio::test]
    async fn a_status_signal_lost_partway_keeps_the_settled_batches() {
        let store = InMemoryOutboxStore::new();
        for n in 0..(STATUS_BATCH + 1) {
            sent_with_hop(&store, &format!("k{n:03}"), &format!("h{n:03}")).await;
        }
        let collected: Vec<(String, OutboxStatus)> = (0..(STATUS_BATCH + 1))
            .map(|n| (format!("h{n:03}"), OutboxStatus::Collected))
            .collect();
        let borrowed: Vec<(&str, OutboxStatus)> = collected
            .iter()
            .map(|(id, state)| (id.as_str(), *state))
            .collect();
        let transport = DrainMockTransport::with_status(Some(vec![]), &borrowed);
        *transport.status_answers.lock().unwrap() = Some(1);

        let r = poll_outbox_drain(&transport, &store).await.unwrap();
        assert_eq!((r.delivered, r.drained), (STATUS_BATCH, 0), "{r:?}");
        let waiting = store.awaiting_confirmation().await.unwrap();
        assert_eq!(
            waiting.len(),
            1,
            "the unanswered batch waits for the next poll"
        );
    }

    /// The same when a later batch fails outright: the settled batches are
    /// reported, not discarded with an error.
    #[tokio::test]
    async fn a_status_call_failing_partway_keeps_the_settled_batches() {
        let store = InMemoryOutboxStore::new();
        for n in 0..(STATUS_BATCH + 1) {
            sent_with_hop(&store, &format!("k{n:03}"), &format!("h{n:03}")).await;
        }
        let collected: Vec<(String, OutboxStatus)> = (0..(STATUS_BATCH + 1))
            .map(|n| (format!("h{n:03}"), OutboxStatus::Collected))
            .collect();
        let borrowed: Vec<(&str, OutboxStatus)> = collected
            .iter()
            .map(|(id, state)| (id.as_str(), *state))
            .collect();
        let transport = DrainMockTransport::with_status(Some(vec![]), &borrowed);
        *transport.status_answers.lock().unwrap() = Some(1);
        transport
            .status_then_fails
            .store(true, std::sync::atomic::Ordering::SeqCst);

        let r = poll_outbox_drain(&transport, &store).await.unwrap();
        assert_eq!(r.delivered, STATUS_BATCH, "{r:?}");
        assert_eq!(store.awaiting_confirmation().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn drain_absent_before_observed_does_not_confirm() {
        // Eventual-consistency guard: a hop-id not yet indexed in the outbox
        // must NOT be read as a drain.
        let store = InMemoryOutboxStore::new();
        sent_with_hop(&store, "k1", "h1").await;
        let transport = DrainMockTransport::new(Some(vec![])); // h1 not indexed yet

        let r = poll_outbox_drain(&transport, &store).await.unwrap();
        assert_eq!(r.delivered, 0);
        let e = store.get("k1").await.unwrap().unwrap();
        assert_eq!(e.state, OutboxState::Sent);
        assert!(!e.outbox_observed);
    }

    #[tokio::test]
    async fn drain_no_transport_signal_is_a_noop() {
        let store = InMemoryOutboxStore::new();
        sent_with_hop(&store, "k1", "h1").await;
        let transport = DrainMockTransport::new(None); // transport gives no outbox signal

        let r = poll_outbox_drain(&transport, &store).await.unwrap();
        assert_eq!(r, DrainPollReport::default());
        assert_eq!(
            store.get("k1").await.unwrap().unwrap().state,
            OutboxState::Sent
        );
    }
    /// The bug receipts exist for: a live recipient collects before any poll
    /// has seen the message queued. The outbox listing never shows it, so the
    /// fallback leaves it `Sent` for ever; the receipt settles it `Delivered`.
    #[tokio::test]
    async fn a_message_collected_before_the_first_poll_is_delivered() {
        let store = InMemoryOutboxStore::new();
        sent_with_hop(&store, "k1", "h1").await;
        let transport =
            DrainMockTransport::with_status(Some(vec![]), &[("h1", OutboxStatus::Collected)]);

        let r = poll_outbox_drain(&transport, &store).await.unwrap();
        assert_eq!(r.delivered, 1, "{r:?}");
        assert_eq!(
            store.get("k1").await.unwrap().unwrap().state,
            OutboxState::Delivered
        );
    }

    /// The other half: a message seen queued that then expires is not a
    /// delivery. The fallback would call it one; the receipt says it was lost.
    #[tokio::test]
    async fn an_observed_message_the_mediator_discarded_is_lost_not_delivered() {
        let store = InMemoryOutboxStore::new();
        sent_with_hop(&store, "k1", "h1").await;
        sent_with_hop(&store, "k2", "h2").await;
        let mut observed = store.get("k1").await.unwrap().unwrap();
        observed.outbox_observed = true;
        store.put(observed).await.unwrap();
        let transport = DrainMockTransport::with_status(
            Some(vec![]),
            &[
                ("h1", OutboxStatus::Discarded),
                ("h2", OutboxStatus::Withdrawn),
            ],
        );

        let r = poll_outbox_drain(&transport, &store).await.unwrap();
        assert_eq!((r.delivered, r.lost), (0, 2), "{r:?}");
        for key in ["k1", "k2"] {
            assert_eq!(
                store.get(key).await.unwrap().unwrap().state,
                OutboxState::Failed,
                "{key}"
            );
        }
    }

    #[tokio::test]
    async fn a_queued_or_delivered_message_is_observed_and_unknown_is_left_alone() {
        let store = InMemoryOutboxStore::new();
        sent_with_hop(&store, "k1", "h1").await;
        sent_with_hop(&store, "k2", "h2").await;
        sent_with_hop(&store, "k3", "h3").await;
        let transport = DrainMockTransport::with_status(
            None,
            &[
                ("h1", OutboxStatus::Queued),
                ("h2", OutboxStatus::Delivered),
            ],
        );

        let r = poll_outbox_drain(&transport, &store).await.unwrap();
        assert_eq!((r.observed, r.delivered, r.lost), (2, 0, 0), "{r:?}");
        for key in ["k1", "k2"] {
            let e = store.get(key).await.unwrap().unwrap();
            assert_eq!(e.state, OutboxState::Sent);
            assert!(e.outbox_observed, "{key}");
        }
        let unknown = store.get("k3").await.unwrap().unwrap();
        assert_eq!(unknown.state, OutboxState::Sent);
        assert!(!unknown.outbox_observed);
    }

    /// A status can only settle the message it names: one recorded under an
    /// id nobody asked about, or an answer that omits the entry, leaves it as
    /// it was — whatever the order or count of the answer.
    #[tokio::test]
    async fn a_status_under_another_id_settles_nothing() {
        let store = InMemoryOutboxStore::new();
        sent_with_hop(&store, "k1", "h1").await;
        let transport = DrainMockTransport::with_status(
            Some(vec![]),
            &[("someone-else", OutboxStatus::Collected)],
        );

        let r = poll_outbox_drain(&transport, &store).await.unwrap();
        assert_eq!((r.delivered, r.lost, r.observed), (0, 0, 0), "{r:?}");
        let e = store.get("k1").await.unwrap().unwrap();
        assert_eq!(e.state, OutboxState::Sent);
        assert!(!e.outbox_observed);
    }

    /// A mediator without receipts answers `None`, and the outbox listing is
    /// used: it observes, and reports a drain without settling it.
    #[tokio::test]
    async fn without_receipts_the_outbox_listing_reports_a_drain() {
        let store = InMemoryOutboxStore::new();
        sent_with_hop(&store, "k1", "h1").await;
        let transport = DrainMockTransport::new(Some(vec!["h1".to_string()]));
        poll_outbox_drain(&transport, &store).await.unwrap();
        transport.set_outbox(vec![]);
        let r = poll_outbox_drain(&transport, &store).await.unwrap();
        assert_eq!((r.delivered, r.drained), (0, 1), "{r:?}");
    }

    // ── Relayed entries (VTI-TRN-042 amended, VTI-TRN-064) ───────────────

    async fn relayed_with_hop(store: &InMemoryOutboxStore, key: &str, hop: &str) {
        let mut e = OutboxEntry::new(key, "did:example:bob", vec![1], 1_000, 61_000)
            .with_scope(DeliveryScope::Relayed);
        e.state = OutboxState::Sent;
        e.hop_id = Some(hop.to_string());
        store.put(e).await.unwrap();
    }

    /// The sender's mediator relayed the message away and can only ever
    /// answer `unknown` for it, so it is not asked — neither for status nor in
    /// the outbox listing. A local entry beside it is asked about as before.
    #[tokio::test]
    async fn a_relayed_entry_is_never_polled() {
        let store = InMemoryOutboxStore::new();
        relayed_with_hop(&store, "relayed", "h-relayed").await;
        sent_with_hop(&store, "local", "h-local").await;
        let transport = DrainMockTransport::with_status(
            Some(vec!["h-relayed".to_string(), "h-local".to_string()]),
            &[
                ("h-relayed", OutboxStatus::Collected),
                ("h-local", OutboxStatus::Queued),
            ],
        );

        let r = poll_outbox_drain(&transport, &store).await.unwrap();
        assert_eq!(asked_about(&transport), vec!["h-local".to_string()]);
        assert_eq!((r.delivered, r.observed), (0, 1), "{r:?}");
        assert_eq!(
            store.get("relayed").await.unwrap().unwrap().state,
            OutboxState::Sent
        );
    }

    #[tokio::test]
    async fn only_relayed_entries_waiting_asks_the_mediator_nothing() {
        let store = InMemoryOutboxStore::new();
        relayed_with_hop(&store, "relayed", "h-relayed").await;
        let transport = DrainMockTransport::new(Some(vec!["h-relayed".to_string()]));

        let r = poll_outbox_drain(&transport, &store).await.unwrap();
        assert!(asked_about(&transport).is_empty());
        assert_eq!(r, DrainPollReport::default());
        assert!(!store.get("relayed").await.unwrap().unwrap().outbox_observed);
    }

    /// An escalator that counts how often it was asked.
    struct CountingEscalator(std::sync::atomic::AtomicUsize, Escalation);
    #[async_trait::async_trait]
    impl ExpiryEscalator for CountingEscalator {
        async fn escalate(&self, _entry: &OutboxEntry) -> Escalation {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.1.clone()
        }
    }

    /// No evidence class was available: the entry is recorded unconfirmable
    /// with its reason, and nothing escalates it to a second copy.
    #[tokio::test]
    async fn a_relayed_entry_with_no_receipt_is_unconfirmable_and_not_escalated() {
        let store = InMemoryOutboxStore::new();
        relayed_with_hop(&store, "k", "h").await;
        let escalator = CountingEscalator(Default::default(), Escalation::Failed);

        let report = sweep_confirmations_with(&store, 61_000, &escalator)
            .await
            .unwrap();
        assert_eq!(escalator.0.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert_eq!((report.unconfirmed, report.unconfirmable), (1, 1));
        assert_eq!(report.failed, 0);
        let e = store.get("k").await.unwrap().unwrap();
        assert_eq!(e.state, OutboxState::Unconfirmed);
        assert_eq!(
            e.unconfirmed_reason,
            Some(UnconfirmedReason::NoEvidencePath)
        );
    }

    /// For a recipient known to send receipts the path exists, so its silence
    /// means something and VTI-TRN-042 escalation applies.
    #[tokio::test]
    async fn a_relayed_entry_to_a_recipient_known_to_send_receipts_is_escalated() {
        let store = InMemoryOutboxStore::new();
        relayed_with_hop(&store, "k", "h").await;
        let reach = ReceiptReach::new();
        reach.record("did:example:bob", 30_000);
        let escalator = CountingEscalator(Default::default(), Escalation::Failed);

        let report = sweep_confirmations_with_reach(&store, 61_000, &escalator, &reach)
            .await
            .unwrap();
        assert_eq!(escalator.0.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!((report.failed, report.unconfirmable), (1, 0));
        assert_eq!(
            store.get("k").await.unwrap().unwrap().state,
            OutboxState::Failed
        );
    }

    /// A path that could have produced evidence and did not is recorded as
    /// such, apart from one that never could.
    #[tokio::test]
    async fn a_local_entry_whose_window_passed_says_so() {
        let store = InMemoryOutboxStore::new();
        sent_with_hop(&store, "k", "h").await;

        let report = sweep_confirmations(&store, 61_000).await.unwrap();
        assert_eq!((report.unconfirmed, report.unconfirmable), (1, 0));
        assert_eq!(
            store.get("k").await.unwrap().unwrap().unconfirmed_reason,
            Some(UnconfirmedReason::WindowPassed)
        );
    }
}

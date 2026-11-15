use std::sync::Arc;
use std::time::Duration;

use affinidi_messaging_sdk::errors::ATMError;
use affinidi_messaging_sdk::protocols::mediator::acls::AccessListModeType;
use affinidi_messaging_sdk::tasks::messaging::account;
use affinidi_messaging_sdk::{ATM, profiles::ATMProfile};
use sha256::digest;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use super::inflight::{Claim, InFlight};
use super::listener::Listener;
use super::poison::{Disposition, HandlerGuard, report_dead_letter};
use crate::config::Protocols;
use crate::error::{DIDCommServiceError, StartupError};
use crate::handler::{DIDCommHandler, TspHandler};
#[cfg(feature = "tsp")]
use affinidi_messaging_sdk::protocols::message_pickup::{DeliveryOutcome, InboundFrame};

type SyncError = Box<dyn std::error::Error + Send + Sync>;

const OFFLINE_SYNC_INTERVAL_SECS: u64 = 30;
/// Messages fetched per delivery request.
const OFFLINE_BATCH_LIMIT: usize = 100;
/// Batches fetched back to back in one sync before waiting for the next tick,
/// so one sync cannot run unbounded against a queue that keeps filling.
const MAX_BATCHES_PER_SYNC: usize = 50;
/// Short retry used only when the very first drains can't run yet because the
/// websocket is still coming up right after connect — so the initial backlog is
/// fetched within a second or two instead of waiting a full interval.
const OFFLINE_SYNC_RETRY_SECS: u64 = 2;

impl Listener {
    pub(crate) async fn set_acl_mode(
        &self,
        acl_mode: &AccessListModeType,
    ) -> Result<(), DIDCommServiceError> {
        let atm = self.atm()?;
        let profile = self.profile()?;

        info!(acl_mode = ?acl_mode, "ACL mode configured");

        // A partial ACL update setting only the access-list mode; the mediator's
        // self-service gating applies it (the rest of the ACL is left unchanged).
        let mode = match acl_mode {
            AccessListModeType::ExplicitAllow => {
                account::update::v0_2::MediatorAclAccessListMode::ExplicitAllow
            }
            AccessListModeType::ExplicitDeny => {
                account::update::v0_2::MediatorAclAccessListMode::ExplicitDeny
            }
        };
        let acl: account::update::v0_2::MediatorAcl = account::update::v0_2::MediatorAcl::builder()
            .access_list_mode(Some(mode))
            .try_into()
            .expect("MediatorAcl has no required member");
        atm.trust_tasks()
            .account_update(
                profile,
                Some(digest(&profile.inner.did)),
                None,
                Some(acl),
                None,
            )
            .await
            .map_err(StartupError::AclApply)?;

        Ok(())
    }
}

/// The periodic offline drain for one listener connection.
///
/// It shares the listener's [`InFlight`] record, so a message the live stream
/// is handling is skipped here (and the reverse), and its handler permits, so
/// both paths together run at most `max_concurrent_handlers` handlers.
pub(crate) struct OfflineSync {
    pub listener_id: String,
    pub atm: ATM,
    pub profile: Arc<ATMProfile>,
    pub handler: Arc<dyn DIDCommHandler>,
    // Read only by the TSP-feature drain.
    #[cfg_attr(not(feature = "tsp"), allow(dead_code))]
    pub tsp_handler: Option<Arc<dyn TspHandler>>,
    pub in_flight: Arc<InFlight>,
    pub permits: Arc<Semaphore>,
    pub auto_delete: bool,
    #[cfg_attr(not(feature = "tsp"), allow(dead_code))]
    pub protocols: Protocols,
    /// The listener's handler guard (timeout, poison-frame dead-lettering),
    /// shared so a frame's failures count across both paths.
    pub guard: Arc<HandlerGuard>,
}

/// Handler tasks of one batch, each yielding its message's claim and what to
/// do with it.
pub(crate) type HandlerSet = JoinSet<(Claim, Disposition)>;

/// What one batch did, to decide whether to fetch another straight away.
struct BatchOutcome {
    fetched: usize,
    acked: usize,
}

impl OfflineSync {
    pub(crate) async fn run(&self, shutdown: &CancellationToken) {
        let profile_alias = self.profile.inner.alias.clone();
        loop {
            // Drain the offline/queued backlog at the TOP of the loop, so it runs
            // immediately on connect rather than only after the first interval.
            let next_delay_secs = match self.sync(shutdown).await {
                Ok(()) => OFFLINE_SYNC_INTERVAL_SECS,
                Err(e) => {
                    // A websocket reconnect (e.g. when the mediator closes the
                    // socket on access-token expiry) can land mid-poll and abort
                    // an in-flight request. That is expected and self-heals, so
                    // log it at debug rather than raising a misleading "sync
                    // failed" warning. Right after connect the socket may still be
                    // coming up — retry soon so the initial drain isn't delayed a
                    // whole interval; back off normally on any other error.
                    if matches!(
                        e.downcast_ref::<ATMError>(),
                        Some(ATMError::Disconnected(_))
                    ) {
                        debug!(profile = %profile_alias, "Offline sync skipped: websocket reconnecting");
                        OFFLINE_SYNC_RETRY_SECS
                    } else {
                        warn!(profile = %profile_alias, error = %e, "Offline sync failed");
                        OFFLINE_SYNC_INTERVAL_SECS
                    }
                }
            };

            tokio::select! {
                _ = shutdown.cancelled() => {
                    debug!(profile = %profile_alias, "Offline sync task shutting down");
                    break;
                }
                _ = tokio::time::sleep(Duration::from_secs(next_delay_secs)) => {}
            }
        }
    }

    /// Drain the queue: fetch batches back to back while each one comes back
    /// full and makes progress (some of it was acked), up to
    /// [`MAX_BATCHES_PER_SYNC`]. With `auto_delete` off nothing is acked, so a
    /// second fetch would return the same messages and only one batch is taken.
    async fn sync(&self, shutdown: &CancellationToken) -> Result<(), SyncError> {
        for _ in 0..MAX_BATCHES_PER_SYNC {
            if shutdown.is_cancelled() {
                break;
            }
            let outcome = self.sync_batch().await?;
            if outcome.fetched < OFFLINE_BATCH_LIMIT || outcome.acked == 0 {
                break;
            }
        }
        Ok(())
    }

    async fn acquire(&self) -> Result<OwnedSemaphorePermit, SyncError> {
        Ok(self.permits.clone().acquire_owned().await?)
    }

    /// Run a DIDComm handler on its own task, holding a handler permit, under
    /// the handler guard.
    fn spawn_dispatch(
        &self,
        set: &mut HandlerSet,
        permit: OwnedSemaphorePermit,
        claim: Claim,
        message: affinidi_messaging_didcomm::Message,
        meta: affinidi_messaging_didcomm::UnpackMetadata,
    ) {
        let listener_id = self.listener_id.clone();
        let atm = self.atm.clone();
        let profile = self.profile.clone();
        let handler = self.handler.clone();
        let guard = self.guard.clone();
        set.spawn(async move {
            let _permit = permit;
            // The batch is acked below, once every handler has returned.
            let disposition = guard
                .run(claim.id(), async move {
                    Listener::dispatch_message(
                        &listener_id,
                        &atm,
                        &profile,
                        &handler,
                        message,
                        meta,
                        None,
                    )
                    .await;
                    true
                })
                .await;
            (claim, disposition)
        });
    }

    /// Wait for every handler of the batch. Returns the claims handled and the
    /// claims dead-lettered (reported here); a claim left queued is released
    /// unacked.
    pub(crate) async fn join_all(&self, mut set: HandlerSet) -> (Vec<Claim>, Vec<Claim>) {
        let mut handled = Vec::new();
        let mut dead = Vec::new();
        while let Some(result) = set.join_next().await {
            match result {
                Ok((claim, disposition)) => {
                    self.settle(claim, disposition, &mut handled, &mut dead)
                }
                // The guard catches handler panics; this is the wrapper task
                // itself, whose claim was dropped (released unacked).
                Err(e) => {
                    error!(profile = %self.profile.inner.alias, error = %e, "Offline handler task failed")
                }
            }
        }
        (handled, dead)
    }

    /// Sort one guarded handler's outcome.
    fn settle(
        &self,
        claim: Claim,
        disposition: Disposition,
        handled: &mut Vec<Claim>,
        dead: &mut Vec<Claim>,
    ) {
        match disposition {
            Disposition::Ack => handled.push(claim),
            // A failure that may clear: released unacked, so a later sync
            // offers it again.
            Disposition::Leave => drop(claim),
            Disposition::DeadLetter { attempts, why } => {
                report_dead_letter(
                    &self.atm,
                    &self.profile.inner.alias,
                    claim.id(),
                    attempts,
                    why,
                );
                dead.push(claim);
            }
        }
    }

    /// Ack the messages this batch handled (only with `auto_delete`) and the
    /// ones it dropped as undeliverable (always: nobody will ever take them),
    /// then release their claims.
    async fn ack(&self, handled: Vec<Claim>, dropped: Vec<Claim>) -> Result<usize, SyncError> {
        let mut ids: Vec<String> = dropped.iter().map(|c| c.id().to_string()).collect();
        if self.auto_delete {
            ids.extend(handled.iter().map(|c| c.id().to_string()));
        }
        if ids.is_empty() {
            for c in handled {
                c.finish(false);
            }
            return Ok(0);
        }

        // On an error the claims drop unacked: the messages stay queued and the
        // next sync sees them again.
        let reply = self
            .atm
            .message_pickup()
            .send_messages_received(&self.profile, &ids, true)
            .await?;
        if reply.is_none() {
            warn!(profile = %self.profile.inner.alias, "No status reply for offline messages ack");
        } else {
            debug!(profile = %self.profile.inner.alias, count = ids.len(), "Offline messages acknowledged and deleted");
        }
        for c in dropped {
            c.finish(true);
        }
        for c in handled {
            c.finish(self.auto_delete);
        }
        Ok(ids.len())
    }

    async fn queued_count(&self) -> Result<usize, SyncError> {
        let status_reply = self
            .atm
            .message_pickup()
            .send_status_request(&self.profile, true, None)
            .await?;
        let count = status_reply.map(|m| m.message_count).unwrap_or(0);
        debug!(profile = %self.profile.inner.alias, count, "Offline messages count");
        Ok(count as usize)
    }

    /// TSP-aware drain: fetch the backlog as classified frames so a TSP frame
    /// goes to the TSP handler (like the live loop) instead of being
    /// DIDComm-unpacked and left to poison-loop.
    #[cfg(feature = "tsp")]
    async fn sync_batch(&self) -> Result<BatchOutcome, SyncError> {
        if self.queued_count().await? == 0 {
            return Ok(BatchOutcome {
                fetched: 0,
                acked: 0,
            });
        }

        let frames = self
            .atm
            .message_pickup()
            .send_delivery_request_classified(&self.profile, Some(OFFLINE_BATCH_LIMIT), true)
            .await?;
        let fetched = frames.len();
        debug!(profile = %self.profile.inner.alias, count = fetched, "Retrieved offline frames");

        let (set, mut handled, mut dropped) = self.route_frames(frames).await?;
        let (more_handled, dead) = self.join_all(set).await;
        handled.extend(more_handled);
        // Dead letters are acked like undeliverable frames: always.
        dropped.extend(dead);
        let acked = self.ack(handled, dropped).await?;
        Ok(BatchOutcome { fetched, acked })
    }

    /// Claim and dispatch one fetched batch, keyed by each frame's attachment
    /// id (the mediator's id for it, equal to `InboundFrame::ack_id` on the
    /// live path). Returns the spawned DIDComm handlers, the claims handled,
    /// and the claims dropped as undeliverable; a frame the live stream holds,
    /// or acked a moment ago, is in neither (R1.7). Nor is a message that
    /// failed for a reason that may clear (`DeliveryOutcome::Retry`, e.g. a
    /// signer DID that did not resolve this time): it is left queued and
    /// retried on a later sync rather than acked and lost.
    #[cfg(feature = "tsp")]
    pub(crate) async fn route_frames(
        &self,
        frames: Vec<(DeliveryOutcome, String)>,
    ) -> Result<(HandlerSet, Vec<Claim>, Vec<Claim>), SyncError> {
        let alias = &self.profile.inner.alias;
        let mut set = JoinSet::new();
        let mut handled = Vec::new();
        let mut dropped = Vec::new();
        for (outcome, id) in frames {
            let frame = match outcome {
                DeliveryOutcome::Frame(frame) => Some(frame),
                // Can never be processed: acked below so it is not redelivered.
                DeliveryOutcome::Reject => None,
                // May clear: neither dispatched nor acked, so the mediator
                // keeps it for a later sync.
                DeliveryOutcome::Retry => {
                    debug!(profile = %alias, "Offline message failed transiently; left queued for retry");
                    continue;
                }
                // `DeliveryOutcome` is `#[non_exhaustive]`: leave an outcome
                // this build does not know queued rather than ack it.
                _ => {
                    warn!(profile = %alias, "Unrecognised offline delivery outcome; left queued");
                    continue;
                }
            };
            // One owner per message (R1.7): skip what the live stream is
            // handling, or handled and acked a moment ago.
            let Some(claim) = self.in_flight.claim(&id) else {
                debug!(profile = %alias, "Offline message already being handled; skipped");
                continue;
            };
            match frame {
                Some(InboundFrame::DidComm(message, meta)) if self.protocols.didcomm() => {
                    let permit = self.acquire().await?;
                    let meta = super::listener::convert_meta(*meta);
                    self.spawn_dispatch(&mut set, permit, claim, *message, meta);
                }
                Some(InboundFrame::DidComm(..)) => {
                    debug!(profile = %alias, "Offline DIDComm frame on a listener with DIDComm disabled; dropped (acked)");
                    dropped.push(claim);
                }
                Some(InboundFrame::Tsp(packed)) => {
                    match (&self.tsp_handler, self.protocols.tsp()) {
                        (Some(h), true) => {
                            // TSP frames are handled in order, one at a time: a
                            // peer's invite must be recorded before its payload.
                            let _permit = self.acquire().await?;
                            let (listener_id, atm, profile, h) = (
                                self.listener_id.clone(),
                                self.atm.clone(),
                                self.profile.clone(),
                                h.clone(),
                            );
                            // `false` from the dispatch is a failure that may
                            // clear (an unresolvable sender, unconfirmed key
                            // state): `Leave`, released unacked for a later sync.
                            let disposition = self
                                .guard
                                .run(claim.id(), async move {
                                    Listener::dispatch_tsp(
                                        &listener_id,
                                        &atm,
                                        &profile,
                                        &h,
                                        *packed,
                                    )
                                    .await
                                })
                                .await;
                            self.settle(claim, disposition, &mut handled, &mut dropped);
                        }
                        (_, false) => {
                            debug!(profile = %alias, "Offline TSP frame on a listener with TSP disabled; dropped (acked)");
                            dropped.push(claim);
                        }
                        (None, true) => {
                            warn!(profile = %alias, "Offline TSP frame but no TSP handler configured — dropping (acked)");
                            dropped.push(claim);
                        }
                    }
                }
                // `InboundFrame` is `#[non_exhaustive]`.
                Some(_) => {
                    warn!(profile = %alias, "Unrecognised offline frame kind — dropping (acked)");
                    dropped.push(claim);
                }
                // A permanent reject (bad encoding, invalid signature, policy
                // reject): drop it and ack it so the mediator stops
                // redelivering.
                None => dropped.push(claim),
            }
        }

        Ok((set, handled, dropped))
    }

    #[cfg(not(feature = "tsp"))]
    async fn sync_batch(&self) -> Result<BatchOutcome, SyncError> {
        // Without the `tsp` feature a listener cannot enable TSP (refused at
        // start), so DIDComm is always on here.
        if self.queued_count().await? == 0 {
            return Ok(BatchOutcome {
                fetched: 0,
                acked: 0,
            });
        }

        let alias = &self.profile.inner.alias;
        let offline_messages = self
            .atm
            .message_pickup()
            .send_delivery_request(&self.profile, Some(OFFLINE_BATCH_LIMIT), true)
            .await?;
        let fetched = offline_messages.len();
        debug!(profile = %alias, count = fetched, "Retrieved offline messages");

        let mut set = HandlerSet::new();
        for (message, meta) in offline_messages {
            // Claim by the mediator's id for the message (`sha256_hash`, the
            // delivery attachment id), which is also what it is acked by. The
            // message keeps its sender's `id`, so a reply threads to it.
            let Some(claim) = self.in_flight.claim(&meta.sha256_hash) else {
                debug!(profile = %alias, "Offline message already being handled; skipped");
                continue;
            };
            let permit = self.acquire().await?;
            let meta = super::listener::convert_meta(meta);
            self.spawn_dispatch(&mut set, permit, claim, message, meta);
        }

        let (handled, dead) = self.join_all(set).await;
        let acked = self.ack(handled, dead).await?;
        Ok(BatchOutcome { fetched, acked })
    }
}

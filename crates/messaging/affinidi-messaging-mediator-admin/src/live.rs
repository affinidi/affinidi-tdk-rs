//! The console's live stream, and the traffic-monitor feeds read from it.
//!
//! One task owns the connection's live stream (R1.7): it is the only
//! `live_stream_next` reader, and it routes each `messaging/monitor/event`
//! batch to the feed its subscription belongs to. Request/response calls are
//! unaffected — the SDK hands a reply to the call waiting on it before any
//! `next` reader sees it. Anything else pushed to the console (it is not a
//! mail client) is left in the queue, untouched.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use affinidi_messaging_sdk::{
    ATM, profiles::ATMProfile, protocols::trust_tasks::decode_monitor_event,
};
use chrono::{DateTime, Utc};
use tokio::sync::{Mutex, mpsc};
use tokio::task::JoinHandle;
use trust_tasks_rs::specs::messaging::monitor;

use crate::error::{ConsoleError, Result};

/// A monitor filter (DIDs, directions, stages, protocols, channels, message
/// type prefixes, failures only).
pub type MonitorFilter = monitor::subscribe::v0_1::MonitorFilter;
/// One observed step in a message's life.
pub type MonitorEvent = monitor::event::v0_1::MonitorEvent;

/// Lease requested for a monitor subscription; the feed renews well before it
/// lapses.
const LEASE_SECONDS: u32 = 300;
/// Renew this long before expiry.
const RENEW_MARGIN: Duration = Duration::from_secs(60);
/// Batches buffered per feed before the oldest are dropped (and counted).
const FEED_BUFFER: usize = 64;

/// What a monitor feed yields.
#[derive(Debug, Clone)]
pub enum MonitorUpdate {
    /// A batch of events, and how many the mediator dropped since the last
    /// one (rate ceiling, or this console briefly offline).
    Events {
        events: Vec<MonitorEvent>,
        dropped: u64,
    },
    /// Batches were lost in transit: `missing` sequence numbers never arrived.
    Gap { missing: u64 },
    /// An empty batch: the tap is alive and nothing matched.
    Heartbeat,
    /// The subscription ended — lease renewal failed, or it was cancelled.
    Ended(String),
}

type Payload = monitor::event::v0_1::Payload;

/// The single reader of a console's live stream.
pub(crate) struct LiveStream {
    feeds: Arc<Mutex<HashMap<String, mpsc::Sender<Payload>>>>,
    stop: Arc<AtomicBool>,
    task: JoinHandle<()>,
}

impl LiveStream {
    pub(crate) fn start(atm: ATM, profile: Arc<ATMProfile>) -> Self {
        let feeds: Arc<Mutex<HashMap<String, mpsc::Sender<Payload>>>> = Arc::default();
        let stop = Arc::new(AtomicBool::new(false));
        let task = tokio::spawn({
            let feeds = feeds.clone();
            let stop = stop.clone();
            async move {
                while !stop.load(Ordering::Relaxed) {
                    let next = atm
                        .message_pickup()
                        .live_stream_next(&profile, Some(Duration::from_millis(500)), false)
                        .await;
                    match next {
                        Ok(Some((message, _))) => {
                            let Some(batch) = decode_monitor_event(&message) else {
                                // Not a monitor batch: leave it in the queue.
                                continue;
                            };
                            let id = batch.payload.subscription_id.to_string();
                            if let Some(tx) = feeds.lock().await.get(&id) {
                                // A full feed means its reader has stalled; the
                                // batch is dropped here, as the mediator would.
                                let _ = tx.try_send(batch.payload);
                            }
                        }
                        Ok(None) => {}
                        Err(e) => {
                            tracing::debug!("live stream read failed, retrying: {e}");
                            tokio::time::sleep(Duration::from_secs(1)).await;
                        }
                    }
                }
            }
        });
        Self { feeds, stop, task }
    }

    pub(crate) fn stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
        self.task.abort();
    }

    /// Subscribe and return a feed that renews itself.
    pub(crate) async fn open_feed(
        &self,
        atm: &ATM,
        profile: &Arc<ATMProfile>,
        filter: MonitorFilter,
    ) -> Result<MonitorFeed> {
        let granted = atm
            .trust_tasks()
            .monitor_subscribe(profile, Some(filter), Some(LEASE_SECONDS), None, None)
            .await
            .map_err(ConsoleError::from_call)?;
        let id = granted.subscription_id.to_string();

        let (batch_tx, batch_rx) = mpsc::channel(FEED_BUFFER);
        self.feeds.lock().await.insert(id.clone(), batch_tx);
        let (end_tx, end_rx) = mpsc::channel(1);

        let renew = tokio::spawn({
            let atm = atm.clone();
            let profile = profile.clone();
            let id = id.clone();
            let mut expires_at = granted.expires_at;
            async move {
                loop {
                    tokio::time::sleep(until_renewal(expires_at)).await;
                    match atm
                        .trust_tasks()
                        .monitor_subscribe(
                            &profile,
                            None,
                            Some(LEASE_SECONDS),
                            None,
                            Some(id.clone()),
                        )
                        .await
                    {
                        Ok(renewed) => expires_at = renewed.expires_at,
                        Err(e) => {
                            let _ = end_tx.send(format!("lease renewal failed: {e}")).await;
                            return;
                        }
                    }
                }
            }
        });

        Ok(MonitorFeed {
            id,
            filter: granted.filter,
            batches: batch_rx,
            ended: end_rx,
            pending: VecDeque::new(),
            last_seq: 0,
            renew,
            feeds: self.feeds.clone(),
            atm: atm.clone(),
            profile: profile.clone(),
        })
    }
}

/// How long to sleep before renewing a lease that ends at `expires_at`.
fn until_renewal(expires_at: DateTime<Utc>) -> Duration {
    let left = (expires_at - Utc::now()).to_std().unwrap_or_default();
    left.saturating_sub(RENEW_MARGIN)
        .max(Duration::from_secs(5))
}

/// A live traffic-monitor subscription.
///
/// Read it with [`MonitorFeed::next`]. It renews its lease on its own and
/// unsubscribes when dropped.
pub struct MonitorFeed {
    id: String,
    filter: MonitorFilter,
    batches: mpsc::Receiver<Payload>,
    ended: mpsc::Receiver<String>,
    pending: VecDeque<MonitorUpdate>,
    last_seq: u64,
    renew: JoinHandle<()>,
    feeds: Arc<Mutex<HashMap<String, mpsc::Sender<Payload>>>>,
    atm: ATM,
    profile: Arc<ATMProfile>,
}

impl MonitorFeed {
    pub fn subscription_id(&self) -> &str {
        &self.id
    }

    /// The filter in force — narrowed by the mediator to what this session may
    /// see.
    pub fn filter(&self) -> &MonitorFilter {
        &self.filter
    }

    /// The next update. `None` once the feed has ended and been drained.
    pub async fn next(&mut self) -> Option<MonitorUpdate> {
        if let Some(update) = self.pending.pop_front() {
            return Some(update);
        }
        tokio::select! {
            batch = self.batches.recv() => {
                let batch = batch?;
                let updates = sequence(&mut self.last_seq, batch);
                self.pending.extend(updates);
                self.pending.pop_front()
            }
            reason = self.ended.recv() => reason.map(MonitorUpdate::Ended),
        }
    }
}

/// Turn one batch into updates, reporting any sequence gap before it.
fn sequence(last_seq: &mut u64, batch: Payload) -> Vec<MonitorUpdate> {
    let seq = batch.seq.get();
    let mut out = Vec::new();
    if *last_seq > 0 && seq > *last_seq + 1 {
        out.push(MonitorUpdate::Gap {
            missing: seq - *last_seq - 1,
        });
    }
    if seq > *last_seq {
        *last_seq = seq;
    }
    if batch.events.is_empty() && batch.dropped == 0 {
        out.push(MonitorUpdate::Heartbeat);
    } else {
        out.push(MonitorUpdate::Events {
            events: batch.events,
            dropped: batch.dropped,
        });
    }
    out
}

impl Drop for MonitorFeed {
    fn drop(&mut self) {
        self.renew.abort();
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let (feeds, atm, profile, id) = (
            self.feeds.clone(),
            self.atm.clone(),
            self.profile.clone(),
            self.id.clone(),
        );
        runtime.spawn(async move {
            feeds.lock().await.remove(&id);
            let _ = atm.trust_tasks().monitor_unsubscribe(&profile, &id).await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn batch(seq: u64, events: usize, dropped: u64) -> Payload {
        let events: Vec<serde_json::Value> = (0..events)
            .map(|_| {
                serde_json::json!({
                    "at": "2026-09-21T00:00:00Z", "direction": "inbound",
                    "stage": "received", "channel": "rest", "protocol": "didcomm",
                })
            })
            .collect();
        serde_json::from_value(serde_json::json!({
            "subscriptionId": "urn:uuid:s", "seq": seq, "events": events,
            "dropped": dropped, "expiresAt": "2026-09-21T01:00:00Z",
        }))
        .unwrap()
    }

    #[test]
    fn in_order_batches_yield_events_and_heartbeats() {
        let mut last = 0;
        assert!(matches!(
            sequence(&mut last, batch(1, 2, 0))[..],
            [MonitorUpdate::Events { .. }]
        ));
        assert!(matches!(
            sequence(&mut last, batch(2, 0, 0))[..],
            [MonitorUpdate::Heartbeat]
        ));
        assert_eq!(last, 2);
    }

    #[test]
    fn a_skipped_sequence_is_reported_as_a_gap_first() {
        let mut last = 3;
        let updates = sequence(&mut last, batch(6, 1, 4));
        assert!(matches!(updates[0], MonitorUpdate::Gap { missing: 2 }));
        assert!(matches!(
            updates[1],
            MonitorUpdate::Events { dropped: 4, .. }
        ));
    }

    #[test]
    fn renewal_is_ahead_of_expiry_but_never_immediate() {
        let soon = Utc::now() + chrono::Duration::seconds(30);
        assert_eq!(until_renewal(soon), Duration::from_secs(5));
        let later = Utc::now() + chrono::Duration::seconds(300);
        let wait = until_renewal(later);
        assert!(wait <= Duration::from_secs(240) && wait >= Duration::from_secs(230));
    }
}

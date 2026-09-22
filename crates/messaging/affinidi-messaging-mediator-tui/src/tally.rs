//! Running totals for the traffic monitor: how many messages, how fast, and
//! which accounts are busiest, since the monitor started.
//!
//! A message is counted once, when it arrives (`received`), so the rates are
//! messages per second rather than monitor events per second (one message
//! produces several: received, stored, delivered, deleted). Deliveries and
//! refusals are counted against the account they concern.
//!
//! The totals cover what the monitor saw: events the mediator dropped for the
//! rate limit, or lost in transit, are not in them (the pane's title shows how
//! many).
//!
//! Memory is bounded whatever the traffic: at most [`MAX_ACCOUNTS`] accounts are
//! tracked (a recipient comes from an envelope's cleartext header, so a sender
//! can name any number of them), the least recently seen giving way; the
//! ten-second rate is kept in one-second buckets; and counters saturate rather
//! than wrap.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use serde_json::Value;

/// The window the "now" rate is measured over.
const RECENT: Duration = Duration::from_secs(10);
/// Most accounts tracked at once; beyond it the least recently seen is dropped.
pub const MAX_ACCOUNTS: usize = 5_000;

/// One account's traffic since the monitor started.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AccountTally {
    /// Messages it sent that arrived at the mediator.
    pub sent: u64,
    /// Messages addressed to it that arrived.
    pub addressed: u64,
    /// Messages handed to it (collected, pushed or relayed to it).
    pub delivered: u64,
    /// Its messages the mediator refused.
    pub refused: u64,
    /// Bytes of the messages it sent.
    pub bytes: u64,
    /// When it last appeared.
    pub last: Option<Instant>,
}

impl AccountTally {
    /// How busy it has been: everything it was part of.
    pub fn activity(&self) -> u64 {
        self.sent + self.addressed + self.delivered + self.refused
    }
}

/// Messages that arrived, split by the wire they arrived on. The mediator
/// reports one of `didcomm`, `didcommV1`, `tsp` or anything else; the last is
/// counted as `other`, which is what the monitor calls a message it could not
/// classify.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ProtocolMix {
    pub didcomm: u64,
    pub didcomm_v1: u64,
    pub tsp: u64,
    pub other: u64,
}

impl ProtocolMix {
    /// Everything counted here.
    pub fn total(&self) -> u64 {
        self.didcomm
            .saturating_add(self.didcomm_v1)
            .saturating_add(self.tsp)
            .saturating_add(self.other)
    }

    /// TSP's share of it, as a percentage. `None` when nothing is counted yet
    /// — a share of no messages is not zero, it is unknown.
    pub fn tsp_share(&self) -> Option<f64> {
        let total = self.total();
        (total > 0).then(|| self.tsp as f64 * 100.0 / total as f64)
    }

    fn record(&mut self, protocol: Option<&str>) {
        let slot = match protocol {
            Some("didcomm") => &mut self.didcomm,
            Some("didcommV1") => &mut self.didcomm_v1,
            Some("tsp") => &mut self.tsp,
            _ => &mut self.other,
        };
        *slot = slot.saturating_add(1);
    }
}

/// Totals since the monitor started.
#[derive(Clone, Debug)]
pub struct TrafficTally {
    started: Instant,
    /// Messages that arrived.
    pub messages: u64,
    /// Those messages, split by wire protocol.
    pub protocols: ProtocolMix,
    /// Bytes of the messages that arrived.
    pub bytes: u64,
    /// Messages refused.
    pub refused: u64,
    /// Arrivals within the last [`RECENT`], in one-second buckets
    /// (bucket start, count), for the "now" rate.
    recent: VecDeque<(Instant, u64)>,
    accounts: HashMap<String, AccountTally>,
}

impl TrafficTally {
    pub fn new(now: Instant) -> Self {
        Self {
            started: now,
            messages: 0,
            protocols: ProtocolMix::default(),
            bytes: 0,
            refused: 0,
            recent: VecDeque::new(),
            accounts: HashMap::new(),
        }
    }

    /// When counting started.
    pub fn started(&self) -> Instant {
        self.started
    }

    /// Count one monitor event.
    pub fn record(&mut self, e: &Value, now: Instant) {
        let from = e["from"].as_str();
        let to = e["to"].as_str();
        let size = e["size"].as_u64().unwrap_or(0);
        match e["stage"].as_str() {
            Some("received") => {
                self.messages = self.messages.saturating_add(1);
                self.protocols.record(e["protocol"].as_str());
                self.bytes = self.bytes.saturating_add(size);
                match self.recent.back_mut() {
                    Some((start, n)) if now.duration_since(*start) < Duration::from_secs(1) => {
                        *n = n.saturating_add(1);
                    }
                    _ => self.recent.push_back((now, 1)),
                }
                if let Some(from) = from {
                    let a = self.account(from, now);
                    a.sent = a.sent.saturating_add(1);
                    a.bytes = a.bytes.saturating_add(size);
                }
                if let Some(to) = to {
                    let a = self.account(to, now);
                    a.addressed = a.addressed.saturating_add(1);
                }
            }
            Some("delivered") => {
                if let Some(to) = to {
                    let a = self.account(to, now);
                    a.delivered = a.delivered.saturating_add(1);
                }
            }
            Some("refused") => {
                self.refused = self.refused.saturating_add(1);
                if let Some(from) = from {
                    let a = self.account(from, now);
                    a.refused = a.refused.saturating_add(1);
                }
            }
            _ => {}
        }
        self.forget_before(now);
    }

    fn account(&mut self, hash: &str, now: Instant) -> &mut AccountTally {
        if !self.accounts.contains_key(hash) && self.accounts.len() >= MAX_ACCOUNTS {
            // Make room: drop the account seen least recently.
            if let Some(oldest) = self
                .accounts
                .iter()
                .min_by_key(|(_, a)| a.last)
                .map(|(k, _)| k.clone())
            {
                self.accounts.remove(&oldest);
            }
        }
        let a = self.accounts.entry(hash.to_string()).or_default();
        a.last = Some(now);
        a
    }

    fn forget_before(&mut self, now: Instant) {
        while self
            .recent
            .front()
            .is_some_and(|(t, _)| now.duration_since(*t) > RECENT)
        {
            self.recent.pop_front();
        }
    }

    /// Messages per second since counting started.
    pub fn rate(&self, now: Instant) -> f64 {
        let secs = now.duration_since(self.started).as_secs_f64();
        if secs < 1.0 {
            self.messages as f64
        } else {
            self.messages as f64 / secs
        }
    }

    /// Messages per second over the last ten seconds.
    pub fn rate_now(&self, now: Instant) -> f64 {
        let in_window: u64 = self
            .recent
            .iter()
            .filter(|(t, _)| now.duration_since(*t) <= RECENT)
            .map(|(_, n)| n)
            .sum();
        in_window as f64 / RECENT.as_secs_f64()
    }

    /// The `n` busiest accounts, busiest first.
    pub fn top(&self, n: usize) -> Vec<(&str, &AccountTally)> {
        let mut all: Vec<(&str, &AccountTally)> =
            self.accounts.iter().map(|(k, v)| (k.as_str(), v)).collect();
        all.sort_by(|a, b| {
            b.1.activity()
                .cmp(&a.1.activity())
                .then_with(|| a.0.cmp(b.0))
        });
        all.truncate(n);
        all
    }

    /// How many accounts have appeared.
    pub fn accounts(&self) -> usize {
        self.accounts.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn event(stage: &str, from: &str, to: &str, size: u64) -> Value {
        json!({ "stage": stage, "from": from, "to": to, "size": size })
    }

    fn event_on(stage: &str, protocol: &str) -> Value {
        json!({ "stage": stage, "from": "a", "to": "b", "size": 1, "protocol": protocol })
    }

    #[test]
    fn arrivals_are_split_by_wire_protocol() {
        let t0 = Instant::now();
        let mut t = TrafficTally::new(t0);
        assert_eq!(t.protocols.tsp_share(), None, "no traffic, no share");

        for protocol in ["tsp", "tsp", "didcomm", "didcommV1", "something-new"] {
            t.record(&event_on("received", protocol), t0);
        }
        // A stage that is not an arrival is not counted twice.
        t.record(&event_on("delivered", "tsp"), t0);

        assert_eq!(t.protocols.tsp, 2);
        assert_eq!(t.protocols.didcomm, 1);
        assert_eq!(t.protocols.didcomm_v1, 1);
        assert_eq!(t.protocols.other, 1, "an unknown wire counts as other");
        assert_eq!(t.protocols.total(), t.messages);
        assert!((t.protocols.tsp_share().unwrap() - 40.0).abs() < 1e-9);
    }

    #[test]
    fn a_message_is_counted_once_however_many_steps_it_takes() {
        let t0 = Instant::now();
        let mut t = TrafficTally::new(t0);
        for stage in ["received", "stored", "delivered", "deleted"] {
            t.record(&event(stage, "alice", "bob", 100), t0);
        }
        assert_eq!(t.messages, 1);
        assert_eq!(t.bytes, 100);
        let top = t.top(10);
        let bob = top.iter().find(|(h, _)| *h == "bob").unwrap().1;
        assert_eq!((bob.addressed, bob.delivered), (1, 1));
        let alice = top.iter().find(|(h, _)| *h == "alice").unwrap().1;
        assert_eq!((alice.sent, alice.bytes), (1, 100));
    }

    #[test]
    fn refusals_count_against_the_sender() {
        let t0 = Instant::now();
        let mut t = TrafficTally::new(t0);
        t.record(&event("refused", "mallory", "bob", 10), t0);
        assert_eq!(t.refused, 1);
        assert_eq!(t.messages, 0);
        assert_eq!(t.top(1)[0].0, "mallory");
        assert_eq!(t.top(1)[0].1.refused, 1);
    }

    #[test]
    fn rates_cover_the_whole_run_and_the_last_ten_seconds() {
        let t0 = Instant::now();
        let mut t = TrafficTally::new(t0);
        // 20 messages at the start, then 5 in the last 10 s of a 40 s run.
        for _ in 0..20 {
            t.record(&event("received", "a", "b", 1), t0);
        }
        let later = t0 + Duration::from_secs(35);
        for _ in 0..5 {
            t.record(&event("received", "a", "b", 1), later);
        }
        let now = t0 + Duration::from_secs(40);
        assert!((t.rate(now) - 25.0 / 40.0).abs() < 1e-9);
        assert!((t.rate_now(now) - 0.5).abs() < 1e-9, "{}", t.rate_now(now));
    }

    #[test]
    fn tracked_accounts_are_capped_and_the_stalest_gives_way() {
        let t0 = Instant::now();
        let mut t = TrafficTally::new(t0);
        for i in 0..MAX_ACCOUNTS + 10 {
            let now = t0 + Duration::from_millis(i as u64);
            t.record(&event("delivered", "x", &format!("acct-{i}"), 1), now);
        }
        assert_eq!(t.accounts(), MAX_ACCOUNTS);
        let kept: Vec<&str> = t.top(MAX_ACCOUNTS).into_iter().map(|(h, _)| h).collect();
        assert!(!kept.contains(&"acct-0"), "the oldest was dropped");
        assert!(kept.contains(&format!("acct-{}", MAX_ACCOUNTS + 9).as_str()));
    }

    #[test]
    fn counters_saturate_and_the_rate_window_stays_small() {
        let t0 = Instant::now();
        let mut t = TrafficTally::new(t0);
        t.record(&event("received", "a", "b", u64::MAX), t0);
        t.record(&event("received", "a", "b", u64::MAX), t0);
        assert_eq!(t.bytes, u64::MAX);
        for _ in 0..10_000 {
            t.record(&event("received", "a", "b", 1), t0);
        }
        assert!(
            t.recent.len() <= 2,
            "one bucket per second, not one entry per message"
        );
        assert!((t.rate_now(t0) - 10_002.0 / 10.0).abs() < 1e-9);
    }

    #[test]
    fn the_busiest_accounts_come_first() {
        let t0 = Instant::now();
        let mut t = TrafficTally::new(t0);
        for _ in 0..3 {
            t.record(&event("received", "busy", "x", 1), t0);
        }
        t.record(&event("received", "quiet", "y", 1), t0);
        let top: Vec<&str> = t.top(2).into_iter().map(|(h, _)| h).collect();
        assert_eq!(top[0], "busy");
        assert_eq!(t.accounts(), 4);
    }
}

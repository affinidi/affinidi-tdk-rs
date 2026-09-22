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

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use serde_json::Value;

/// The window the "now" rate is measured over.
const RECENT: Duration = Duration::from_secs(10);

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

/// Totals since the monitor started.
#[derive(Clone, Debug)]
pub struct TrafficTally {
    started: Instant,
    /// Messages that arrived.
    pub messages: u64,
    /// Bytes of the messages that arrived.
    pub bytes: u64,
    /// Messages refused.
    pub refused: u64,
    /// Arrival times within the last [`RECENT`], for the "now" rate.
    recent: VecDeque<Instant>,
    accounts: HashMap<String, AccountTally>,
}

impl TrafficTally {
    pub fn new(now: Instant) -> Self {
        Self {
            started: now,
            messages: 0,
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
                self.messages += 1;
                self.bytes += size;
                self.recent.push_back(now);
                if let Some(from) = from {
                    let a = self.account(from, now);
                    a.sent += 1;
                    a.bytes += size;
                }
                if let Some(to) = to {
                    self.account(to, now).addressed += 1;
                }
            }
            Some("delivered") => {
                if let Some(to) = to {
                    self.account(to, now).delivered += 1;
                }
            }
            Some("refused") => {
                self.refused += 1;
                if let Some(from) = from {
                    self.account(from, now).refused += 1;
                }
            }
            _ => {}
        }
        self.forget_before(now);
    }

    fn account(&mut self, hash: &str, now: Instant) -> &mut AccountTally {
        let a = self.accounts.entry(hash.to_string()).or_default();
        a.last = Some(now);
        a
    }

    fn forget_before(&mut self, now: Instant) {
        while self
            .recent
            .front()
            .is_some_and(|t| now.duration_since(*t) > RECENT)
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
        let in_window = self
            .recent
            .iter()
            .filter(|t| now.duration_since(**t) <= RECENT)
            .count();
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

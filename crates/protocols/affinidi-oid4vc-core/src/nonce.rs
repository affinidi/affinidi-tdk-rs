/*!
 * Replay prevention for OID4VC nonces.
 *
 * OID4VC binds a server-issued nonce into signed artifacts (the OpenID4VCI
 * `c_nonce` echoed in a key-binding proof; the OpenID4VP request `nonce` echoed
 * in a presentation). Checking that the echoed nonce *matches* (which the
 * protocol crates already do) stops a value being forged — but **not** a
 * captured-and-replayed artifact within the freshness window. Preventing replay
 * by ensuring each issued nonce is accepted **at most once** is a **MUST** for
 * issuers and verifiers; the matching check alone is not sufficient.
 *
 * [`NonceStore`] is a minimal, dependency-free helper for **single-process**
 * deployments. Multi-instance deployments must back replay prevention with
 * shared storage (e.g. Redis) so a nonce consumed on one node is rejected on
 * the others — this in-memory store does not coordinate across processes.
 */

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// An in-memory, single-use nonce store with a per-entry time-to-live.
///
/// Register each nonce you issue with [`register`](Self::register), then
/// [`consume`](Self::consume) it when it comes back. `consume` returns `true`
/// exactly once per registered, unexpired nonce; a replay (or an unknown or
/// expired nonce) returns `false`. Cloning isn't provided — share via `Arc`.
///
/// ```
/// use affinidi_oid4vc_core::nonce::NonceStore;
/// use std::time::Duration;
///
/// let store = NonceStore::new();
/// store.register("c_nonce-abc", Duration::from_secs(300));
///
/// assert!(store.consume("c_nonce-abc"));  // first use: accepted
/// assert!(!store.consume("c_nonce-abc")); // replay: rejected
/// assert!(!store.consume("never-issued")); // unknown: rejected
/// ```
#[derive(Default)]
pub struct NonceStore {
    // nonce -> expiry instant. A monotonic `Instant` (not wall-clock) so TTLs
    // are immune to system clock changes.
    inner: Mutex<HashMap<String, Instant>>,
}

impl NonceStore {
    /// Create an empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register an issued nonce, valid for `ttl` from now. Re-registering an
    /// existing nonce refreshes its expiry. Opportunistically evicts expired
    /// entries so the map can't grow without bound.
    pub fn register(&self, nonce: impl Into<String>, ttl: Duration) {
        let mut map = self.lock();
        let now = Instant::now();
        map.retain(|_, expiry| *expiry > now);
        map.insert(nonce.into(), now + ttl);
    }

    /// Atomically check-and-consume a nonce. Returns `true` iff the nonce was
    /// registered and has not expired or been consumed; the entry is removed so
    /// any later call for the same nonce (a replay) returns `false`. Unknown and
    /// expired nonces return `false`.
    pub fn consume(&self, nonce: &str) -> bool {
        let mut map = self.lock();
        match map.remove(nonce) {
            Some(expiry) => expiry > Instant::now(),
            None => false,
        }
    }

    /// Number of live (registered, unexpired, unconsumed) nonces, after evicting
    /// expired entries.
    pub fn len(&self) -> usize {
        let mut map = self.lock();
        let now = Instant::now();
        map.retain(|_, expiry| *expiry > now);
        map.len()
    }

    /// Whether the store holds no live nonces.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Instant>> {
        // Recover from a poisoned lock rather than propagating the panic: a
        // replay-prevention store should keep working after an unrelated panic.
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn consume_succeeds_once_then_rejects_replay() {
        let store = NonceStore::new();
        store.register("abc", Duration::from_secs(300));
        assert!(store.consume("abc"), "first use accepted");
        assert!(!store.consume("abc"), "replay rejected");
    }

    #[test]
    fn unknown_nonce_rejected() {
        let store = NonceStore::new();
        assert!(!store.consume("never-issued"));
    }

    #[test]
    fn expired_nonce_rejected() {
        let store = NonceStore::new();
        // Zero TTL: expiry == register-time instant, which is <= the (later)
        // consume-time instant, so it reads as expired.
        store.register("stale", Duration::ZERO);
        assert!(!store.consume("stale"));
    }

    #[test]
    fn len_counts_live_and_evicts_expired() {
        let store = NonceStore::new();
        store.register("live", Duration::from_secs(300));
        store.register("dead", Duration::ZERO);
        assert_eq!(store.len(), 1);
        assert!(!store.is_empty());
        assert!(store.consume("live"));
        assert!(store.is_empty());
    }
}

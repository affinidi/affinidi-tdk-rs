//! A deterministic, fault-injecting [`AsyncResolver`] for tests.
//!
//! [`StaticResolver`] returns canned outcomes for known DIDs without touching
//! the network, so a test can drive any code that depends on DID resolution
//! through exactly the path it wants: a successful document, a recognised-but-
//! failed resolution, an unhandled method (`None`), a slow resolution, or one
//! that never returns. It records every call so concurrency tests (e.g.
//! cache-stampede deduplication) can assert how many resolutions actually
//! happened.
//!
//! ```
//! use affinidi_tdk_test_support::resolver::{Outcome, StaticResolver};
//! use affinidi_did_common::Document;
//!
//! let did = "did:web:example.com";
//! let resolver = StaticResolver::new()
//!     .resolves(did, Document::new(did).unwrap());
//! ```

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use affinidi_did_common::{DID, Document};
use affinidi_did_resolver_traits::{AsyncResolver, Resolution, ResolverError};

/// What a [`StaticResolver`] does when asked to resolve a particular DID.
///
/// `Delays` wraps another outcome so a test can express "resolve after 2s" or
/// "fail after 500ms"; `Hangs` never completes, which is the lever for
/// request-path timeout tests.
#[derive(Clone)]
pub enum Outcome {
    /// Resolve to this document — the happy path. Boxed because a `Document`
    /// dwarfs the other variants.
    Resolves(Box<Document>),
    /// Recognise the DID but fail resolution
    /// (`Some(Err(ResolverError::ResolutionFailed))`).
    Fails(String),
    /// "Not my DID" — return `None` so a resolver chain falls through.
    NotHandled,
    /// Wait `after`, then apply the inner outcome.
    Delays {
        /// How long to sleep before applying `then`.
        after: Duration,
        /// The outcome to apply once the delay elapses.
        then: Box<Outcome>,
    },
    /// Never return. Drives "upstream resolution hangs" timeout tests.
    Hangs,
}

impl Outcome {
    /// Convenience: delay `after`, then resolve to `document`.
    pub fn resolves_after(after: Duration, document: Document) -> Self {
        Outcome::Delays {
            after,
            then: Box::new(Outcome::Resolves(Box::new(document))),
        }
    }
}

/// An in-memory [`AsyncResolver`] with per-DID canned outcomes and a recorded
/// call log.
///
/// Unknown DIDs get the `default` outcome, which is [`Outcome::NotHandled`]
/// (return `None`) unless overridden — matching the resolver-chain convention
/// that an unrecognised DID passes to the next resolver.
pub struct StaticResolver {
    name: String,
    default: Outcome,
    entries: HashMap<String, Outcome>,
    calls: Arc<Mutex<Vec<String>>>,
}

impl StaticResolver {
    /// A resolver that handles nothing until outcomes are registered.
    pub fn new() -> Self {
        Self {
            name: "StaticResolver".to_string(),
            default: Outcome::NotHandled,
            entries: HashMap::new(),
            calls: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Override the resolver name (must be unique within a resolver chain).
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = name.into();
        self
    }

    /// Register the outcome for a specific DID.
    ///
    /// `did` is matched against the resolved DID's canonical string form
    /// (`DID::to_string`); register the exact DID your code will resolve.
    pub fn outcome(mut self, did: impl Into<String>, outcome: Outcome) -> Self {
        self.entries.insert(did.into(), outcome);
        self
    }

    /// Shorthand for `outcome(did, Outcome::Resolves(document))`.
    pub fn resolves(self, did: impl Into<String>, document: Document) -> Self {
        self.outcome(did, Outcome::Resolves(Box::new(document)))
    }

    /// Set the outcome for DIDs with no explicit registration
    /// (defaults to [`Outcome::NotHandled`]).
    pub fn default_outcome(mut self, outcome: Outcome) -> Self {
        self.default = outcome;
        self
    }

    /// Every `resolve()` call this resolver has seen, in order, by DID string.
    pub fn calls(&self) -> Vec<String> {
        self.calls.lock().expect("calls mutex not poisoned").clone()
    }

    /// How many times a particular DID has been resolved.
    pub fn call_count(&self, did: &str) -> usize {
        self.calls
            .lock()
            .expect("calls mutex not poisoned")
            .iter()
            .filter(|d| d.as_str() == did)
            .count()
    }

    /// Total number of `resolve()` calls across all DIDs.
    pub fn total_calls(&self) -> usize {
        self.calls.lock().expect("calls mutex not poisoned").len()
    }
}

impl Default for StaticResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl AsyncResolver for StaticResolver {
    fn name(&self) -> &str {
        &self.name
    }

    fn resolve<'a>(
        &'a self,
        did: &'a DID,
    ) -> Pin<Box<dyn Future<Output = Resolution> + Send + 'a>> {
        let key = did.to_string();
        // Record the call and pick the outcome synchronously, releasing the
        // lock before we await so a `Hangs`/`Delays` outcome never holds it.
        self.calls
            .lock()
            .expect("calls mutex not poisoned")
            .push(key.clone());
        let outcome = self
            .entries
            .get(&key)
            .cloned()
            .unwrap_or_else(|| self.default.clone());
        Box::pin(eval(outcome))
    }
}

/// Apply an [`Outcome`], awaiting any delay or hanging forever as requested.
async fn eval(outcome: Outcome) -> Resolution {
    match outcome {
        Outcome::Resolves(doc) => Some(Ok(*doc)),
        Outcome::Fails(msg) => Some(Err(ResolverError::ResolutionFailed(msg))),
        Outcome::NotHandled => None,
        Outcome::Delays { after, then } => {
            tokio::time::sleep(after).await;
            Box::pin(eval(*then)).await
        }
        Outcome::Hangs => std::future::pending().await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn did(s: &str) -> DID {
        s.parse().expect("valid DID")
    }

    #[tokio::test]
    async fn resolves_registered_did() {
        let id = "did:web:example.com";
        let resolver = StaticResolver::new().resolves(id, Document::new(id).unwrap());

        let res = resolver.resolve(&did(id)).await;
        let doc = res.expect("handled").expect("ok");
        assert_eq!(doc.id.as_str(), "did:web:example.com");
        assert_eq!(resolver.call_count(id), 1);
    }

    #[tokio::test]
    async fn unknown_did_is_not_handled_by_default() {
        let resolver = StaticResolver::new();
        assert!(
            resolver
                .resolve(&did("did:web:example.com"))
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn fails_outcome_surfaces_error() {
        let id = "did:web:example.com";
        let resolver =
            StaticResolver::new().outcome(id, Outcome::Fails("upstream down".to_string()));
        let err = resolver.resolve(&did(id)).await.unwrap().unwrap_err();
        assert!(matches!(err, ResolverError::ResolutionFailed(_)));
    }

    #[tokio::test(start_paused = true)]
    async fn delays_then_resolves() {
        let id = "did:web:slow.example";
        let resolver = StaticResolver::new().outcome(
            id,
            Outcome::resolves_after(Duration::from_secs(5), Document::new(id).unwrap()),
        );
        // With time paused, the resolution only completes once time advances.
        let res = tokio::time::timeout(Duration::from_secs(10), resolver.resolve(&did(id))).await;
        assert!(res.is_ok(), "should resolve within the (virtual) window");
    }

    #[tokio::test(start_paused = true)]
    async fn hangs_never_resolves() {
        let id = "did:web:blackhole.example";
        let resolver = StaticResolver::new().outcome(id, Outcome::Hangs);
        let res = tokio::time::timeout(Duration::from_secs(30), resolver.resolve(&did(id))).await;
        assert!(res.is_err(), "a hanging resolution must trip the timeout");
    }

    #[tokio::test]
    async fn records_calls_for_dedup_assertions() {
        let id = "did:web:counted.example";
        let resolver = StaticResolver::new().resolves(id, Document::new(id).unwrap());
        for _ in 0..3 {
            let _ = resolver.resolve(&did(id)).await;
        }
        assert_eq!(resolver.total_calls(), 3);
        assert_eq!(resolver.call_count(id), 3);
        assert_eq!(resolver.calls(), vec![id, id, id]);
    }
}

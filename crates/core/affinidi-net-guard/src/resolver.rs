//! The connect-time half of the guard: a DNS resolver that vets every answer.

use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;

use reqwest::dns::{Addrs, Name, Resolve, Resolving};

use crate::EgressPolicy;

/// A [`reqwest::dns::Resolve`] that refuses to hand back an address its policy
/// blocks.
///
/// It resolves with the system resolver (or an `inner` resolver), fails the
/// whole name if **any** answer is blocked, and returns only the addresses it
/// checked. The connection is therefore made to exactly what was vetted: there
/// is no second lookup, and no window for DNS rebinding.
///
/// This is only half the guard. `reqwest` never consults a resolver when the
/// URL's host is an IP literal, and a proxy resolves names itself; vet URLs
/// with [`EgressPolicy::vet`] and build clients with
/// [`GuardedClientBuilder`](crate::GuardedClientBuilder), which does both.
#[derive(Clone)]
pub struct GuardedResolver {
    policy: EgressPolicy,
    inner: Option<Arc<dyn Resolve>>,
}

impl fmt::Debug for GuardedResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GuardedResolver")
            .field("policy", &self.policy)
            .field("inner", &self.inner.as_ref().map(|_| "custom"))
            .finish()
    }
}

impl GuardedResolver {
    /// A resolver that looks names up with the system resolver.
    pub fn new(policy: EgressPolicy) -> Self {
        Self {
            policy,
            inner: None,
        }
    }

    /// Look names up with `inner` instead (hickory, DNS-over-HTTPS, a test
    /// stub). Its answers are vetted exactly like the system resolver's.
    pub fn with_inner(mut self, inner: Arc<dyn Resolve>) -> Self {
        self.inner = Some(inner);
        self
    }
}

impl Resolve for GuardedResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let policy = self.policy.clone();
        let inner = self.inner.clone();
        Box::pin(async move {
            let host = name.as_str().to_owned();
            let addrs: Vec<SocketAddr> = match inner {
                Some(inner) => inner.resolve(name).await?.collect(),
                // Port 0: reqwest substitutes the URL's port, or the scheme's
                // default, for it.
                None => tokio::net::lookup_host((host.as_str(), 0)).await?.collect(),
            };
            policy.check_resolved(&host, &addrs)?;
            Ok(Box::new(addrs.into_iter()) as Addrs)
        })
    }
}

/// A [`GuardedResolver`] over the system resolver, ready for
/// `reqwest::ClientBuilder::dns_resolver`.
///
/// Installing it on your own client is not enough on its own; see
/// [`GuardedResolver`].
pub fn guarded_dns_resolver(policy: EgressPolicy) -> Arc<dyn Resolve> {
    Arc::new(GuardedResolver::new(policy))
}

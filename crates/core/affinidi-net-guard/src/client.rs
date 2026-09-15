//! [`GuardedClientBuilder`] and [`GuardedClient`]: both halves of the guard
//! on one `reqwest` client.

use std::any::Any;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use reqwest::dns::Resolve;
use reqwest::{Method, Request, RequestBuilder, Response};

use crate::redirect::{RedirectMode, redirect_policy};
use crate::resolver::GuardedResolver;
use crate::{EgressError, EgressPolicy, VettedUrl};

/// Default whole-request timeout.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

/// Default connect timeout.
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Default cap for [`GuardedClient::read_body_capped`]: 1 MiB.
pub const DEFAULT_MAX_BODY: usize = 1 << 20;

#[cfg(test)]
pub(crate) type ResolverWrap = Box<dyn FnOnce(Arc<dyn Resolve>) -> Arc<dyn Resolve> + Send>;

/// Builds a [`GuardedClient`].
///
/// The guard settings are applied last in [`build`](Self::build), so nothing
/// set here can undo them: the [`GuardedResolver`], the redirect policy,
/// finite timeouts, no proxy (neither the environment's nor any other), no
/// `Referer` on redirects, and `https_only` unless the policy has dev
/// loopback.
pub struct GuardedClientBuilder {
    policy: EgressPolicy,
    builder: reqwest::ClientBuilder,
    timeout: Duration,
    connect_timeout: Duration,
    redirects: RedirectMode,
    max_body: usize,
    inner_resolver: Option<Arc<dyn Resolve>>,
    #[cfg(test)]
    wrap_resolver: Option<ResolverWrap>,
}

impl fmt::Debug for GuardedClientBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GuardedClientBuilder")
            .field("policy", &self.policy)
            .field("timeout", &self.timeout)
            .field("connect_timeout", &self.connect_timeout)
            .field("redirects", &self.redirects)
            .field("max_body", &self.max_body)
            .finish_non_exhaustive()
    }
}

impl GuardedClientBuilder {
    /// Start a client for `policy`, with [`DEFAULT_TIMEOUT`],
    /// [`DEFAULT_CONNECT_TIMEOUT`], [`RedirectMode::None`] and
    /// [`DEFAULT_MAX_BODY`].
    pub fn new(policy: EgressPolicy) -> Self {
        Self {
            policy,
            builder: reqwest::Client::builder(),
            timeout: DEFAULT_TIMEOUT,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            redirects: RedirectMode::None,
            max_body: DEFAULT_MAX_BODY,
            inner_resolver: None,
            #[cfg(test)]
            wrap_resolver: None,
        }
    }

    /// Whole-request timeout.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Connect timeout.
    pub fn connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    /// How redirects are treated.
    pub fn redirects(mut self, mode: RedirectMode) -> Self {
        self.redirects = mode;
        self
    }

    /// Cap for [`GuardedClient::read_body_capped`].
    pub fn max_body(mut self, bytes: usize) -> Self {
        self.max_body = bytes;
        self
    }

    /// `User-Agent` header. An invalid value fails [`build`](Self::build).
    pub fn user_agent(mut self, value: impl Into<String>) -> Self {
        self.builder = self.builder.user_agent(value.into());
        self
    }

    /// How long an idle pooled connection may be reused.
    pub fn pool_idle_timeout(mut self, timeout: Duration) -> Self {
        self.builder = self.builder.pool_idle_timeout(timeout);
        self
    }

    /// A preconfigured TLS configuration, passed to
    /// `reqwest::ClientBuilder::tls_backend_preconfigured` (for example a
    /// `rustls::ClientConfig` with the platform verifier). TLS settings
    /// cannot change where a connection goes.
    pub fn tls_preconfigured(mut self, tls: impl Any) -> Self {
        self.builder = self.builder.tls_backend_preconfigured(tls);
        self
    }

    /// Look names up with `resolver` instead of the system resolver. Its
    /// answers are still vetted.
    pub fn inner_resolver(mut self, resolver: Arc<dyn Resolve>) -> Self {
        self.inner_resolver = Some(resolver);
        self
    }

    /// Wraps the guarded resolver: lets this crate's tests map a vetted
    /// public address onto a local listener.
    #[cfg(test)]
    pub(crate) fn wrap_resolver(mut self, wrap: ResolverWrap) -> Self {
        self.wrap_resolver = Some(wrap);
        self
    }

    /// Build the client.
    ///
    /// # Errors
    ///
    /// [`EgressError::Transport`] if `reqwest` cannot build it.
    pub fn build(self) -> Result<GuardedClient, EgressError> {
        let mut resolver = GuardedResolver::new(self.policy.clone());
        if let Some(inner) = self.inner_resolver {
            resolver = resolver.with_inner(inner);
        }
        let resolver: Arc<dyn Resolve> = Arc::new(resolver);
        #[cfg(test)]
        let resolver = match self.wrap_resolver {
            Some(wrap) => wrap(resolver),
            None => resolver,
        };
        let inner = self
            .builder
            .dns_resolver(resolver)
            .redirect(redirect_policy(self.policy.clone(), self.redirects))
            .timeout(self.timeout)
            .connect_timeout(self.connect_timeout)
            .https_only(!self.policy.is_dev_loopback())
            .referer(false)
            .no_proxy()
            .build()?;
        Ok(GuardedClient {
            inner,
            policy: self.policy,
            max_body: self.max_body,
        })
    }
}

/// A `reqwest` client that runs both halves of the guard.
///
/// Requests take a [`VettedUrl`] and re-vet it under this client's policy,
/// so a URL vetted under a looser policy cannot slip through. Cloning is
/// cheap.
#[derive(Debug, Clone)]
pub struct GuardedClient {
    inner: reqwest::Client,
    policy: EgressPolicy,
    max_body: usize,
}

impl GuardedClient {
    /// The policy this client enforces.
    pub fn policy(&self) -> &EgressPolicy {
        &self.policy
    }

    /// The cap [`read_body_capped`](Self::read_body_capped) applies.
    pub fn max_body(&self) -> usize {
        self.max_body
    }

    /// Start a `GET`.
    ///
    /// # Errors
    ///
    /// A refusal if `url` does not pass this client's policy.
    pub fn get(&self, url: &VettedUrl) -> Result<RequestBuilder, EgressError> {
        self.request(Method::GET, url)
    }

    /// Start a `POST`.
    ///
    /// # Errors
    ///
    /// A refusal if `url` does not pass this client's policy.
    pub fn post(&self, url: &VettedUrl) -> Result<RequestBuilder, EgressError> {
        self.request(Method::POST, url)
    }

    /// Start a request with any method.
    ///
    /// # Errors
    ///
    /// A refusal if `url` does not pass this client's policy.
    pub fn request(&self, method: Method, url: &VettedUrl) -> Result<RequestBuilder, EgressError> {
        let vetted = self.policy.vet_url(url.as_url())?;
        Ok(self.inner.request(method, vetted.into_url()))
    }

    /// Send a request built elsewhere (for libraries that produce their own
    /// request, such as a Web Push encoder). The request's URL is vetted
    /// under this client's policy and must be on `url`'s origin.
    ///
    /// # Errors
    ///
    /// A refusal, [`EgressError::CrossOrigin`], or
    /// [`EgressError::Transport`].
    pub async fn execute(
        &self,
        url: &VettedUrl,
        request: Request,
    ) -> Result<Response, EgressError> {
        let target = self.policy.vet_url(request.url())?;
        if target.as_url().origin() != url.as_url().origin() {
            return Err(EgressError::CrossOrigin(
                target.as_url().origin().ascii_serialization(),
            ));
        }
        Ok(self.inner.execute(request).await?)
    }

    /// Read a response body, refusing more than [`max_body`](Self::max_body)
    /// bytes whether or not the server declared a `Content-Length`.
    ///
    /// # Errors
    ///
    /// [`EgressError::BodyTooLarge`] or [`EgressError::Transport`].
    pub async fn read_body_capped(&self, mut response: Response) -> Result<Vec<u8>, EgressError> {
        let max = self.max_body;
        if response
            .content_length()
            .is_some_and(|declared| declared > max as u64)
        {
            return Err(EgressError::BodyTooLarge { max });
        }
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            if body.len() + chunk.len() > max {
                return Err(EgressError::BodyTooLarge { max });
            }
            body.extend_from_slice(&chunk);
        }
        Ok(body)
    }
}

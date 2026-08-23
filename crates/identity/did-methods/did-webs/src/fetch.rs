//! Fetching the two artifacts a `did:webs` identifier publishes.
//!
//! Both are fetched, and both are needed for different reasons: `keri.cesr`
//! is the only thing that carries authority, and `did.json` is what the
//! verified key state is checked against. A published document that cannot be
//! fetched is not fatal — the resolution is still fully determined by the KEL
//! — but a document that *disagrees* is.

use std::time::Duration;

use affinidi_did_common::Document;
use tracing::debug;

use crate::errors::DidWebsError;
use crate::identifier::{DID_JSON, DidWebs, KERI_CESR};
use crate::resolver::resolve_from_artifacts;

/// Default request timeout, matching the in-tree `did:web` resolver.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(20);

/// Largest artifact this resolver will read.
///
/// A KEL grows with every rotation and interaction, so it has no natural
/// bound, and the server is not trusted. Without a cap a resolution can be
/// turned into unbounded memory use by anyone who can serve a URL.
pub const MAX_ARTIFACT_BYTES: usize = 4 * 1024 * 1024;

/// A `did:webs` resolver holding a reusable HTTP client.
///
/// Resolution fetches two artifacts from the same host, so sharing a client —
/// and its connection pool — across them and across calls is worth doing.
#[derive(Debug, Clone)]
pub struct WebsResolver {
    client: reqwest::Client,
    allow_http: bool,
}

impl WebsResolver {
    /// A resolver with the default client.
    ///
    /// # Panics
    /// Panics only if the platform TLS backend cannot be initialised, which is
    /// the same condition under which `reqwest::Client::new` panics.
    pub fn new() -> Self {
        let client = reqwest::Client::builder()
            .user_agent(concat!("affinidi-did-webs/", env!("CARGO_PKG_VERSION")))
            .timeout(DEFAULT_TIMEOUT)
            .build()
            .unwrap_or_default();
        Self {
            client,
            allow_http: false,
        }
    }

    /// A resolver over a caller-supplied client, for custom timeouts, proxies,
    /// or a client shared with the rest of an application.
    pub fn with_client(client: reqwest::Client) -> Self {
        Self {
            client,
            allow_http: false,
        }
    }

    /// Permit plain HTTP for **any** host, not just loopback.
    ///
    /// Off by default, and it should stay off in production. A `did:webs`
    /// document is derived from a self-verifying key event log, so an attacker
    /// on the network cannot forge one — but they can serve a *stale* log,
    /// hiding a key rotation that has already happened, which is exactly the
    /// attack pre-rotation exists to defeat.
    ///
    /// It exists because the reference implementation
    /// (`hyperledger-labs/did-webs-resolver`) fetches over plain HTTP, so
    /// interoperating with it — or with any KERI tooling on a private network
    /// without TLS — otherwise cannot work at all.
    pub fn allow_http(mut self, allow: bool) -> Self {
        self.allow_http = allow;
        self
    }

    /// The scheme to fetch this DID's artifacts over.
    fn scheme(&self, did: &DidWebs) -> &'static str {
        if self.allow_http || did.is_loopback() {
            "http"
        } else {
            "https"
        }
    }

    /// Resolve a `did:webs` identifier.
    ///
    /// # Errors
    /// Returns [`DidWebsError`] if the DID is malformed, `keri.cesr` cannot be
    /// fetched or read, the key event log does not verify, or the published
    /// `did.json` disagrees with the verified key state.
    pub async fn resolve(&self, did: &str) -> Result<Document, DidWebsError> {
        let parsed = DidWebs::parse(did)?;

        let scheme = self.scheme(&parsed);
        let cesr_url = parsed.artifact_url_with_scheme(scheme, KERI_CESR);
        let keri_cesr = self.fetch(&cesr_url).await?;

        // A missing or unreadable did.json does not change the answer, because
        // the answer comes from the KEL. It is only ever a cross-check, so a
        // fetch failure is logged rather than propagated — while a document
        // that *disagrees* is refused inside `resolve_from_artifacts`.
        let did_json_url = parsed.artifact_url_with_scheme(scheme, DID_JSON);
        let did_json = match self.fetch(&did_json_url).await {
            Ok(bytes) => Some(bytes),
            Err(e) => {
                debug!("{did_json_url} could not be fetched, resolving from keri.cesr alone: {e}");
                None
            }
        };

        resolve_from_artifacts(&parsed, &keri_cesr, did_json.as_deref())
    }

    /// Fetch one artifact, refusing anything larger than [`MAX_ARTIFACT_BYTES`].
    async fn fetch(&self, url: &str) -> Result<Vec<u8>, DidWebsError> {
        let response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|e| DidWebsError::Fetch {
                url: url.to_string(),
                reason: e.to_string(),
            })?;

        if !response.status().is_success() {
            return Err(DidWebsError::Fetch {
                url: url.to_string(),
                reason: format!("HTTP {}", response.status()),
            });
        }

        // Check the advertised length first so an oversized body is refused
        // before it is read, then check again while reading: `Content-Length`
        // is the server's claim, not a fact.
        if let Some(len) = response.content_length()
            && len > MAX_ARTIFACT_BYTES as u64
        {
            return Err(DidWebsError::Fetch {
                url: url.to_string(),
                reason: format!("artifact declares {len} bytes, over the {MAX_ARTIFACT_BYTES} cap"),
            });
        }

        let bytes = response.bytes().await.map_err(|e| DidWebsError::Fetch {
            url: url.to_string(),
            reason: e.to_string(),
        })?;

        if bytes.len() > MAX_ARTIFACT_BYTES {
            return Err(DidWebsError::Fetch {
                url: url.to_string(),
                reason: format!(
                    "artifact is {} bytes, over the {MAX_ARTIFACT_BYTES} cap",
                    bytes.len()
                ),
            });
        }

        Ok(bytes.to_vec())
    }
}

impl Default for WebsResolver {
    fn default() -> Self {
        Self::new()
    }
}

/// Resolve a `did:webs` identifier with a one-off client.
///
/// Prefer [`WebsResolver`] when resolving more than once, so the connection
/// pool is reused.
///
/// # Errors
/// See [`WebsResolver::resolve`].
pub async fn resolve(did: &str) -> Result<Document, DidWebsError> {
    WebsResolver::new().resolve(did).await
}

//! Network DID method resolvers implementing [`AsyncResolver`].
//!
//! Each struct wraps an external resolver crate and normalizes its interface
//! into the uniform `AsyncResolver` contract. Feature-gated resolvers are
//! conditionally compiled.

use std::future::Future;
use std::pin::Pin;

use affinidi_did_common::{DID, DIDMethod};
pub use affinidi_did_web::HostPolicy;
// `Document` is only named by the ssi-backed helper below, which is gated.
#[cfg(feature = "did-cheqd")]
use affinidi_did_common::Document;
use affinidi_did_resolver_traits::{AsyncResolver, Resolution, ResolverError};
use tracing::error;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Convert an ssi `DIDResolver` result (typed output) into a `Document`.
#[cfg(feature = "did-cheqd")]
fn document_from_ssi_output(output: impl serde::Serialize) -> Result<Document, ResolverError> {
    let value = serde_json::to_value(output)
        .map_err(|e| ResolverError::InvalidDocument(format!("Serialization failed: {e}")))?;
    serde_json::from_value(value)
        .map_err(|e| ResolverError::InvalidDocument(format!("Invalid document shape: {e}")))
}

// ---------------------------------------------------------------------------
// did:ethr
// ---------------------------------------------------------------------------

/// Resolver for `did:ethr` — Ethereum DID method.
///
/// Resolution is an offline derivation from the identifier: this does not
/// replay ERC-1056 registry events, so the document is the DID's genesis state.
#[cfg(feature = "did-ethr")]
pub struct EthrResolver;

#[cfg(feature = "did-ethr")]
impl AsyncResolver for EthrResolver {
    fn name(&self) -> &str {
        "EthrResolver"
    }

    fn resolve<'a>(
        &'a self,
        did: &'a DID,
    ) -> Pin<Box<dyn Future<Output = Resolution> + Send + 'a>> {
        Box::pin(async move {
            let identifier = match did.method() {
                DIDMethod::Ethr { identifier, .. } => identifier,
                _ => return None,
            };

            Some(
                affinidi_did_ethr::resolve_identifier(&identifier).map_err(|e| {
                    error!("did:ethr resolution error: {e:?}");
                    ResolverError::ResolutionFailed(e.to_string())
                }),
            )
        })
    }
}

// ---------------------------------------------------------------------------
// did:pkh
// ---------------------------------------------------------------------------

/// Resolver for `did:pkh` — PKH (Public Key Hash) DID method.
#[cfg(feature = "did-pkh")]
pub struct PkhResolver;

#[cfg(feature = "did-pkh")]
impl AsyncResolver for PkhResolver {
    fn name(&self) -> &str {
        "PkhResolver"
    }

    fn resolve<'a>(
        &'a self,
        did: &'a DID,
    ) -> Pin<Box<dyn Future<Output = Resolution> + Send + 'a>> {
        Box::pin(async move {
            let identifier = match did.method() {
                DIDMethod::Pkh { identifier, .. } => identifier,
                _ => return None,
            };

            Some(
                affinidi_did_pkh::resolve_identifier(&identifier).map_err(|e| {
                    error!("did:pkh resolution error: {e:?}");
                    ResolverError::ResolutionFailed(e.to_string())
                }),
            )
        })
    }
}

// ---------------------------------------------------------------------------
// did:web
// ---------------------------------------------------------------------------

/// Resolver for `did:web` — Web DID method.
///
/// Backed by [`affinidi_did_web`], which sits on `reqwest 0.13` / `rustls 0.23`
/// instead of the spruceid `did-web` crate's `reqwest 0.11` / `rustls 0.21`
/// stack — clearing the rustls-webpki advisories that previously came in
/// transitively through this resolver.
///
/// A `did:web` value names the host to fetch from, so by default this refuses
/// non-routable targets — see [`HostPolicy`]. A deployment whose did:web hosts
/// really do live on an internal network (or a local test stack using
/// `did:web:localhost%3A8080`) opts out with [`WebResolver::with_policy`] and
/// installs it via [`crate::DIDCacheClient::set_resolver`].
pub struct WebResolver {
    inner: affinidi_did_web::DIDWeb,
}

impl WebResolver {
    /// Create a resolver with the default HTTP client, refusing non-routable
    /// hosts.
    pub fn new() -> Self {
        Self::with_policy(HostPolicy::PublicOnly)
    }

    /// Create a resolver with the default HTTP client under an explicit
    /// [`HostPolicy`].
    pub fn with_policy(policy: HostPolicy) -> Self {
        Self {
            inner: affinidi_did_web::DIDWeb::with_policy(policy),
        }
    }
}

impl Default for WebResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl AsyncResolver for WebResolver {
    fn name(&self) -> &str {
        "WebResolver"
    }

    fn resolve<'a>(
        &'a self,
        did: &'a DID,
    ) -> Pin<Box<dyn Future<Output = Resolution> + Send + 'a>> {
        Box::pin(async move {
            if !matches!(did.method(), DIDMethod::Web { .. }) {
                return None;
            }

            let did_str = did.to_string();
            Some(match self.inner.resolve(&did_str).await {
                Ok(doc) => Ok(doc),
                Err(e) => {
                    error!("did:web resolution error: {e:?}");
                    Err(ResolverError::ResolutionFailed(e.to_string()))
                }
            })
        })
    }
}

// ---------------------------------------------------------------------------
// did:jwk (feature-gated)
// ---------------------------------------------------------------------------

/// Resolver for `did:jwk` — JSON Web Key DID method.
#[cfg(feature = "did-jwk")]
pub struct JwkResolver;

#[cfg(feature = "did-jwk")]
impl AsyncResolver for JwkResolver {
    fn name(&self) -> &str {
        "JwkResolver"
    }

    fn resolve<'a>(
        &'a self,
        did: &'a DID,
    ) -> Pin<Box<dyn Future<Output = Resolution> + Send + 'a>> {
        Box::pin(async move {
            let identifier = match did.method() {
                DIDMethod::Jwk { identifier, .. } => identifier,
                _ => return None,
            };

            Some(
                affinidi_did_jwk::resolve_identifier(&identifier).map_err(|e| {
                    error!("did:jwk resolution error: {e:?}");
                    ResolverError::ResolutionFailed(e.to_string())
                }),
            )
        })
    }
}

// ---------------------------------------------------------------------------
// did:webvh (feature-gated)
// ---------------------------------------------------------------------------

/// Resolver for `did:webvh` — Web Verifiable History DID method.
#[cfg(feature = "did-webvh")]
pub struct WebvhResolver;

#[cfg(feature = "did-webvh")]
impl AsyncResolver for WebvhResolver {
    fn name(&self) -> &str {
        "WebvhResolver"
    }

    fn resolve<'a>(
        &'a self,
        did: &'a DID,
    ) -> Pin<Box<dyn Future<Output = Resolution> + Send + 'a>> {
        Box::pin(async move {
            if !matches!(did.method(), DIDMethod::Webvh { .. }) {
                return None;
            }

            use didwebvh_rs::log_entry::LogEntryMethods;

            let mut method = didwebvh_rs::DIDWebVHState::default();
            let did_str = did.to_string();

            Some(match method.resolve(&did_str, Default::default()).await {
                Ok((log_entry, _)) => {
                    let doc_value = log_entry.get_did_document().map_err(|e| {
                        ResolverError::InvalidDocument(format!(
                            "Resolved webvh DID but couldn't convert to DID Document: {e}"
                        ))
                    });
                    match doc_value {
                        Ok(value) => serde_json::from_value(value).map_err(|e| {
                            ResolverError::InvalidDocument(format!("Invalid document: {e}"))
                        }),
                        Err(e) => Err(e),
                    }
                }
                Err(e) => {
                    error!("did:webvh resolution error: {e:?}");
                    Err(ResolverError::ResolutionFailed(e.to_string()))
                }
            })
        })
    }
}

// ---------------------------------------------------------------------------
// did:cheqd (feature-gated)
// ---------------------------------------------------------------------------

/// Resolver for `did:cheqd` — Cheqd network DID method.
#[cfg(feature = "did-cheqd")]
pub struct CheqdResolver;

#[cfg(feature = "did-cheqd")]
impl AsyncResolver for CheqdResolver {
    fn name(&self) -> &str {
        "CheqdResolver"
    }

    fn resolve<'a>(
        &'a self,
        did: &'a DID,
    ) -> Pin<Box<dyn Future<Output = Resolution> + Send + 'a>> {
        Box::pin(async move {
            if !matches!(did.method(), DIDMethod::Cheqd { .. }) {
                return None;
            }

            let did_str = did.to_string();
            use ssi_dids_core::DIDResolver;
            let ssi_did = match ssi_dids_core::DID::new(&did_str) {
                Ok(d) => d,
                Err(e) => {
                    return Some(Err(ResolverError::InvalidDocument(format!(
                        "Invalid DID: {e}"
                    ))));
                }
            };

            Some(
                match did_resolver_cheqd::DIDCheqd::default()
                    .resolve(ssi_did)
                    .await
                {
                    Ok(res) => document_from_ssi_output(res.document.into_document()),
                    Err(e) => {
                        error!("did:cheqd resolution error: {e:?}");
                        Err(ResolverError::ResolutionFailed(e.to_string()))
                    }
                },
            )
        })
    }
}

// ---------------------------------------------------------------------------
// did:scid (feature-gated)
// ---------------------------------------------------------------------------

/// Resolver for `did:scid` — Self-Certifying Identifier DID method.
#[cfg(feature = "did-scid")]
pub struct ScidResolver;

#[cfg(feature = "did-scid")]
impl AsyncResolver for ScidResolver {
    fn name(&self) -> &str {
        "ScidResolver"
    }

    fn resolve<'a>(
        &'a self,
        did: &'a DID,
    ) -> Pin<Box<dyn Future<Output = Resolution> + Send + 'a>> {
        Box::pin(async move {
            if !matches!(did.method(), DIDMethod::Scid { .. }) {
                return None;
            }

            let did_str = did.to_string();

            Some(did_scid::resolve(&did_str, None, None).await.map_err(|e| {
                error!("did:scid resolution error: {e:?}");
                ResolverError::ResolutionFailed(e.to_string())
            }))
        })
    }
}

// ---------------------------------------------------------------------------
// did:ebsi (feature-gated)
// ---------------------------------------------------------------------------

/// Resolver for `did:ebsi` — EBSI DID method for legal entities.
///
/// Resolves DIDs via the EBSI DID Registry API (pilot environment by default).
#[cfg(feature = "did-ebsi")]
pub struct EbsiResolver;

#[cfg(feature = "did-ebsi")]
impl AsyncResolver for EbsiResolver {
    fn name(&self) -> &str {
        "EbsiResolver"
    }

    fn resolve<'a>(
        &'a self,
        did: &'a DID,
    ) -> Pin<Box<dyn Future<Output = Resolution> + Send + 'a>> {
        Box::pin(async move {
            if !matches!(did.method(), DIDMethod::Ebsi { .. }) {
                return None;
            }

            let did_str = did.to_string();
            Some(
                did_ebsi::resolve_ebsi_did(&did_str, did_ebsi::EBSI_PILOT_API)
                    .await
                    .map_err(|e| {
                        error!("did:ebsi resolution error: {e:?}");
                        ResolverError::ResolutionFailed(e.to_string())
                    }),
            )
        })
    }
}

// ---------------------------------------------------------------------------
// did:webs (feature-gated)
// ---------------------------------------------------------------------------

/// Resolver for `did:webs` — `did:web` discovery with KERI-verified key state.
///
/// Fetches `keri.cesr` and `did.json` from the DID's location, verifies the key
/// event log, and returns the document that key state implies. The published
/// `did.json` is cross-checked rather than trusted; a disagreement fails the
/// resolution.
///
/// `did:webs` is not modelled by [`DIDMethod`], so it arrives here as
/// `DIDMethod::Other { method: "webs", .. }` and is registered under
/// `MethodName::Other("webs")`.
#[cfg(feature = "did-webs")]
pub struct WebsResolver {
    inner: affinidi_did_webs::WebsResolver,
}

#[cfg(feature = "did-webs")]
impl WebsResolver {
    /// A resolver with its own HTTP client and connection pool.
    pub fn new() -> Self {
        Self {
            inner: affinidi_did_webs::WebsResolver::new(),
        }
    }
}

#[cfg(feature = "did-webs")]
impl Default for WebsResolver {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "did-webs")]
impl AsyncResolver for WebsResolver {
    fn name(&self) -> &str {
        "WebsResolver"
    }

    fn resolve<'a>(
        &'a self,
        did: &'a DID,
    ) -> Pin<Box<dyn Future<Output = Resolution> + Send + 'a>> {
        Box::pin(async move {
            match did.method() {
                DIDMethod::Other { method, .. } if method == "webs" => {}
                _ => return None,
            }

            let did_str = did.to_string();
            Some(self.inner.resolve(&did_str).await.map_err(|e| {
                error!("did:webs resolution error: {e:?}");
                ResolverError::ResolutionFailed(e.to_string())
            }))
        })
    }
}

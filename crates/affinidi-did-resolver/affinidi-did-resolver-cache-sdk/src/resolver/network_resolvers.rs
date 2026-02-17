//! Network DID method resolvers implementing [`AsyncResolver`].
//!
//! Each struct wraps an external resolver crate and normalizes its interface
//! into the uniform `AsyncResolver` contract. Feature-gated resolvers are
//! conditionally compiled.

use std::future::Future;
use std::pin::Pin;

use affinidi_did_common::{DID, DIDMethod, Document};
use affinidi_did_resolver_traits::{AsyncResolver, Resolution, ResolverError};
use tracing::error;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Convert an ssi `DIDMethodResolver` result (raw bytes) into a `Document`.
fn document_from_bytes(bytes: Vec<u8>) -> Result<Document, ResolverError> {
    let json = String::from_utf8(bytes)
        .map_err(|e| ResolverError::InvalidDocument(format!("Invalid UTF-8: {e}")))?;
    serde_json::from_str(&json)
        .map_err(|e| ResolverError::InvalidDocument(format!("Invalid JSON document: {e}")))
}

/// Convert an ssi `DIDResolver` result (typed output) into a `Document`.
fn document_from_ssi_output(
    output: impl serde::Serialize,
) -> Result<Document, ResolverError> {
    let value = serde_json::to_value(output)
        .map_err(|e| ResolverError::InvalidDocument(format!("Serialization failed: {e}")))?;
    serde_json::from_value(value)
        .map_err(|e| ResolverError::InvalidDocument(format!("Invalid document shape: {e}")))
}


// ---------------------------------------------------------------------------
// did:ethr
// ---------------------------------------------------------------------------

/// Resolver for `did:ethr` — Ethereum DID method.
pub struct EthrResolver;

impl AsyncResolver for EthrResolver {
    fn resolve<'a>(&'a self, did: &'a DID) -> Pin<Box<dyn Future<Output = Resolution> + Send + 'a>> {
        Box::pin(async move {
            let identifier = match did.method() {
                DIDMethod::Ethr { identifier, .. } => identifier,
                _ => return None,
            };

            let method = did_ethr::DIDEthr;
            use ssi_dids_core::DIDMethodResolver;

            Some(
                match method
                    .resolve_method_representation(
                        &identifier,
                        ssi_dids_core::resolution::Options::default(),
                    )
                    .await
                {
                    Ok(res) => document_from_bytes(res.document),
                    Err(e) => {
                        error!("did:ethr resolution error: {e:?}");
                        Err(ResolverError::ResolutionFailed(e.to_string()))
                    }
                },
            )
        })
    }
}

// ---------------------------------------------------------------------------
// did:pkh
// ---------------------------------------------------------------------------

/// Resolver for `did:pkh` — PKH (Public Key Hash) DID method.
pub struct PkhResolver;

impl AsyncResolver for PkhResolver {
    fn resolve<'a>(&'a self, did: &'a DID) -> Pin<Box<dyn Future<Output = Resolution> + Send + 'a>> {
        Box::pin(async move {
            if !matches!(did.method(), DIDMethod::Pkh { .. }) {
                return None;
            }

            let method = did_pkh::DIDPKH;
            let did_str = did.to_string();
            use ssi_dids_core::DIDResolver;
            let ssi_did = match ssi_dids_core::DID::new(&did_str) {
                Ok(d) => d,
                Err(e) => return Some(Err(ResolverError::InvalidDocument(format!("Invalid DID: {e}")))),
            };

            Some(
                match method
                    .resolve(ssi_did)
                    .await
                {
                    Ok(res) => document_from_ssi_output(res.document.into_document()),
                    Err(e) => {
                        error!("did:pkh resolution error: {e:?}");
                        Err(ResolverError::ResolutionFailed(e.to_string()))
                    }
                },
            )
        })
    }
}

// ---------------------------------------------------------------------------
// did:web
// ---------------------------------------------------------------------------

/// Resolver for `did:web` — Web DID method.
pub struct WebResolver;

impl AsyncResolver for WebResolver {
    fn resolve<'a>(&'a self, did: &'a DID) -> Pin<Box<dyn Future<Output = Resolution> + Send + 'a>> {
        Box::pin(async move {
            if !matches!(did.method(), DIDMethod::Web { .. }) {
                return None;
            }

            let method = did_web::DIDWeb;
            let did_str = did.to_string();
            use ssi_dids_core::DIDResolver;
            let ssi_did = match ssi_dids_core::DID::new(&did_str) {
                Ok(d) => d,
                Err(e) => return Some(Err(ResolverError::InvalidDocument(format!("Invalid DID: {e}")))),
            };

            Some(
                match method
                    .resolve(ssi_did)
                    .await
                {
                    Ok(res) => document_from_ssi_output(res.document.into_document()),
                    Err(e) => {
                        error!("did:web resolution error: {e:?}");
                        Err(ResolverError::ResolutionFailed(e.to_string()))
                    }
                },
            )
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
    fn resolve<'a>(&'a self, did: &'a DID) -> Pin<Box<dyn Future<Output = Resolution> + Send + 'a>> {
        Box::pin(async move {
            if !matches!(did.method(), DIDMethod::Jwk { .. }) {
                return None;
            }

            let method = did_jwk::DIDJWK;
            use ssi_dids_core::DIDMethodResolver;

            Some(
                match method
                    .resolve_method_representation(
                        &did.method_specific_id(),
                        ssi_dids_core::resolution::Options::default(),
                    )
                    .await
                {
                    Ok(res) => document_from_bytes(res.document),
                    Err(e) => {
                        error!("did:jwk resolution error: {e:?}");
                        Err(ResolverError::ResolutionFailed(e.to_string()))
                    }
                },
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
    fn resolve<'a>(&'a self, did: &'a DID) -> Pin<Box<dyn Future<Output = Resolution> + Send + 'a>> {
        Box::pin(async move {
            if !matches!(did.method(), DIDMethod::Webvh { .. }) {
                return None;
            }

            use didwebvh_rs::log_entry::LogEntryMethods;

            let mut method = didwebvh_rs::DIDWebVHState::default();
            let did_str = did.to_string();

            Some(match method.resolve(&did_str, None).await {
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
    fn resolve<'a>(&'a self, did: &'a DID) -> Pin<Box<dyn Future<Output = Resolution> + Send + 'a>> {
        Box::pin(async move {
            if !matches!(did.method(), DIDMethod::Cheqd { .. }) {
                return None;
            }

            let did_str = did.to_string();
            use ssi_dids_core::DIDResolver;
            let ssi_did = match ssi_dids_core::DID::new(&did_str) {
                Ok(d) => d,
                Err(e) => return Some(Err(ResolverError::InvalidDocument(format!("Invalid DID: {e}")))),
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
    fn resolve<'a>(&'a self, did: &'a DID) -> Pin<Box<dyn Future<Output = Resolution> + Send + 'a>> {
        Box::pin(async move {
            if !matches!(did.method(), DIDMethod::Scid { .. }) {
                return None;
            }

            let did_str = did.to_string();

            Some(
                did_scid::resolve(&did_str, None, None)
                    .await
                    .map_err(|e| {
                        error!("did:scid resolution error: {e:?}");
                        ResolverError::ResolutionFailed(e.to_string())
                    }),
            )
        })
    }
}

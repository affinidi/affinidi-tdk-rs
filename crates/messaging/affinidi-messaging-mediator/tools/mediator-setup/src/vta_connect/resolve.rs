//! Thin wrapper over `vta_sdk::session::resolve_vta_endpoint` that presents a
//! cleaner result type and distinguishes "DIDComm only" / "REST only" / "both"
//! for the diagnostics UI.

use vta_sdk::session::{VtaEndpoint, resolve_vta_endpoint};

#[derive(Clone, Debug)]
#[allow(dead_code)] // `vta_did` mirrors upstream `VtaEndpoint`; kept for symmetry / future audit display.
pub struct ResolvedVta {
    pub vta_did: String,
    /// DIDComm mediator DID advertised in the VTA document, if any.
    pub mediator_did: Option<String>,
    /// REST URL advertised via the `#vta-rest` service, if any.
    pub rest_url: Option<String>,
}

/// Resolve a VTA DID and extract its transport endpoints.
///
/// Returns an error if the DID cannot be resolved and no fallback URL can be
/// inferred from the DID string.
pub async fn resolve_vta(vta_did: &str) -> anyhow::Result<ResolvedVta> {
    match resolve_vta_endpoint(vta_did)
        .await
        .map_err(|e| anyhow::anyhow!("resolve {vta_did}: {e}"))?
    {
        VtaEndpoint::DIDComm {
            vta_did,
            mediator_did,
            rest_url,
        } => Ok(ResolvedVta {
            vta_did,
            mediator_did: Some(mediator_did),
            rest_url,
        }),
        VtaEndpoint::Rest { url } => Ok(ResolvedVta {
            vta_did: vta_did.to_string(),
            mediator_did: None,
            rest_url: Some(url),
        }),
    }
}

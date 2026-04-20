//! VTA-managed mediator DID creation.
//!
//! When the operator has an online VTA and picks `Configure via VTA`, the
//! VTA hosts the mediator's DID — keys stay on the VTA, the DID document is
//! minted server-side and published by the VTA's webvh server.
//!
//! The wizard asks the VTA to render the built-in `didcomm-mediator`
//! template with the mediator's public URL. The server injects ambient
//! vars (`DID`, `SIGNING_KEY_MB`, `KA_KEY_MB`, etc.) automatically. If an
//! operator wants a custom shape, they upload a context- or global-scoped
//! template under the same name via `pnm did-templates create` and the
//! VTA's resolution order (context → global → builtin) picks it up on the
//! next wizard run.
//!
//! The returned DID goes into `mediator.toml`; no local secrets are
//! written — at runtime the mediator fetches its `DidSecretsBundle` from
//! the VTA context via the existing `integration::startup` pattern.

use vta_sdk::{
    client::{CreateDidWebvhRequest, VtaClient},
    protocols::did_management::create::CreateDidWebvhResultBody,
};

/// Result of a VTA-managed mediator DID creation.
///
/// `did_document` is returned by the VTA on success and may be useful for
/// writing a local reference copy. No secrets are produced — all key
/// material stays inside the VTA's secure store.
pub struct VtaMediatorDid {
    pub did: String,
    pub context_id: String,
    pub signing_key_id: String,
    pub ka_key_id: String,
    pub did_document: Option<serde_json::Value>,
    pub log_entry: Option<String>,
}

impl From<CreateDidWebvhResultBody> for VtaMediatorDid {
    fn from(r: CreateDidWebvhResultBody) -> Self {
        Self {
            did: r.did,
            context_id: r.context_id,
            signing_key_id: r.signing_key_id,
            ka_key_id: r.ka_key_id,
            did_document: r.did_document,
            log_entry: r.log_entry,
        }
    }
}

/// Name of the built-in template the VTA uses to render the mediator DID
/// document. Operators can shadow this in the context or global scope by
/// uploading a template with the same name via
/// `pnm did-templates create --name didcomm-mediator …`.
pub const MEDIATOR_TEMPLATE: &str = "didcomm-mediator";

/// Ask the VTA to mint a webvh DID for the mediator under `context_id`.
///
/// The document shape is produced by rendering the `didcomm-mediator`
/// template with `URL = mediator_url`; the server mints Ed25519 signing +
/// X25519 key-agreement keys and injects ambient template variables. The
/// `template_context` is set to the same context id so context-scoped
/// overrides shadow the built-in cleanly.
pub async fn create_vta_mediator_did(
    rest_url: &str,
    access_token: &str,
    context_id: &str,
    mediator_url: &str,
) -> anyhow::Result<VtaMediatorDid> {
    let client = VtaClient::new(rest_url);
    client.set_token_async(access_token.to_string()).await;

    let mut template_vars = std::collections::HashMap::new();
    template_vars.insert(
        "URL".to_string(),
        serde_json::Value::String(mediator_url.to_string()),
    );

    let req = CreateDidWebvhRequest {
        context_id: context_id.to_string(),
        server_id: None,
        url: None,
        path: None,
        label: Some("mediator".into()),
        portable: true,
        add_mediator_service: false,
        additional_services: None,
        pre_rotation_count: 2,
        did_document: None,
        did_log: None,
        set_primary: true,
        signing_key_id: None,
        ka_key_id: None,
        template: Some(MEDIATOR_TEMPLATE.into()),
        template_context: Some(context_id.to_string()),
        template_vars,
    };

    let result = client
        .create_did_webvh(req)
        .await
        .map_err(|e| anyhow::anyhow!("VTA create_did_webvh failed: {e}"))?;
    Ok(result.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_result_maps_all_fields() {
        // Round-trip through JSON so we don't need to depend on `chrono`
        // just to construct a timestamp in a unit test.
        let raw_json = serde_json::json!({
            "did": "did:webvh:SCID:mediator.example.com",
            "context_id": "mediator",
            "server_id": "webvh-1",
            "scid": "SCID",
            "portable": true,
            "signing_key_id": "sign-123",
            "ka_key_id": "ka-456",
            "pre_rotation_key_count": 2,
            "created_at": "2026-04-19T00:00:00Z",
            "did_document": { "id": "did:webvh:..." },
            "log_entry": "{...}",
        });
        let raw: CreateDidWebvhResultBody = serde_json::from_value(raw_json).unwrap();
        let mapped: VtaMediatorDid = raw.into();
        assert_eq!(mapped.did, "did:webvh:SCID:mediator.example.com");
        assert_eq!(mapped.context_id, "mediator");
        assert_eq!(mapped.signing_key_id, "sign-123");
        assert_eq!(mapped.ka_key_id, "ka-456");
        assert!(mapped.did_document.is_some());
        assert!(mapped.log_entry.is_some());
    }
}

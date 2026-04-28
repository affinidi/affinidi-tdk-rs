//! Generate a self-hosted `did:webvh` DID for the mediator.
//!
//! Renders the canonical `didcomm-mediator` template (shipped in the
//! `vta_sdk::did_templates` built-ins) with the mediator's keys + URL,
//! then hands the resulting document to `didwebvh_rs::create::create_did`.
//! The template is the same one the VTA renders server-side, so the DID
//! document shape is identical whether the mediator is self-hosted or
//! VTA-managed.
//!
//! Operators who want a different shape can fork the built-in via
//! `pnm did-templates init didcomm-mediator > custom.json`, edit, and
//! upload under the same name — the VTA's resolution order (context →
//! global → built-in) picks the override up automatically. This local
//! generator is the self-hosted sibling: it always uses the built-in, but
//! the produced shape matches what a VTA with the built-in would produce.

use std::sync::Arc;

use affinidi_secrets_resolver::secrets::Secret;
use didwebvh_rs::{
    create::{CreateDIDConfig, create_did},
    parameters::Parameters,
};
use vta_sdk::did_templates::{TemplateVars, load_embedded};

pub struct DidWebvhResult {
    /// The final DID string (resolved from the WebVH log entry).
    pub did: String,
    /// Private keys the mediator needs at runtime — Ed25519 signing, X25519
    /// key-agreement.
    pub secrets: Vec<Secret>,
    /// The DID document log entry in JSONL form, ready for the operator to
    /// host at the webvh URL.
    pub did_doc: String,
}

/// Generate a did:webvh DID for the mediator.
///
/// `address` is the host-only base URL (`https://mediator.example.com`)
/// — it gets encoded into the DID identifier and is what webvh resolvers
/// use to locate `/.well-known/did.jsonl`. Strip any HTTP path before
/// passing it in; otherwise the DID becomes
/// `did:webvh:<scid>:host:foo:bar` and resolves at `/foo/bar/did.jsonl`
/// instead of `/.well-known/did.jsonl`.
///
/// `service_url` is what gets fed to the template's `URL` variable and
/// becomes the service-endpoint base in the rendered DID document.
/// Should be the mediator's full public URL including any HTTP API
/// prefix (`https://mediator.example.com/mediator/v1`) so clients
/// resolving the DID hit the actual mediator routes.
pub async fn generate_did_webvh(
    address: &str,
    service_url: &str,
) -> anyhow::Result<DidWebvhResult> {
    let address = if address.starts_with("http://") || address.starts_with("https://") {
        address.to_string()
    } else {
        format!("https://{address}")
    };

    // ── Mediator keys ──────────────────────────────────────────────
    // Ed25519 signing (maps to the template's `#key-1`), X25519 derived
    // from the same seed for key agreement (maps to `#key-2`).
    let mut signing = Secret::generate_ed25519(None, None);
    let mut key_agreement = signing
        .to_x25519()
        .map_err(|e| anyhow::anyhow!("Failed to derive X25519 from Ed25519: {e}"))?;
    let signing_mb = signing
        .get_public_keymultibase()
        .map_err(|e| anyhow::anyhow!("Failed to get Ed25519 public key: {e}"))?;
    let ka_mb = key_agreement
        .get_public_keymultibase()
        .map_err(|e| anyhow::anyhow!("Failed to get X25519 public key: {e}"))?;

    // ── Render template ─────────────────────────────────────────────
    let template = load_embedded("didcomm-mediator")
        .map_err(|e| anyhow::anyhow!("Failed to load mediator template: {e}"))?;
    let mut vars = TemplateVars::new();
    // Service endpoints land on the operator's full URL (host + api prefix).
    // The DID identifier itself comes from `address` via `CreateDIDConfig`
    // below, so the two are correctly decoupled — clients resolving the
    // DID look up `/.well-known/did.jsonl` then dial the service URLs
    // they find inside.
    vars.insert_string("URL", service_url);
    vars.insert_string("SIGNING_KEY_MB", &signing_mb);
    vars.insert_string("KA_KEY_MB", &ka_mb);
    // `{DID}` is a sentinel — we declare it as "provided" so the renderer
    // doesn't flag it as unresolved; `didwebvh-rs` substitutes the actual
    // DID string after SCID computation.
    vars.insert_string("DID", "{DID}");
    let did_document = template
        .render(&vars)
        .map_err(|e| anyhow::anyhow!("Failed to render mediator template: {e}"))?;

    // ── Authorization + pre-rotation ───────────────────────────────
    let mut auth_key = Secret::generate_ed25519(None, None);
    let auth_pubkey = auth_key
        .get_public_keymultibase()
        .map_err(|e| anyhow::anyhow!("Failed to get authorization public key: {e}"))?;
    auth_key.id = format!("did:key:{auth_pubkey}#{auth_pubkey}");

    let next_auth_key = Secret::generate_ed25519(None, None);
    let next_auth_pubkey = next_auth_key
        .get_public_keymultibase()
        .map_err(|e| anyhow::anyhow!("Failed to get next authorization public key: {e}"))?;

    let parameters = Parameters {
        update_keys: Some(Arc::new(vec![auth_pubkey.into()])),
        portable: Some(true),
        next_key_hashes: Some(Arc::new(vec![next_auth_pubkey.into()])),
        ..Default::default()
    };

    let config = CreateDIDConfig::builder()
        .address(address)
        .authorization_key(auth_key)
        .did_document(did_document)
        .parameters(parameters)
        .build()
        .map_err(|e| anyhow::anyhow!("Failed to build webvh config: {e}"))?;

    let result = create_did(config)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create did:webvh: {e}"))?;

    let final_did = result.did().to_string();

    // Align runtime secret IDs with the resolved DID. `#key-1` is the
    // signing slot, `#key-2` is the key-agreement slot — matches the
    // built-in template.
    signing.id = format!("{final_did}#key-1");
    key_agreement.id = format!("{final_did}#key-2");

    let did_doc = serde_json::to_string(result.log_entry())?;

    Ok(DidWebvhResult {
        did: final_did,
        secrets: vec![signing, key_agreement],
        did_doc,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    #[tokio::test]
    async fn webvh_matches_canonical_mediator_template() {
        let result = generate_did_webvh(
            "https://mediator.example.com",
            "https://mediator.example.com/mediator/v1",
        )
        .await
        .unwrap();
        // Two runtime secrets: signing + key agreement.
        assert_eq!(result.secrets.len(), 2);

        let entry: Value = serde_json::from_str(&result.did_doc).unwrap();
        let doc = &entry["state"];

        // Canonical shape from the `didcomm-mediator` template:
        // - 2 verification methods (`#key-1`, `#key-2`), both `Multikey`
        // - assertionMethod + authentication -> `#key-1`
        // - keyAgreement -> `#key-2`
        // - DIDCommMessaging service (`#didcomm`) with a single serviceEndpoint
        //   object carrying `uri`, `accept`, `routingKeys`
        // - Authentication service (`#auth`) pointing at `{URL}/authenticate`
        let vms = doc["verificationMethod"].as_array().unwrap();
        assert_eq!(vms.len(), 2);
        assert!(vms.iter().all(|vm| vm["type"] == "Multikey"));
        assert!(vms[0]["id"].as_str().unwrap().ends_with("#key-1"));
        assert!(vms[1]["id"].as_str().unwrap().ends_with("#key-2"));

        assert_eq!(doc["assertionMethod"].as_array().unwrap().len(), 1);
        assert_eq!(doc["authentication"].as_array().unwrap().len(), 1);
        assert_eq!(doc["keyAgreement"].as_array().unwrap().len(), 1);

        let services = doc["service"].as_array().unwrap();
        assert_eq!(services.len(), 2);
        assert_eq!(services[0]["type"], "DIDCommMessaging");
        assert!(services[0]["id"].as_str().unwrap().ends_with("#didcomm"));
        let endpoint = &services[0]["serviceEndpoint"];
        assert_eq!(
            endpoint["uri"].as_str().unwrap(),
            "https://mediator.example.com/mediator/v1"
        );
        let accept = endpoint["accept"].as_array().unwrap();
        assert_eq!(accept.len(), 1);
        assert_eq!(accept[0], "didcomm/v2");

        assert_eq!(services[1]["type"], "Authentication");
        assert!(services[1]["id"].as_str().unwrap().ends_with("#auth"));
        assert_eq!(
            services[1]["serviceEndpoint"].as_str().unwrap(),
            "https://mediator.example.com/mediator/v1/authenticate"
        );
    }

    #[tokio::test]
    async fn webvh_key_ids_match_final_did() {
        let result = generate_did_webvh("mediator.example.com", "https://mediator.example.com")
            .await
            .unwrap();
        for secret in &result.secrets {
            assert!(secret.id.starts_with(&result.did));
        }
        assert!(result.secrets[0].id.ends_with("#key-1"));
        assert!(result.secrets[1].id.ends_with("#key-2"));
    }
}

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
use serde_json::json;
use vta_sdk::did_templates::{TemplateVars, load_embedded};

use crate::cli::KeySuite;

pub struct DidWebvhResult {
    /// The final DID string (resolved from the WebVH log entry).
    pub did: String,
    /// Private keys the mediator needs at runtime — Ed25519 signing, X25519
    /// key-agreement, plus any opt-in extra-suite keys (e.g. P-256 signing +
    /// P-256 key-agreement when `p256` is requested).
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
    key_suites: &[KeySuite],
    tsp_enabled: bool,
) -> anyhow::Result<DidWebvhResult> {
    let address = if address.starts_with("http://") || address.starts_with("https://") {
        address.to_string()
    } else {
        format!("https://{address}")
    };

    // ── Mediator keys ──────────────────────────────────────────────
    // Ed25519 signing (maps to the template's `#key-0`), X25519 derived
    // from the same seed for key agreement (maps to `#key-1`).
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

    // ── Opt-in extra key suites ────────────────────────────────────
    // Each requested suite contributes a signing key (`#key-2`) + a
    // key-agreement key (`#key-3`) advertised through the template's
    // optional P-256 slots. Only P-256 is supported today. When no suite
    // is requested the slots stay pruned, so the default document is
    // byte-identical to before.
    let include_p256 = key_suites.contains(&KeySuite::P256);
    let mut p256_signing = if include_p256 {
        Some(
            Secret::generate_p256(None, None)
                .map_err(|e| anyhow::anyhow!("Failed to generate P-256 signing key: {e}"))?,
        )
    } else {
        None
    };
    let mut p256_key_agreement = if include_p256 {
        Some(
            Secret::generate_p256(None, None)
                .map_err(|e| anyhow::anyhow!("Failed to generate P-256 key-agreement key: {e}"))?,
        )
    } else {
        None
    };

    // secp256k1 suite: a signing key (`#key-4`) + a key-agreement key
    // (`#key-5`), injected into the rendered document after templating (the
    // embedded template has no secp256k1 slots, so we append them directly,
    // mirroring the TSP-service injection). Numbered above the P-256 slots so
    // the two suites never collide.
    let include_secp256k1 = key_suites.contains(&KeySuite::Secp256k1);
    let mut secp256k1_signing = if include_secp256k1 {
        Some(
            Secret::generate_secp256k1(None, None)
                .map_err(|e| anyhow::anyhow!("Failed to generate secp256k1 signing key: {e}"))?,
        )
    } else {
        None
    };
    let mut secp256k1_key_agreement =
        if include_secp256k1 {
            Some(Secret::generate_secp256k1(None, None).map_err(|e| {
                anyhow::anyhow!("Failed to generate secp256k1 key-agreement key: {e}")
            })?)
        } else {
            None
        };

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
    // Opt-in P-256 verification methods. The supplied objects keep the
    // `{DID}` sentinel — didwebvh-rs resolves it across the whole document
    // after SCID computation, including these var-injected methods (they
    // are not recursively re-substituted by the template renderer). When no
    // P-256 suite is requested these vars stay unset and the renderer prunes
    // the corresponding null slots.
    if let (Some(p256_sign), Some(p256_ka)) = (p256_signing.as_ref(), p256_key_agreement.as_ref()) {
        let p256_sign_mb = p256_sign
            .get_public_keymultibase()
            .map_err(|e| anyhow::anyhow!("Failed to get P-256 signing public key: {e}"))?;
        let p256_ka_mb = p256_ka
            .get_public_keymultibase()
            .map_err(|e| anyhow::anyhow!("Failed to get P-256 key-agreement public key: {e}"))?;
        vars.insert(
            "VM_P256_SIGNING",
            json!({
                "id": "{DID}#key-2",
                "type": "Multikey",
                "controller": "{DID}",
                "publicKeyMultibase": p256_sign_mb,
            }),
        );
        vars.insert(
            "VM_P256_KA",
            json!({
                "id": "{DID}#key-3",
                "type": "Multikey",
                "controller": "{DID}",
                "publicKeyMultibase": p256_ka_mb,
            }),
        );
        vars.insert_string("AUTH_P256", "{DID}#key-2");
        vars.insert_string("ASSERTION_P256", "{DID}#key-2");
        vars.insert_string("KEYAGREEMENT_P256", "{DID}#key-3");
    }
    // `{DID}` is a sentinel — we declare it as "provided" so the renderer
    // doesn't flag it as unresolved; `didwebvh-rs` substitutes the actual
    // DID string after SCID computation.
    vars.insert_string("DID", "{DID}");
    let mut did_document = template
        .render(&vars)
        .map_err(|e| anyhow::anyhow!("Failed to render mediator template: {e}"))?;

    // ── TSP service, matched to the operator's choice ───────────────
    // did:webvh binds the document to the DID (SCID), so the mediator runtime
    // cannot mutate it the way it does for did:web — the `TSPTransport` service
    // must be settled here, before `create_did` computes the SCID.
    //
    // The shipped `didcomm-mediator` template advertises a `#tsp` service
    // *unconditionally*, so we normalise both ways: ensure it's present when
    // TSP is enabled (a no-op with the current template; a safety net for a
    // forked template that lacks it), and strip it when TSP is off so a
    // DIDComm-only mediator doesn't mislead peers into routing TSP it can't
    // handle. The `{DID}#tsp` id keeps the template's sentinel; `didwebvh-rs`
    // resolves it across the whole document after SCID computation.
    if tsp_enabled {
        augment_webvh_doc_with_tsp_service(&mut did_document)?;
    } else {
        strip_tsp_service(&mut did_document);
    }

    // Inject secp256k1 verification methods (post-render; see key generation
    // above). Uses `{DID}` sentinels so `create_did` resolves them alongside
    // the templated methods after SCID computation.
    if let (Some(k1_sign), Some(k1_ka)) =
        (secp256k1_signing.as_ref(), secp256k1_key_agreement.as_ref())
    {
        let k1_sign_mb = k1_sign
            .get_public_keymultibase()
            .map_err(|e| anyhow::anyhow!("Failed to get secp256k1 signing public key: {e}"))?;
        let k1_ka_mb = k1_ka.get_public_keymultibase().map_err(|e| {
            anyhow::anyhow!("Failed to get secp256k1 key-agreement public key: {e}")
        })?;
        inject_secp256k1_vms(&mut did_document, &k1_sign_mb, &k1_ka_mb)?;
    }

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

    // Align runtime secret IDs with the resolved DID. `#key-0` is the
    // signing slot, `#key-1` is the key-agreement slot — matches the
    // built-in template.
    signing.id = format!("{final_did}#key-0");
    key_agreement.id = format!("{final_did}#key-1");

    // Opt-in P-256 keys occupy `#key-2` (signing / assertion) and `#key-3`
    // (key agreement), matching the slots advertised in the rendered DID
    // document above.
    let mut secrets = vec![signing, key_agreement];
    if let Some(mut p256_sign) = p256_signing.take() {
        p256_sign.id = format!("{final_did}#key-2");
        secrets.push(p256_sign);
    }
    if let Some(mut p256_ka) = p256_key_agreement.take() {
        p256_ka.id = format!("{final_did}#key-3");
        secrets.push(p256_ka);
    }

    // secp256k1 runtime secrets occupy `#key-4` (signing / assertion) and
    // `#key-5` (key agreement), matching the injected verification methods.
    if let Some(mut k1_sign) = secp256k1_signing.take() {
        k1_sign.id = format!("{final_did}#key-4");
        secrets.push(k1_sign);
    }
    if let Some(mut k1_ka) = secp256k1_key_agreement.take() {
        k1_ka.id = format!("{final_did}#key-5");
        secrets.push(k1_ka);
    }

    let did_doc = serde_json::to_string(result.log_entry())?;

    Ok(DidWebvhResult {
        did: final_did,
        secrets,
        did_doc,
    })
}

/// Inject secp256k1 signing (`#key-4`) and key-agreement (`#key-5`)
/// verification methods into a rendered (pre-SCID) mediator DID document.
///
/// The embedded template has no secp256k1 slots, so — as with the TSP service
/// — the methods are appended directly. Ids keep the `{DID}` sentinel so
/// `create_did` resolves them across the document after SCID computation. The
/// signing key joins `authentication`/`assertionMethod`; the key-agreement key
/// joins `keyAgreement`.
fn inject_secp256k1_vms(
    did_document: &mut serde_json::Value,
    signing_mb: &str,
    key_agreement_mb: &str,
) -> anyhow::Result<()> {
    use serde_json::{Value, json};

    let obj = did_document
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("Rendered DID document is not a JSON object"))?;

    let vms = obj
        .get_mut("verificationMethod")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| {
            anyhow::anyhow!("Rendered DID document has no `verificationMethod` array")
        })?;
    vms.push(json!({
        "id": "{DID}#key-4",
        "type": "Multikey",
        "controller": "{DID}",
        "publicKeyMultibase": signing_mb,
    }));
    vms.push(json!({
        "id": "{DID}#key-5",
        "type": "Multikey",
        "controller": "{DID}",
        "publicKeyMultibase": key_agreement_mb,
    }));

    for (field, kid) in [
        ("authentication", "{DID}#key-4"),
        ("assertionMethod", "{DID}#key-4"),
        ("keyAgreement", "{DID}#key-5"),
    ] {
        let arr = obj
            .get_mut(field)
            .and_then(Value::as_array_mut)
            .ok_or_else(|| anyhow::anyhow!("Rendered DID document has no `{field}` array"))?;
        arr.push(Value::String(kid.to_string()));
    }

    Ok(())
}

/// Inject a `TSPTransport` service into a rendered (pre-SCID) mediator DID
/// document so did:webvh peers can discover the mediator's TSP endpoint.
///
/// TSP and DIDComm share the mediator's `/inbound`, so the TSP endpoint
/// mirrors the first `DIDCommMessaging` service endpoint URI — matching the
/// runtime's did:web behaviour (`augment_did_web_doc_with_tsp_service`). The
/// service id keeps the `{DID}` sentinel (`{DID}#tsp`) so `create_did`
/// resolves it alongside every other self-reference once the SCID is known.
///
/// Idempotent: if a `TSPTransport` service is already present the document is
/// left unchanged. Errors only if the document has no `service` array or no
/// DIDComm endpoint to mirror (a mediator template without one is a bug).
fn augment_webvh_doc_with_tsp_service(did_document: &mut serde_json::Value) -> anyhow::Result<()> {
    use serde_json::Value;

    let service_type_is = |svc: &Value, want: &str| {
        svc.get("type").is_some_and(|t| match t {
            Value::String(s) => s == want,
            Value::Array(arr) => arr.iter().any(|v| v.as_str() == Some(want)),
            _ => false,
        })
    };

    let services = did_document
        .get_mut("service")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| anyhow::anyhow!("Rendered DID document has no `service` array"))?;

    // Already advertised (e.g. a forked template) — leave it be.
    if services
        .iter()
        .any(|svc| service_type_is(svc, "TSPTransport"))
    {
        return Ok(());
    }

    // Mirror the first DIDCommMessaging endpoint URI. The template renders
    // `serviceEndpoint` as an array of `{uri, accept, routingKeys}` objects,
    // but tolerate the object / bare-string shapes a forked template might use.
    let uri = services
        .iter()
        .find(|svc| service_type_is(svc, "DIDCommMessaging"))
        .and_then(|svc| svc.get("serviceEndpoint"))
        .and_then(|ep| match ep {
            Value::Array(arr) => arr.first().and_then(|e| e.get("uri")),
            Value::Object(_) => ep.get("uri"),
            _ => Some(ep),
        })
        .and_then(Value::as_str)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Rendered DID document has no DIDCommMessaging endpoint to mirror for TSP"
            )
        })?
        .to_string();

    services.push(serde_json::json!({
        "id": "{DID}#tsp",
        "type": ["TSPTransport"],
        "serviceEndpoint": uri,
    }));

    Ok(())
}

/// Remove any `TSPTransport` service from a rendered (pre-SCID) DID document.
///
/// The shipped `didcomm-mediator` template advertises a `#tsp` service
/// unconditionally; when the operator did **not** enable TSP we drop it so a
/// DIDComm-only mediator doesn't advertise a transport it can't serve. A no-op
/// when no such service is present (e.g. a forked template without one).
fn strip_tsp_service(did_document: &mut serde_json::Value) {
    use serde_json::Value;

    if let Some(services) = did_document
        .get_mut("service")
        .and_then(Value::as_array_mut)
    {
        services.retain(|svc| {
            !svc.get("type").is_some_and(|t| match t {
                Value::String(s) => s == "TSPTransport",
                Value::Array(arr) => arr.iter().any(|v| v.as_str() == Some("TSPTransport")),
                _ => false,
            })
        });
    }
}

/// Convert a did:webvh log entry into the equivalent did:web DID document.
///
/// Re-exported from `affinidi-messaging-mediator-common` so the wizard's
/// `did-web.json` operator artefact and the mediator runtime's
/// `/.well-known/did.json` body share one tested rewrite implementation.
/// Returns `(did:web identifier, pretty-printed did.json document)`.
///
/// The returned document is an operator artefact for hosting the DID
/// under did:web (e.g. at a web server's `/.well-known/did.json`). It is
/// **not** consumed by the mediator runtime, which serves its own DID
/// document from the webvh log (`did_web_self_hosted` → `did.jsonl`).
pub use affinidi_messaging_mediator_common::did_web::webvh_log_to_did_web;

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    #[tokio::test]
    async fn webvh_matches_canonical_mediator_template() {
        let result = generate_did_webvh(
            "https://mediator.example.com",
            "https://mediator.example.com/mediator/v1",
            &[],
            false,
        )
        .await
        .unwrap();
        // Two runtime secrets: signing + key agreement.
        assert_eq!(result.secrets.len(), 2);

        let entry: Value = serde_json::from_str(&result.did_doc).unwrap();
        let doc = &entry["state"];

        // Canonical shape from the `didcomm-mediator` template:
        // - 2 verification methods (`#key-0`, `#key-1`), both `Multikey`
        // - assertionMethod + authentication -> `#key-0`
        // - keyAgreement -> `#key-1`
        // - DIDCommMessaging service (`#service`) with two serviceEndpoint
        //   entries carrying `uri`, `accept`, `routingKeys` for HTTP + WSS
        // - Authentication service (`#auth`) pointing at `{URL}/authenticate`
        let vms = doc["verificationMethod"].as_array().unwrap();
        assert_eq!(vms.len(), 2);
        assert!(vms.iter().all(|vm| vm["type"] == "Multikey"));
        assert!(vms[0]["id"].as_str().unwrap().ends_with("#key-0"));
        assert!(vms[1]["id"].as_str().unwrap().ends_with("#key-1"));

        assert_eq!(doc["assertionMethod"].as_array().unwrap().len(), 1);
        assert_eq!(doc["authentication"].as_array().unwrap().len(), 1);
        assert_eq!(doc["keyAgreement"].as_array().unwrap().len(), 1);

        // Locate services by `type` rather than position — the canonical
        // preference order is not this test's concern.
        let services = doc["service"].as_array().unwrap();
        let service_type_is =
            |svc: &Value, want: &str| svc["type"] == json!([want]) || svc["type"] == json!(want);
        // TSP was NOT enabled, so the template's unconditional `#tsp` service
        // must be stripped — a DIDComm-only mediator must not advertise TSP.
        assert!(
            !services
                .iter()
                .any(|svc| service_type_is(svc, "TSPTransport")),
            "TSPTransport must be stripped when TSP is disabled"
        );
        let didcomm = services
            .iter()
            .find(|svc| service_type_is(svc, "DIDCommMessaging"))
            .expect("DIDCommMessaging service present");
        assert!(didcomm["id"].as_str().unwrap().ends_with("#service"));
        let endpoints = didcomm["serviceEndpoint"].as_array().unwrap();
        assert_eq!(endpoints.len(), 2);
        assert_eq!(
            endpoints[0]["uri"].as_str().unwrap(),
            "https://mediator.example.com/mediator/v1"
        );
        // WS_URL is auto-derived by the template renderer: scheme swap
        // plus `/ws` suffix on the path.
        assert_eq!(
            endpoints[1]["uri"].as_str().unwrap(),
            "wss://mediator.example.com/mediator/v1/ws"
        );
        let accept = endpoints[0]["accept"].as_array().unwrap();
        assert_eq!(accept.len(), 1);
        assert_eq!(accept[0], "didcomm/v2");

        let auth = services
            .iter()
            .find(|svc| service_type_is(svc, "Authentication"))
            .expect("Authentication service present");
        assert!(auth["id"].as_str().unwrap().ends_with("#auth"));
        assert_eq!(
            auth["serviceEndpoint"].as_str().unwrap(),
            "https://mediator.example.com/mediator/v1/authenticate"
        );
    }

    #[tokio::test]
    async fn webvh_p256_suite_adds_signing_and_key_agreement_keys() {
        let result = generate_did_webvh(
            "https://mediator.example.com",
            "https://mediator.example.com/mediator/v1",
            &[KeySuite::P256],
            false,
        )
        .await
        .unwrap();

        // Four runtime secrets now: Ed25519 + X25519 + P-256 signing + P-256 KA.
        assert_eq!(result.secrets.len(), 4);
        assert!(result.secrets[0].id.ends_with("#key-0"));
        assert!(result.secrets[1].id.ends_with("#key-1"));
        assert!(result.secrets[2].id.ends_with("#key-2"));
        assert!(result.secrets[3].id.ends_with("#key-3"));
        use affinidi_secrets_resolver::secrets::KeyType;
        assert!(matches!(result.secrets[2].get_key_type(), KeyType::P256));
        assert!(matches!(result.secrets[3].get_key_type(), KeyType::P256));

        let entry: Value = serde_json::from_str(&result.did_doc).unwrap();
        let doc = &entry["state"];

        // Four verification methods; the P-256 pair are `#key-2` / `#key-3`,
        // both `Multikey`, and the relationship arrays grew to two entries.
        let vms = doc["verificationMethod"].as_array().unwrap();
        assert_eq!(vms.len(), 4);
        assert!(vms.iter().all(|vm| vm["type"] == "Multikey"));
        assert!(vms[2]["id"].as_str().unwrap().ends_with("#key-2"));
        assert!(vms[3]["id"].as_str().unwrap().ends_with("#key-3"));
        // P-256 Multikey multibase uses the `zDna…` (0x1200) prefix.
        assert!(
            vms[2]["publicKeyMultibase"]
                .as_str()
                .unwrap()
                .starts_with("zDn")
        );
        assert!(
            vms[3]["publicKeyMultibase"]
                .as_str()
                .unwrap()
                .starts_with("zDn")
        );

        let auth = doc["authentication"].as_array().unwrap();
        assert_eq!(auth.len(), 2);
        assert!(auth[1].as_str().unwrap().ends_with("#key-2"));
        let assertion = doc["assertionMethod"].as_array().unwrap();
        assert_eq!(assertion.len(), 2);
        assert!(assertion[1].as_str().unwrap().ends_with("#key-2"));
        let ka = doc["keyAgreement"].as_array().unwrap();
        assert_eq!(ka.len(), 2);
        assert!(ka[1].as_str().unwrap().ends_with("#key-3"));

        // The webvh SCID sentinel must be fully resolved — no `{DID}` token
        // survives in the var-injected P-256 methods.
        assert!(!result.did_doc.contains("{DID}"));
    }

    #[tokio::test]
    async fn webvh_secp256k1_suite_adds_signing_and_key_agreement_keys() {
        let result = generate_did_webvh(
            "https://mediator.example.com",
            "https://mediator.example.com/mediator/v1",
            &[KeySuite::P256, KeySuite::Secp256k1],
            false,
        )
        .await
        .unwrap();

        use affinidi_secrets_resolver::secrets::KeyType;
        // Six runtime secrets: Ed25519 + X25519 + P-256(sign,KA) + secp256k1(sign,KA).
        assert_eq!(result.secrets.len(), 6);
        assert!(result.secrets[4].id.ends_with("#key-4"));
        assert!(result.secrets[5].id.ends_with("#key-5"));
        assert!(matches!(
            result.secrets[4].get_key_type(),
            KeyType::Secp256k1
        ));
        assert!(matches!(
            result.secrets[5].get_key_type(),
            KeyType::Secp256k1
        ));

        let entry: Value = serde_json::from_str(&result.did_doc).unwrap();
        let doc = &entry["state"];

        // Six verification methods; the secp256k1 pair are `#key-4` / `#key-5`.
        let vms = doc["verificationMethod"].as_array().unwrap();
        assert_eq!(vms.len(), 6);
        assert!(vms[4]["id"].as_str().unwrap().ends_with("#key-4"));
        assert!(vms[5]["id"].as_str().unwrap().ends_with("#key-5"));
        assert_eq!(vms[5]["type"], "Multikey");
        // secp256k1 multikeys use the `zQ3s` multibase prefix.
        assert!(
            vms[5]["publicKeyMultibase"]
                .as_str()
                .unwrap()
                .starts_with("zQ3s")
        );

        // The secp256k1 keys join the relationship arrays.
        let auth = doc["authentication"].as_array().unwrap();
        assert!(auth.iter().any(|a| a.as_str().unwrap().ends_with("#key-4")));
        let assertion = doc["assertionMethod"].as_array().unwrap();
        assert!(
            assertion
                .iter()
                .any(|a| a.as_str().unwrap().ends_with("#key-4"))
        );
        let ka = doc["keyAgreement"].as_array().unwrap();
        assert!(ka.iter().any(|k| k.as_str().unwrap().ends_with("#key-5")));

        // SCID sentinel fully resolved in the injected methods too.
        assert!(!result.did_doc.contains("{DID}"));
    }

    #[tokio::test]
    async fn webvh_key_ids_match_final_did() {
        let result = generate_did_webvh(
            "mediator.example.com",
            "https://mediator.example.com",
            &[],
            false,
        )
        .await
        .unwrap();
        for secret in &result.secrets {
            assert!(secret.id.starts_with(&result.did));
        }
        assert!(result.secrets[0].id.ends_with("#key-0"));
        assert!(result.secrets[1].id.ends_with("#key-1"));
    }

    #[tokio::test]
    async fn did_web_export_rewrites_every_self_reference() {
        let result = generate_did_webvh(
            "https://mediator.example.com",
            "https://mediator.example.com/mediator/v1",
            &[],
            false,
        )
        .await
        .unwrap();

        let (web_did, doc_str) = webvh_log_to_did_web(&result.did_doc, &result.did).unwrap();

        // The webvh DID is `did:webvh:{scid}:mediator.example.com`, so the
        // did:web form drops the scid segment.
        assert_eq!(web_did, "did:web:mediator.example.com");

        // No trace of the webvh identifier (or the bare `did:webvh:`
        // method prefix) should survive anywhere in the document.
        assert!(!doc_str.contains("did:webvh:"));
        assert!(!doc_str.contains(&result.did));

        let doc: Value = serde_json::from_str(&doc_str).unwrap();
        assert_eq!(doc["id"], web_did);
        // Verification-method + service self-references were all rewritten.
        for vm in doc["verificationMethod"].as_array().unwrap() {
            assert!(vm["id"].as_str().unwrap().starts_with("did:web:"));
        }
        for svc in doc["service"].as_array().unwrap() {
            assert!(svc["id"].as_str().unwrap().starts_with("did:web:"));
        }
    }

    #[tokio::test]
    async fn did_web_export_errors_on_log_without_state() {
        let err = webvh_log_to_did_web(r#"{"versionId":"1-abc"}"#, "did:webvh:QmScId:example.com")
            .unwrap_err();
        assert!(err.to_string().contains("state"));
    }

    #[tokio::test]
    async fn webvh_tsp_enabled_bakes_in_tsptransport_service() {
        let result = generate_did_webvh(
            "https://mediator.example.com",
            "https://mediator.example.com/mediator/v1",
            &[],
            true,
        )
        .await
        .unwrap();

        // Keys are unchanged by the TSP service — it reuses the mediator's
        // existing Ed25519 signing + X25519 key-agreement keys.
        assert_eq!(result.secrets.len(), 2);

        let entry: Value = serde_json::from_str(&result.did_doc).unwrap();
        let doc = &entry["state"];
        let services = doc["service"].as_array().unwrap();

        let service_type_is =
            |svc: &Value, want: &str| svc["type"] == json!([want]) || svc["type"] == json!(want);
        let tsp = services
            .iter()
            .find(|svc| service_type_is(svc, "TSPTransport"))
            .expect("TSPTransport service baked in");

        // The `{DID}#tsp` sentinel was resolved to the final DID by create_did.
        let tsp_id = tsp["id"].as_str().unwrap();
        assert!(tsp_id.ends_with("#tsp"));
        assert!(tsp_id.starts_with(&result.did));
        assert!(!result.did_doc.contains("{DID}"));

        // Endpoint mirrors the DIDComm HTTP endpoint (shared `/inbound`).
        assert_eq!(
            tsp["serviceEndpoint"].as_str().unwrap(),
            "https://mediator.example.com/mediator/v1"
        );

        // DIDComm service is untouched.
        assert!(
            services
                .iter()
                .any(|svc| service_type_is(svc, "DIDCommMessaging"))
        );
    }

    #[test]
    fn augment_is_idempotent_when_tsp_already_present() {
        // A document that already advertises TSP is left unchanged.
        let mut doc: Value = serde_json::from_str(
            r#"{"service":[{"id":"{DID}#tsp","type":["TSPTransport"],"serviceEndpoint":"https://x/"}]}"#,
        )
        .unwrap();
        let before = doc.clone();
        augment_webvh_doc_with_tsp_service(&mut doc).unwrap();
        assert_eq!(doc, before);
    }

    #[test]
    fn augment_errors_without_a_didcomm_endpoint_to_mirror() {
        let mut doc: Value = serde_json::from_str(
            r#"{"service":[{"id":"{DID}#auth","type":["Authentication"],"serviceEndpoint":"https://x/authenticate"}]}"#,
        )
        .unwrap();
        let err = augment_webvh_doc_with_tsp_service(&mut doc).unwrap_err();
        assert!(err.to_string().contains("DIDCommMessaging"));
    }

    #[test]
    fn strip_removes_tsp_but_keeps_other_services() {
        let mut doc: Value = serde_json::from_str(
            r#"{"service":[
                {"id":"{DID}#service","type":["DIDCommMessaging"],"serviceEndpoint":[{"uri":"https://x/"}]},
                {"id":"{DID}#tsp","type":["TSPTransport"],"serviceEndpoint":"https://x/"},
                {"id":"{DID}#auth","type":["Authentication"],"serviceEndpoint":"https://x/authenticate"}
            ]}"#,
        )
        .unwrap();
        strip_tsp_service(&mut doc);
        let services = doc["service"].as_array().unwrap();
        assert_eq!(services.len(), 2);
        assert!(
            !services
                .iter()
                .any(|s| s["type"] == json!(["TSPTransport"]))
        );
        assert!(
            services
                .iter()
                .any(|s| s["type"] == json!(["DIDCommMessaging"]))
        );
        assert!(
            services
                .iter()
                .any(|s| s["type"] == json!(["Authentication"]))
        );
    }

    #[test]
    fn strip_is_a_noop_without_a_tsp_service() {
        let src = r#"{"service":[{"id":"{DID}#service","type":["DIDCommMessaging"],"serviceEndpoint":[{"uri":"https://x/"}]}]}"#;
        let mut doc: Value = serde_json::from_str(src).unwrap();
        let before = doc.clone();
        strip_tsp_service(&mut doc);
        assert_eq!(doc, before);
    }
}

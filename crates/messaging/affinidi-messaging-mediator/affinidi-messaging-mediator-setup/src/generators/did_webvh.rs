use std::sync::Arc;

use affinidi_secrets_resolver::secrets::Secret;
use didwebvh_rs::{
    DIDWebVHState, log_entry::LogEntryMethods, parameters::Parameters, url::WebVHURL,
};
use serde_json::{Value, json};
use url::Url;

/// Keys generated for a did:webvh DID.
struct Keys {
    signing_ed25519: Secret,
    signing_p256: Secret,
    key_agreement_ed25519: Secret,
    key_agreement_p256: Secret,
    key_agreement_secp256k1: Secret,
}

fn create_keys() -> anyhow::Result<Keys> {
    let signing_ed25519 = Secret::generate_ed25519(None, None);
    let signing_p256 = Secret::generate_p256(None, None)
        .map_err(|e| anyhow::anyhow!("Failed to generate P-256 key: {e}"))?;
    let key_agreement_ed25519 = signing_ed25519
        .to_x25519()
        .map_err(|e| anyhow::anyhow!("Failed to convert Ed25519 to X25519: {e}"))?;
    let key_agreement_p256 = Secret::generate_p256(None, None)
        .map_err(|e| anyhow::anyhow!("Failed to generate P-256 key agreement key: {e}"))?;
    let key_agreement_secp256k1 = Secret::generate_secp256k1(None, None)
        .map_err(|e| anyhow::anyhow!("Failed to generate secp256k1 key: {e}"))?;

    Ok(Keys {
        signing_ed25519,
        signing_p256,
        key_agreement_ed25519,
        key_agreement_p256,
        key_agreement_secp256k1,
    })
}

fn create_service_endpoints(did: &str, url: &str, secure: bool) -> anyhow::Result<Vec<Value>> {
    let http_scheme = if secure { "https" } else { "http" };
    let ws_scheme = if secure { "wss" } else { "ws" };

    let base_domain = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .or_else(|| url.strip_prefix("wss://"))
        .or_else(|| url.strip_prefix("ws://"))
        .unwrap_or(url)
        .replace("%3A", ":");

    let base_http_url = format!("{http_scheme}://{base_domain}");
    let base_ws_url = format!("{ws_scheme}://{base_domain}/ws");
    let auth_url = format!("{http_scheme}://{base_domain}/authenticate");

    Ok(vec![
        json!({
            "id": format!("{did}#service"),
            "type": "DIDCommMessaging",
            "serviceEndpoint": [
                { "uri": base_http_url, "accept": ["didcomm/v2"] },
                { "uri": base_ws_url, "accept": ["didcomm/v2"] }
            ]
        }),
        json!({
            "id": format!("{did}#auth"),
            "type": "Authentication",
            "serviceEndpoint": auth_url
        }),
    ])
}

/// Result of did:webvh generation.
pub struct DidWebvhResult {
    /// The DID string
    pub did: String,
    /// All secrets for the DID
    pub secrets: Vec<Secret>,
    /// The DID document log entry (JSONL format for hosting)
    pub did_doc: String,
}

/// Generate a did:webvh DID with full key set and service endpoints.
///
/// `host` is the domain (e.g., "example.com" or "localhost:7037/mediator/v1")
/// `secure` controls whether https/wss or http/ws schemes are used.
pub async fn generate_did_webvh(host: &str, secure: bool) -> anyhow::Result<DidWebvhResult> {
    let full_url = if host.starts_with("http://") || host.starts_with("https://") {
        host.to_string()
    } else {
        format!("https://{host}")
    };
    let parsed_url = Url::parse(&full_url)?;
    let webvh_url =
        WebVHURL::parse_url(&parsed_url).map_err(|e| anyhow::anyhow!("Invalid webvh URL: {e}"))?;
    let did_id = webvh_url.to_string();

    let Keys {
        mut signing_ed25519,
        mut signing_p256,
        mut key_agreement_ed25519,
        mut key_agreement_p256,
        mut key_agreement_secp256k1,
    } = create_keys()?;

    let pub_key_0 = signing_ed25519
        .get_public_keymultibase()
        .map_err(|e| anyhow::anyhow!("Failed to get public key: {e}"))?;
    let pub_key_1 = signing_p256
        .get_public_keymultibase()
        .map_err(|e| anyhow::anyhow!("Failed to get public key: {e}"))?;
    let pub_key_2 = key_agreement_ed25519
        .get_public_keymultibase()
        .map_err(|e| anyhow::anyhow!("Failed to get public key: {e}"))?;
    let pub_key_3 = key_agreement_p256
        .get_public_keymultibase()
        .map_err(|e| anyhow::anyhow!("Failed to get public key: {e}"))?;
    let pub_key_4 = key_agreement_secp256k1
        .get_public_keymultibase()
        .map_err(|e| anyhow::anyhow!("Failed to get public key: {e}"))?;

    let mut did_document = json!({
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://www.w3.org/ns/cid/v1"
        ],
        "id": &did_id,
        "verificationMethod": [
            { "id": format!("{did_id}#key-0"), "type": "Multikey", "controller": &did_id, "publicKeyMultibase": pub_key_0 },
            { "id": format!("{did_id}#key-1"), "type": "Multikey", "controller": &did_id, "publicKeyMultibase": pub_key_1 },
            { "id": format!("{did_id}#key-2"), "type": "Multikey", "controller": &did_id, "publicKeyMultibase": pub_key_2 },
            { "id": format!("{did_id}#key-3"), "type": "Multikey", "controller": &did_id, "publicKeyMultibase": pub_key_3 },
            { "id": format!("{did_id}#key-4"), "type": "Multikey", "controller": &did_id, "publicKeyMultibase": pub_key_4 }
        ],
        "authentication":  [format!("{did_id}#key-0"), format!("{did_id}#key-1")],
        "assertionMethod": [format!("{did_id}#key-0"), format!("{did_id}#key-1")],
        "keyAgreement":    [format!("{did_id}#key-2"), format!("{did_id}#key-3"), format!("{did_id}#key-4")],
    });

    did_document["service"] =
        serde_json::to_value(create_service_endpoints(&did_id, host, secure)?)?;

    // Generate update keys for WebVH log
    let mut update_secret = Secret::generate_ed25519(None, None);
    let update_pubkey = update_secret
        .get_public_keymultibase()
        .map_err(|e| anyhow::anyhow!("Failed to get update public key: {e}"))?;
    update_secret.id = format!("did:key:{0}#{0}", update_pubkey);

    let next_update_secret = Secret::generate_ed25519(None, None);

    let parameters = Parameters {
        update_keys: Some(Arc::new(vec![update_pubkey.into()])),
        portable: Some(true),
        next_key_hashes: Some(Arc::new(vec![
            next_update_secret
                .get_public_keymultibase()
                .map_err(|e| anyhow::anyhow!("Failed to get next update key: {e}"))?
                .into(),
        ])),
        ..Default::default()
    };

    let mut did_state = DIDWebVHState::default();
    did_state
        .create_log_entry(None, &did_document, &parameters, &update_secret)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create DID log entry: {e}"))?;

    let scid = did_state.scid().to_string();
    let log_entry_state = did_state
        .log_entries()
        .last()
        .ok_or_else(|| anyhow::anyhow!("No log entries were created"))?;

    let fallback_did = format!("did:webvh:{scid}:{}", webvh_url.domain);
    let final_did = match log_entry_state.log_entry.get_did_document() {
        Ok(doc) => doc
            .get("id")
            .and_then(|id: &Value| id.as_str())
            .map(String::from)
            .unwrap_or(fallback_did),
        Err(_) => fallback_did,
    };

    let diddoc_string = serde_json::to_string(&log_entry_state.log_entry)?;

    // Update secret IDs to match the final DID
    signing_ed25519.id = format!("{final_did}#key-0");
    signing_p256.id = format!("{final_did}#key-1");
    key_agreement_ed25519.id = format!("{final_did}#key-2");
    key_agreement_p256.id = format!("{final_did}#key-3");
    key_agreement_secp256k1.id = format!("{final_did}#key-4");

    Ok(DidWebvhResult {
        did: final_did,
        secrets: vec![
            signing_ed25519,
            signing_p256,
            key_agreement_ed25519,
            key_agreement_p256,
            key_agreement_secp256k1,
        ],
        did_doc: diddoc_string,
    })
}

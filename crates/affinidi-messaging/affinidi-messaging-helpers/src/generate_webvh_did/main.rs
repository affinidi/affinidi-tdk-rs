use std::sync::Arc;

use affinidi_tdk::{
    secrets_resolver::secrets::Secret,
    dids::{DID, KeyType, PeerKeyRole},
};
use clap::Parser;
use didwebvh_rs::{
    log_entry::LogEntryMethods, parameters::Parameters as WebVHParameters, url::WebVHURL,
    DIDWebVHState,
};
use ring::signature::Ed25519KeyPair;
use serde_json::{json, Value};
use url::Url;
use base64::prelude::*;
use std::fs::File;
use std::io::Write;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(Parser, Debug)]
#[command(version, about = "Generate did:webvh DIDs for Affinidi Messaging Mediator", long_about = None)]
struct Args {
    /// URL to host the DID document (e.g., example.com or localhost:7037)
    #[arg(long, short = 'u')]
    url: String,

    /// Use secure connection (https/wss)
    #[arg(long, short = 's', default_value_t = true, action = clap::ArgAction::Set)]
    secure: bool,

    /// API prefix path (e.g., /mediator/v1)
    #[arg(long, short = 'p', default_value = "")]
    api_prefix: String,

    /// Service endpoint URL (if not provided, derived from --url and --api-prefix)
    #[arg(long, short = 'e')]
    service_endpoint: Option<String>,

    /// Allow the DID to be moved to a different domain (portable DID)
    #[arg(long, short = 'r', default_value_t = true, action = clap::ArgAction::Set)]
    portable: bool,

    /// Convert the webvh log entry into a did:web compatible DID and DID document
    #[arg(long, default_value_t = false)]
    use_web: bool,

    /// Generate JWT secret for Mediator configuration
    #[arg(long, default_value_t = false)]
    with_jwt: bool,

    /// Generate Mediator Admin did:peer DID and secrets
    #[arg(long, default_value_t = false)]
    with_admin: bool,

    /// Generate output files for the DID document and secrets
    #[arg(long, default_value_t = false)]
    generate_files: bool,
}

struct Keys {
    signing_ed25519: Secret,
    signing_p256: Secret,
    key_agreement_ed25519: Secret,
    key_agreement_p256: Secret,
    key_agreement_secp256k1: Secret,
}

/// Generate cryptographic keys for DID
fn create_keys() -> Result<Keys> {
    let signing_ed25519 = Secret::generate_ed25519(None, None);
    let signing_p256 = Secret::generate_p256(None, None)?;
    let key_agreement_ed25519 = signing_ed25519.to_x25519()?;
    let key_agreement_p256   = Secret::generate_p256(None, None)?;
    let key_agreement_secp256k1 = Secret::generate_secp256k1(None, None)?;

    Ok(Keys {
        signing_ed25519,
        signing_p256,
        key_agreement_ed25519,
        key_agreement_p256,
        key_agreement_secp256k1,
    })
}

/// Create service endpoints for the mediator
fn create_service_endpoints(
    did: &str,
    url: &str,
    secure: bool,
    api_prefix: &str,
    service_endpoint: Option<&str>,
) -> Result<Vec<Value>> {
    let http_scheme = if secure { "https" } else { "http" };
    let ws_scheme = if secure { "wss" } else { "ws" };

    // Determine base domain/endpoint to use - strip scheme if present and replace %3A
    let endpoint = service_endpoint.unwrap_or(url).trim();
    let base_domain = endpoint
        .strip_prefix("https://")
        .or_else(|| endpoint.strip_prefix("http://"))
        .or_else(|| endpoint.strip_prefix("wss://"))
        .or_else(|| endpoint.strip_prefix("ws://"))
        .unwrap_or(endpoint)
        .replace("%3A", ":");

    // Build all service URLs from the base domain
    let base_http_url = format!("{}://{}{}", http_scheme, base_domain, api_prefix);
    let base_ws_url = format!("{}://{}{}/ws", ws_scheme, base_domain, api_prefix);
    let auth_url = format!(
        "{}://{}{}/authenticate",
        http_scheme, base_domain, api_prefix
    );

    Ok(vec![
        json!({
            "id": format!("{}#service", did),
            "type": "DIDCommMessaging",
            "serviceEndpoint": [
                { "uri": base_http_url, "accept": ["didcomm/v2"] },
                { "uri": base_ws_url,  "accept": ["didcomm/v2"] }
            ]
        }),
        json!({
            "id": format!("{}#auth", did),
            "type": "Authentication",
            "serviceEndpoint": auth_url
        }),
    ])
}

/// Determine the hosting path for the did:web DID document
fn get_did_hosting_path(url: &str, use_web: bool) -> String {
    let trimmed_url = url.replace("%3A", ":").trim_end_matches('/').to_string();
    let diddoc_file = if use_web { "did.json" } else { "did.jsonl" };
    if trimmed_url.contains('/') {
        // URL has a path, no .well-known
        format!("https://{}/{}", trimmed_url, diddoc_file)
    } else {
        // Base domain only, use .well-known
        format!("https://{}/.well-known/{}", trimmed_url, diddoc_file)
    }
}

/// Generate JWT secret for Mediator configuration
fn generate_jwt_secret() -> String {
    BASE64_URL_SAFE_NO_PAD
        .encode(Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new()).unwrap())
}

/// Generate a did:peer DID for the mediator admin, along with its secrets
fn generate_mediator_admin() -> (String, Vec<Secret>) {
    
    let (did, secrets) = DID::generate_did_peer(vec![(PeerKeyRole::Verification, KeyType::Ed25519), (PeerKeyRole::Encryption, KeyType::X25519)], None).unwrap();

    (did, secrets)
}


/// Setup did:webvh DID and document.
/// When `use_web` is true, also returns a `(web_did, web_did_doc_json)` tuple.
fn setup_did_webvh(
    url: &str,
    secure: bool,
    portable: bool,
    api_prefix: &str,
    service_endpoint: Option<&str>,
    use_web: bool,
) -> Result<(String, Vec<Secret>, String)> {
    
    println!("Setting up did:webvh...");

    // Build initial DID with placeholder SCID
    let full_url = if url.starts_with("http://") || url.starts_with("https://") {
        url.to_string()
    } else {
        format!("https://{}", url)
    };
    let parsed_url = Url::parse(&full_url)?;
    let webvh_url = WebVHURL::parse_url(&parsed_url)?;
    let did_id = webvh_url.to_string();

    println!("Creating DID with ID: {}", did_id);

    // Create keys and pre-compute public key multibase values
    let Keys {
        mut signing_ed25519,
        mut signing_p256,
        mut key_agreement_ed25519,
        mut key_agreement_p256,
        mut key_agreement_secp256k1,
    } = create_keys()?;

    let pub_key_0 = signing_ed25519.get_public_keymultibase()?;
    let pub_key_1 = signing_p256.get_public_keymultibase()?;
    let pub_key_2 = key_agreement_ed25519.get_public_keymultibase()?;
    let pub_key_3 = key_agreement_p256.get_public_keymultibase()?;
    let pub_key_4 = key_agreement_secp256k1.get_public_keymultibase()?;

    // Build DID document in one shot
    let did_document = json!({
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


    // Add service endpoints
    let mut did_document = did_document;
    did_document["service"] =
        serde_json::to_value(create_service_endpoints(&did_id, url, secure, api_prefix, service_endpoint)?)?;

    // Generate update keys and parameters for WebVH
    let mut update_secret = Secret::generate_ed25519(None, None);
    let update_pubkey = update_secret.get_public_keymultibase()?;
    update_secret.id = format!("did:key:{0}#{0}", update_pubkey);

    let next_update_secret = Secret::generate_ed25519(None, None);

    let parameters = WebVHParameters {
        update_keys: Some(Arc::new(vec![update_pubkey])),
        portable: Some(portable),
        next_key_hashes: Some(Arc::new(vec![next_update_secret.get_public_keymultibase()?])),
        ..Default::default()
    };

    // Create the WebVH DID state and log entry
    let mut did_state = DIDWebVHState::default();
    did_state
        .create_log_entry(None, &did_document, &parameters, &update_secret)
        .map_err(|e| format!("Failed to create DID log entry: {e}"))?;

    let scid = did_state.scid.clone();
    let log_entry_state = did_state
        .log_entries
        .last()
        .ok_or("No log entries were created")?;

    let fallback_did = format!("did:webvh:{scid}:{}", webvh_url.domain);
    let mut final_did = match log_entry_state.log_entry.get_did_document() {
        Ok(doc) => doc
            .get("id")
            .and_then(|id| id.as_str())
            .map(String::from)
            .unwrap_or(fallback_did),
        Err(_) => fallback_did,
    };

    let mut diddoc_string = serde_json::to_string(&log_entry_state.log_entry)?;

    // Optionally convert to did:web
    if use_web {
        final_did = DIDWebVHState::convert_webvh_id_to_web_id(&final_did);
        let web_did_doc = did_state
            .to_web_did()
            .map_err(|e| format!("Failed to convert to did:web: {e}"))?;
        diddoc_string = serde_json::to_string_pretty(&web_did_doc)?;
    }

    // Modify secrets to match key IDs
    signing_ed25519.id = format!("{}#key-0", final_did);
    signing_p256.id = format!("{}#key-1", final_did);
    key_agreement_ed25519.id = format!("{}#key-2", final_did);
    key_agreement_p256.id = format!("{}#key-3", final_did);
    key_agreement_secp256k1.id = format!("{}#key-4", final_did);

    Ok((
        final_did,
        vec![
            signing_ed25519,
            signing_p256,
            key_agreement_ed25519,
            key_agreement_p256,
            key_agreement_secp256k1,
        ],
        diddoc_string,
    ))
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    println!("Generating Mediator DID and Document...");
    println!();

    // Validate URL
    let url = args.url.trim();
    if url.is_empty() {
        return Err("URL cannot be empty".into());
    }
    let did_method = if args.use_web { "did:web" } else { "did:webvh" };
    println!("DID Method: {}", did_method);
    println!("URL: {}", url);
    println!("Secure: {}", args.secure);
    if !args.api_prefix.is_empty() {
        println!("API Prefix: {}", args.api_prefix);
    }
    if let Some(ref endpoint) = args.service_endpoint {
        println!("Service Endpoint: {}", endpoint);
    }
    if args.use_web {
        println!("Mode: Converting webvh log entry to did:web DID document");
    }
    println!();

    // Generate DID and document
    let (did_value, secrets, did_doc) = setup_did_webvh(
        url,
        args.secure,
        args.portable,
        &args.api_prefix,
        args.service_endpoint.as_deref(),
        args.use_web,
    )?;

    let jwt_secret = args.with_jwt
        .then(generate_jwt_secret)
        .unwrap_or_default();

    let (admin_did, admin_secrets) = args.with_admin
        .then(generate_mediator_admin)
        .unwrap_or_default();

    // Format secrets as JSON
    let secrets_json = serde_json::to_string_pretty(&secrets)?;

    println!();
    println!("=========================================================================");
    println!("Generated Mediator DID Information");
    println!("=========================================================================");
    println!();

    println!("DID:");
    println!("{}", did_value);
    println!();

    println!("DID Document:");
    println!("{}", &did_doc);
    println!();

    println!("DID Secrets:");
    println!("{}", secrets_json);
    println!();
    if !jwt_secret.is_empty() {
        println!();
        println!("JWT Secret:");
        println!("{}", jwt_secret);
    }

    println!();
    if !admin_did.is_empty() {
        println!("Mediator Admin DID:");
        println!("{}", admin_did);
        println!();

        let admin_secrets_json = serde_json::to_string_pretty(&admin_secrets)?;
        println!("Mediator Admin Secrets:");
        println!("{}", admin_secrets_json);
        println!();
    }

    if args.generate_files {
        let mut jwt_authorization_secret_file = File::create("jwt_authorization_secret.txt")?;
        jwt_authorization_secret_file.write_all(jwt_secret.as_bytes())?;

        // DID Document
        let mut did_doc_file = File::create("mediator_did.json")?;
        did_doc_file.write_all(did_doc.as_bytes())?;

        // DID Secrets
        let mut secrets_file = File::create("secrets.json")?;
        secrets_file.write_all(secrets_json.as_bytes())?;
    }

    println!("=========================================================================");
    println!("Next Steps");
    println!("=========================================================================");
    println!();

    println!("1. Host the DID document at:");
    println!("   {}", get_did_hosting_path(url, args.use_web));
    println!();
    println!("2. Ensure the file is publicly accessible via HTTPS");
    println!();
    println!("3. Update the log file when making changes to the DID document");
    println!();
    println!("4. Configure your mediator using the generated DID secrets");

    println!();
    println!("✓ Mediator DID generation completed successfully!");

    Ok(())
}

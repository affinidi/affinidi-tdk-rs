use affinidi_tdk::secrets_resolver::secrets::Secret;
use std::sync::Arc;
use clap::Parser;
use didwebvh_rs::DIDWebVHState;
use didwebvh_rs::log_entry::LogEntryMethods;
use didwebvh_rs::parameters::Parameters as WebVHParameters;
use didwebvh_rs::url::WebVHURL;
use serde_json::{Value, json};
use url::Url;

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

    /// Use secure connection (https/wss)
    #[arg(long, short = 'r', default_value_t = true, action = clap::ArgAction::Set)]
    portable: bool,
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

    let mut services = Vec::new();

    // DIDComm Messaging service with HTTP and WebSocket endpoints

    services.push(json!({
        "id": format!("{}#service", did),
        "type": "DIDCommMessaging",
        "serviceEndpoint": json!([
            {
                "uri": base_http_url,
                "accept": ["didcomm/v2"]
            },
            {
                "uri": base_ws_url,
                "accept": ["didcomm/v2"]
            }
        ]),
    }));

    // Authentication service
    services.push(json!({
        "id": format!("{}#auth", did),
        "type": "Authentication",
        "serviceEndpoint": auth_url,
    }));

    Ok(services)
}

/// Determine the hosting path for the DID document based on WebVH URL rules
fn get_did_hosting_path(url: &str) -> String {
    let trimmed_url = url.replace("%3A", ":").trim_end_matches('/').to_string();
    if trimmed_url.contains('/') {
        // URL has a path, no .well-known
        format!("https://{}/did.jsonl", trimmed_url)
    } else {
        // Base domain only, use .well-known
        format!("https://{}/.well-known/did.jsonl", trimmed_url)
    }
}

/// Setup did:webvh DID and document
fn setup_did_webvh(
    url: &str,
    secure: bool,
    portable: bool,
    api_prefix: &str,
    service_endpoint: Option<&str>,
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

    // Create keys
    let Keys {
        mut signing_ed25519,
        mut signing_p256,
        mut key_agreement_ed25519,
        mut key_agreement_p256,
        mut key_agreement_secp256k1,
    } = create_keys()?;

    // Build DID document
    let mut did_document = json!({
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://www.w3.org/ns/cid/v1"
        ],
        "id": &did_id,
        "verificationMethod": [
            {
                "id": format!("{did_id}#key-0"),
                "type": "Multikey",
                "controller": &did_id,
                "publicKeyMultibase": &signing_ed25519.get_public_keymultibase().unwrap()
            },
            {
                "id": format!("{did_id}#key-1"),
                "type": "Multikey",
                "controller": &did_id,
                "publicKeyMultibase": &signing_p256.get_public_keymultibase().unwrap()
            }
        ],
        "authentication": [format!("{did_id}#key-0"), format!("{did_id}#key-1")],
        "assertionMethod": [format!("{did_id}#key-0"), format!("{did_id}#key-1")],
    });

    // Add X25519 key agreement method
    did_document["verificationMethod"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "id": format!("{did_id}#key-2"),
            "type": "Multikey",
            "controller": &did_id,
            "publicKeyMultibase": &key_agreement_ed25519.get_public_keymultibase().unwrap()
        }));
    // Add P256 key agreement method
    did_document["verificationMethod"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "id": format!("{did_id}#key-3"),
            "type": "Multikey",
            "controller": &did_id,
            "publicKeyMultibase": &key_agreement_p256.get_public_keymultibase().unwrap()
        }));
    // Add Secp256k1 key agreement method
    did_document["verificationMethod"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "id": format!("{did_id}#key-4"),
            "type": "Multikey",
            "controller": &did_id,
            "publicKeyMultibase": &key_agreement_secp256k1.get_public_keymultibase().unwrap()
        }));
    did_document["keyAgreement"] = json!([format!("{did_id}#key-2"), format!("{did_id}#key-3"), format!("{did_id}#key-4")]);
    

    // Add service endpoints
    let services = create_service_endpoints(&did_id, url, secure, api_prefix, service_endpoint)?;
    did_document["service"] = serde_json::to_value(services)?;

    // Generate update keys and parameters for WebVH
    let mut update_secret = Secret::generate_ed25519(None, None);
    update_secret.id = [
        "did:key:",
        &update_secret.get_public_keymultibase()?,
        "#",
        &update_secret.get_public_keymultibase()?,
    ]
    .concat();
    let next_update_secret = Secret::generate_ed25519(None, None);

    // Build parameters
    let parameters = WebVHParameters {
        update_keys: Some(Arc::new(vec![update_secret.get_public_keymultibase().unwrap()])),
        portable: Some(portable),
        next_key_hashes: Some(Arc::new(vec![next_update_secret.get_public_keymultibase().unwrap()])),
        ..Default::default()
    };

    // Create the WebVH DID state and log entry
    let mut did_state = DIDWebVHState::default();
    did_state
        .create_log_entry(None, &did_document, &parameters, &update_secret)
        .map_err(|e| format!("Failed to create DID log entry: {e}"))?;

    let scid = did_state.scid.clone();
    let log_entry_state = did_state.log_entries.last().unwrap();

    let fallback_did = format!("did:webvh:{scid}:{}", webvh_url.domain);
    let final_did = match log_entry_state.log_entry.get_did_document() {
        Ok(doc) => doc
            .get("id")
            .and_then(|id| id.as_str())
            .map(String::from)
            .unwrap_or(fallback_did),
        Err(_) => fallback_did,
    };

    let log_string = serde_json::to_string(&log_entry_state.log_entry)?;

    // Modify secrets to match key IDs
    signing_ed25519.id = format!("{}#key-0", final_did);
    signing_p256.id = format!("{}#key-1", final_did);
    key_agreement_ed25519.id = format!("{}#key-2", final_did);
    key_agreement_p256.id = format!("{}#key-3", final_did);
    key_agreement_secp256k1.id = format!("{}#key-4", final_did);

    Ok((
        final_did,
        vec![signing_ed25519, signing_p256, key_agreement_ed25519, key_agreement_p256, key_agreement_secp256k1],
        log_string,
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
    println!("DID Method: did:webvh");
    println!("URL: {}", url);
    println!("Secure: {}", args.secure);
    if !args.api_prefix.is_empty() {
        println!("API Prefix: {}", args.api_prefix);
    }
    if let Some(ref endpoint) = args.service_endpoint {
        println!("Service Endpoint: {}", endpoint);
    }
    println!();

    // Generate DID and document
    let (did, secrets, log_entry) = setup_did_webvh(
        url,
        args.secure,
        args.portable,
        &args.api_prefix,
        args.service_endpoint.as_deref(),
    )?;

    // Format secrets as JSON
    let secrets_json = serde_json::to_string_pretty(&secrets)?;

    println!();
    println!("=========================================================================");
    println!("Generated Mediator DID Information");
    println!("=========================================================================");
    println!();

    println!("DID:");
    println!("{}", did);
    println!();

    println!("DID Document:");
    println!("{}", &log_entry);
    println!();

    println!("DID Secrets:");
    println!("{}", secrets_json);
    println!();

    println!("=========================================================================");
    println!("Next Steps");
    println!("=========================================================================");
    println!();

    println!("1. Host the DID document at:");
    println!("   {}", get_did_hosting_path(url));
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

use affinidi_tdk::{
    did_common::{
        Document,
        service::{Endpoint, Service},
        verification_method::{VerificationMethod, VerificationRelationship},
    },
    secrets_resolver::secrets::Secret,
};
use clap::Parser;
use didwebvh_rs::{DIDWebVHState, parameters::Parameters, url::WebVHURL};
use serde_json::{Value, json};
use std::collections::HashMap;
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
}

/// Generate cryptographic keys for DID
fn create_keys() -> Result<(Secret, Secret)> {
    let mut verification_key = Secret::generate_ed25519(None, None);
    let mut encryption_key = Secret::generate_x25519(None, None)?;

    verification_key.id = verification_key.get_public_keymultibase()?;
    encryption_key.id = encryption_key.get_public_keymultibase()?;

    Ok((verification_key, encryption_key))
}

/// Create service endpoints for the mediator
fn create_service_endpoints(
    did: &str,
    url: &str,
    secure: bool,
    api_prefix: &str,
    service_endpoint: Option<&str>,
) -> Result<Vec<Service>> {
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
    let mut didcomm_properties = HashMap::new();
    didcomm_properties.insert(
        "serviceEndpoint".to_string(),
        json!([
            {
                "uri": base_http_url,
                "routingKeys": [],
                "accept": ["didcomm/v2"]
            },
            {
                "uri": base_ws_url,
                "routingKeys": [],
                "accept": ["didcomm/v2"]
            }
        ]),
    );

    services.push(Service {
        id: Some(Url::parse(&format!("{}#service", did))?),
        type_: vec!["DIDCommMessaging".to_string()],
        property_set: didcomm_properties,
        service_endpoint: Endpoint::Url(Url::parse(&base_http_url)?),
    });

    // Authentication service
    services.push(Service {
        id: Some(Url::parse(&format!("{}#auth", did))?),
        type_: vec!["Authentication".to_string()],
        property_set: HashMap::new(),
        service_endpoint: Endpoint::Url(Url::parse(&auth_url)?),
    });

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
    api_prefix: &str,
    service_endpoint: Option<&str>,
) -> Result<(String, Document, Vec<Secret>, String)> {
    println!("Setting up did:webvh...");

    // Build initial DID with placeholder SCID
    let full_url = if url.starts_with("http://") || url.starts_with("https://") {
        url.to_string()
    } else {
        format!("https://{}", url)
    };
    let parsed_url = Url::parse(&full_url)?;
    let webvh_url = WebVHURL::parse_url(&parsed_url)?;
    let temp_did = webvh_url.to_string();

    println!("Creating did:webvh with SCID...");

    // Create keys
    let (mut verification_key, mut encryption_key) = create_keys()?;

    // Update key IDs with DID reference
    verification_key.id = format!("{}#key-1", temp_did);
    encryption_key.id = format!("{}#key-2", temp_did);

    // Create the basic DID Document
    let mut did_document = Document::new(&temp_did)?;

    // Add JSON-LD contexts
    let mut parameters_set = HashMap::new();
    parameters_set.insert(
        "@context".to_string(),
        json!([
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/multikey/v1",
        ]),
    );
    did_document.parameters_set = parameters_set;

    // Add verification method for signing (P256)
    let mut property_set: HashMap<String, Value> = HashMap::new();
    property_set.insert(
        "publicKeyMultibase".to_string(),
        Value::String(verification_key.get_public_keymultibase()?),
    );

    let v_key_id = Url::parse(&verification_key.id)?;
    did_document.verification_method.push(VerificationMethod {
        id: v_key_id.clone(),
        type_: "Multikey".to_string(),
        controller: Url::parse(&temp_did)?,
        revoked: None,
        expires: None,
        property_set: property_set.clone(),
    });

    did_document
        .assertion_method
        .push(VerificationRelationship::Reference(v_key_id.clone()));
    did_document
        .authentication
        .push(VerificationRelationship::Reference(v_key_id));

    // Add encryption key (Secp256k1)
    property_set.insert(
        "publicKeyMultibase".to_string(),
        Value::String(encryption_key.get_public_keymultibase()?),
    );

    let e_key_id = Url::parse(&encryption_key.id)?;
    did_document.verification_method.push(VerificationMethod {
        id: e_key_id.clone(),
        type_: "Multikey".to_string(),
        controller: Url::parse(&temp_did)?,
        revoked: None,
        expires: None,
        property_set,
    });

    did_document
        .key_agreement
        .push(VerificationRelationship::Reference(e_key_id));

    // Add service endpoints
    let services = create_service_endpoints(&temp_did, url, secure, api_prefix, service_endpoint)?;
    did_document.service = services;

    // Generate update secrets for WebVH
    let mut update_secret = Secret::generate_ed25519(None, None);
    update_secret.id = [
        "did:key:",
        &update_secret.get_public_keymultibase()?,
        "#",
        &update_secret.get_public_keymultibase()?,
    ]
    .concat();

    let next_update_secret = Secret::generate_ed25519(None, None);

    let parameters = Parameters::new()
        .with_key_pre_rotation(true)
        .with_update_keys(vec![update_secret.get_public_keymultibase()?])
        .with_next_key_hashes(vec![next_update_secret.get_public_keymultibase_hash()?])
        .with_portable(true)
        .build();

    // Convert affinidi_tdk Secret to didwebvh_rs compatible Secret via JWK
    let update_secret_jwk = serde_json::to_value(&update_secret)?;
    let didwebvh_update_secret: didwebvh_rs::affinidi_secrets_resolver::secrets::Secret =
        serde_json::from_value(update_secret_jwk)?;

    // Create the WebVH DID state and log entry
    let mut didwebvh = DIDWebVHState::default();
    let log_entry = didwebvh.create_log_entry(
        None,
        &serde_json::to_value(&did_document)?,
        &parameters,
        &didwebvh_update_secret,
    )?;

    // Get the final DID from the log entry
    let final_did = log_entry
        .get_state()
        .get("id")
        .and_then(|v| v.as_str())
        .ok_or("Failed to get DID from log entry")?
        .replace("\"", "");

    // Update DID document from log entry
    did_document = serde_json::from_value(log_entry.get_did_document()?)?;

    // Update secret IDs to match the final DID
    verification_key.id = format!("{}#key-1", final_did);
    encryption_key.id = format!("{}#key-2", final_did);

    // Serialize log entry to string
    let log_string = serde_json::to_string(&log_entry.log_entry)?;

    println!("✓ DID created: {}", final_did);

    Ok((
        final_did,
        did_document,
        vec![verification_key, encryption_key],
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
    let (did, _did_document, secrets, log_entry) = setup_did_webvh(
        url,
        args.secure,
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

//! Helps to generate DIDs and secrets to setup self-hosted mediator.
use affinidi_messaging_helpers::common::{affinidi_logo, check_path};
use affinidi_tdk::dids::{DID, KeyType, PeerKeyRole};
use base64::prelude::*;
use clap::Parser;
use console::{Term, style};
use ring::signature::Ed25519KeyPair;
use serde_json::{Value, json};
use std::error::Error;

/// Setups the environment for Affinidi Messaging
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Path to the environments file (defaults to environments.json)
    #[arg(long)]
    host: Option<String>,

    #[arg(long, short)]
    secure_connection: Option<bool>,

    #[arg(long, short)]
    api_prefix: Option<String>,
}

fn generate_secrets_and_did() -> Result<(String, Value), Box<dyn Error>> {
    let (did, secrets) = DID::generate_did_peer(
        vec![
            (PeerKeyRole::Verification, KeyType::P256),
            (PeerKeyRole::Verification, KeyType::Ed25519),
            (PeerKeyRole::Encryption, KeyType::Secp256k1),
            (PeerKeyRole::Encryption, KeyType::P256),
            (PeerKeyRole::Encryption, KeyType::X25519),
        ],
        None,
    )
    .unwrap();

    let secrets_as_json = serde_json::to_value(secrets)?;

    Ok((did, secrets_as_json))
}

fn generate_jwt_secret() -> String {
    BASE64_URL_SAFE_NO_PAD
        .encode(Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new()).unwrap())
}

fn build_did_doc(
    domain: &str,
    did: &str,
    mut secrets: Value,
    secure_connection: bool,
    api_path: String,
) -> Result<String, Box<dyn Error>> {
    // handle secrets
    if let Value::Array(ref mut items) = secrets {
        for (i, item) in items.iter_mut().enumerate() {
            if let Value::Object(map) = item {
                // replace ids to be did keys
                map.insert("id".to_string(), json!(format!("{}#key-{}", did, i + 1)));
                // Add `controller`
                map.insert("controller".to_string(), json!(did));
                // Handle `privateKeyJwk`
                if let Some(Value::Object(ref mut jwk)) = map.remove("privateKeyJwk") {
                    jwk.remove("d"); // Remove private part
                    map.insert("publicKeyJwk".to_string(), Value::Object(jwk.clone()));
                }
            }
        }
    }

    let http = if secure_connection { "https" } else { "http" };

    let ws = if secure_connection { "wss" } else { "ws" };

    let result = serde_json::to_string_pretty(&json!({
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/jws-2020/v1"
        ],
        "id": did,
        "verificationMethod": secrets,
        "authentication": [
            format!("{}#key-1", did),
            format!("{}#key-2", did),

          ],
          "assertionMethod": [
            format!("{}#key-1", did),
            format!("{}#key-2", did),

          ],
          "keyAgreement": [
            format!("{}#key-3", did),
            format!("{}#key-4", did),
          ],
        "service": [
        {
            "id": format!("{}#service", did),
            "type": "DIDCommMessaging",
            "serviceEndpoint": [
                {
                    "uri": format!("{}://{}{}", http, domain.replace("%3A", ":"), api_path),
                    "routingKeys": [],
                    "accept": [
                        "didcomm/v2"
                    ]
                },
                {
                    "uri": format!("{}://{}{}/ws", ws, domain.replace("%3A", ":"), api_path),
                    "routingKeys": [],
                    "accept": [
                        "didcomm/v2"
                    ]
                }
            ]
        },
        {
            "id": format!("{}#auth", did),
            "type": "Authentication",
            "serviceEndpoint": format!("{}://{}{}/authenticate", http, domain.replace("%3A", ":"), api_path),
        },
    ]
    }))?;

    Ok(result)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let term = Term::stdout();
    let _ = term.clear_screen();
    affinidi_logo::print_logo();
    // Ensure we are somewhere we should be...
    check_path()?;

    let args: Args = Args::parse();
    let host = args.host.unwrap_or("localhost%3A7037".to_string());
    let secure_connection = args.secure_connection.unwrap_or(true);
    let api_prefix = args.api_prefix.unwrap_or("".to_string());

    println!("{}", style("Generating new DID info...").yellow(),);
    let (old_did, secrets_json) = generate_secrets_and_did()?;
    let new_did = if !api_prefix.is_empty() {
        // If prefix is supplied, include it in the DID (no .well-known)
        let did_path_part = api_prefix.replace("/", ":");
        format!("did:web:{}{}", &host, &did_path_part)
    } else {
        // If base domain (no prefix), DID is just the host (no .well-known in DID)
        format!("did:web:{}", &host)
    };
    let did_doc = build_did_doc(
        &host,
        &new_did,
        secrets_json.clone(),
        secure_connection,
        api_prefix,
    )?;
    let mut secrets_string = serde_json::to_string_pretty(&secrets_json)?;
    let jwt_secret = generate_jwt_secret();
    secrets_string = secrets_string.replace(&old_did, &new_did);

    // Creating new Admin account
    let (admin_did, admin_did_secrets) = DID::generate_did_peer(
        vec![
            (PeerKeyRole::Verification, KeyType::P256),
            (PeerKeyRole::Verification, KeyType::Ed25519),
            (PeerKeyRole::Encryption, KeyType::Secp256k1),
            (PeerKeyRole::Encryption, KeyType::P256),
            (PeerKeyRole::Encryption, KeyType::X25519),
        ],
        None,
    )
    .unwrap();
    let admin_did_secrets_string = serde_json::to_string_pretty(&admin_did_secrets)?;

    // print out all the info required to setup the self-hosted mediator
    println!();
    println!("{}", style("Mediator DID Information").yellow());
    println!("{}\n{}", style("DID Value:").green(), &new_did);
    println!("{}\n{}", style("DID Document:").green(), &did_doc);
    println!("{}\n{}", style("DID Secrets:").green(), &secrets_string);
    println!();
    println!("{}\n{}", style("JWT Secret:").green(), &jwt_secret);
    println!();
    println!("{}", style("Mediator Admin Information").yellow());
    println!(
        "{}:\n{}\n{}:\n{}",
        style("Admin DID Value:").green(),
        &admin_did,
        style("Admin DID Secret:").green(),
        &admin_did_secrets_string,
    );

    println!(
        "\n{}",
        style("DID, DID Doc, and secrets completed. Use the values to setup your self-hosted mediator.").green(),
    );

    Ok(())
}

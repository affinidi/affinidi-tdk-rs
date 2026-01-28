//! Methods relating to working with DID's

use affinidi_did_common::one_or_many::OneOrMany;
use affinidi_did_common::{
    PeerCreateKey, PeerKeyPurpose, PeerService, PeerServiceEndpoint, PeerServiceEndpointLong,
    PeerServiceEndpointLongMap, DID as DIDCommon,
};
use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};
use affinidi_tdk::secrets_resolver::secrets::{KeyType, Secret};
use console::style;
use dialoguer::{Input, theme::ColorfulTheme};
use sha256::digest;
use std::error::Error;

/// Creates a fully formed DID, with corresponding secrets
/// - service: Creates a service definition with the provided URI if Some
///   - [0] = URI
pub fn create_did(
    service: Option<Vec<String>>,
    auth_service: bool,
) -> Result<(String, Vec<Secret>), Box<dyn Error>> {
    // Generate keys for encryption and verification
    let mut v_ed25519_key = Secret::generate_ed25519(None, None);
    let mut e_secp256k1_key =
        Secret::generate_secp256k1(None, None).expect("Couldn't create secp256k1 secret");

    // Get the multibase public keys
    let v_multibase = v_ed25519_key.get_public_keymultibase()?;
    let e_multibase = e_secp256k1_key.get_public_keymultibase()?;

    // Put these keys in order and specify the type of each key
    let keys = vec![
        PeerCreateKey::from_multibase(PeerKeyPurpose::Verification, v_multibase),
        PeerCreateKey::from_multibase(PeerKeyPurpose::Encryption, e_multibase),
    ];

    // Create a service definition
    let mut services = service.as_ref().map(|service| {
        let endpoints: Vec<PeerServiceEndpointLongMap> = service
            .iter()
            .map(|uri| PeerServiceEndpointLongMap {
                uri: uri.to_string(),
                accept: vec!["didcomm/v2".into()],
                routing_keys: vec![],
            })
            .collect();

        vec![PeerService {
            id: None,
            type_: "dm".into(),
            endpoint: PeerServiceEndpoint::Long(OneOrMany::Many(
                endpoints
                    .into_iter()
                    .map(|m| PeerServiceEndpointLong {
                        uri: m.uri,
                        accept: m.accept,
                        routing_keys: m.routing_keys,
                    })
                    .collect(),
            )),
        }]
    });

    if auth_service {
        let Some(service) = service.as_ref() else {
            eprintln!("Service URI is required for authentication service");
            return Err("Service URI is required for authentication service".into());
        };

        let auth_svc = PeerService {
            id: Some("#auth".into()),
            type_: "Authentication".into(),
            endpoint: PeerServiceEndpoint::Uri([&service[0], "/authenticate"].concat()),
        };
        services.as_mut().unwrap().push(auth_svc);
    }

    // Create the did:peer DID
    let (did_peer, _) =
        DIDCommon::generate_peer(&keys, services.as_deref()).map_err(|e| e.to_string())?;
    let did_peer_str = did_peer.to_string();

    v_ed25519_key.id = [did_peer_str.as_str(), "#key-1"].concat();
    e_secp256k1_key.id = [did_peer_str.as_str(), "#key-2"].concat();
    let secrets_json = vec![v_ed25519_key, e_secp256k1_key];

    Ok((did_peer_str, secrets_json))
}

/// Helper function to resolve a DID and retrieve the URI address of the service endpoint
pub async fn get_service_address(did: &str) -> Result<String, Box<dyn Error>> {
    let did_resolver = DIDCacheClient::new(DIDCacheConfigBuilder::default().build()).await?;

    let resolve_response = did_resolver.resolve(did).await?;

    let uri = if let Some(service) = resolve_response.doc.service.first() {
        service.service_endpoint.get_uri()
    } else {
        None
    };

    if let Some(uri) = uri {
        Ok(uri.replace('"', "").trim_end_matches('/').to_string())
    } else {
        Err("No service endpoint found".into())
    }
}

pub fn manually_enter_did_or_hash(theme: &ColorfulTheme) -> Option<String> {
    println!();
    println!(
        "{}",
        style("Limited checks are done on the DID or Hash - be careful!").yellow()
    );
    println!("DID or SHA256 Hash of a DID (type exit to quit this dialog)");

    let input: String = Input::with_theme(theme)
        .with_prompt("DID or SHA256 Hash")
        .interact_text()
        .unwrap();

    if input == "exit" {
        return None;
    }

    if input.starts_with("did:") {
        Some(digest(input))
    } else if input.len() != 64 {
        println!(
            "{}",
            style(format!(
                "Invalid SHA256 Hash length. length({}) when expected(64)",
                input.len()
            ))
            .red()
        );
        None
    } else {
        Some(input.to_ascii_lowercase())
    }
}

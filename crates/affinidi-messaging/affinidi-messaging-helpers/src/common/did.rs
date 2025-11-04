//! Methods relating to working with DID's

use affinidi_did_common::one_or_many::OneOrMany;
use affinidi_did_key::DIDKey;
use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};
use affinidi_tdk::secrets_resolver::secrets::{KeyType, Secret};
use console::style;
use dialoguer::{Input, theme::ColorfulTheme};
use did_peer::{
    DIDPeer, DIDPeerCreateKeys, DIDPeerKeys, DIDPeerService, PeerServiceEndPoint,
    PeerServiceEndPointLong, PeerServiceEndPointLongMap,
};
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
    let (v_did_key, mut v_ed25519_key) = DIDKey::generate(KeyType::Ed25519)?;
    let (e_did_key, mut e_secp256k1_key) = DIDKey::generate(KeyType::Secp256k1)?;

    // Put these keys in order and specify the type of each key (we strip the did:key: from the front)
    let keys = vec![
        DIDPeerCreateKeys {
            purpose: DIDPeerKeys::Verification,
            type_: None,
            public_key_multibase: Some(v_did_key[8..].to_string()),
        },
        DIDPeerCreateKeys {
            purpose: DIDPeerKeys::Encryption,
            type_: None,
            public_key_multibase: Some(e_did_key[8..].to_string()),
        },
    ];

    // Create a service definition
    let mut services = service.as_ref().map(|service| {
        let endpoints: Vec<PeerServiceEndPointLongMap> = service
            .iter()
            .map(|uri| PeerServiceEndPointLongMap {
                uri: uri.to_string(),
                accept: vec!["didcomm/v2".into()],
                routing_keys: vec![],
            })
            .collect();

        vec![DIDPeerService {
            id: None,
            _type: "dm".into(),
            service_end_point: PeerServiceEndPoint::Long(PeerServiceEndPointLong::Map(
                OneOrMany::Many(endpoints),
            )),
        }]
    });

    if auth_service {
        let Some(service) = service.as_ref() else {
            eprintln!("Service URI is required for authentication service");
            return Err("Service URI is required for authentication service".into());
        };

        let auth_service = DIDPeerService {
            id: Some("#auth".into()),
            _type: "Authentication".into(),
            service_end_point: PeerServiceEndPoint::Long(PeerServiceEndPointLong::URI(
                [&service[0], "/authenticate"].concat(),
            )),
        };
        services.as_mut().unwrap().push(auth_service);
    }

    let services = services.as_ref();
    // Create the did:peer DID
    let (did_peer, _) =
        DIDPeer::create_peer_did(&keys, services).expect("Failed to create did:peer");

    v_ed25519_key.id = [did_peer.as_str(), "#key-1"].concat();
    e_secp256k1_key.id = [did_peer.as_str(), "#key-2"].concat();
    let secrets_json = vec![v_ed25519_key, e_secp256k1_key];

    Ok((did_peer, secrets_json))
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

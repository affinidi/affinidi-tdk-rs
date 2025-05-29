//! Methods relating to working with DID's

use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};
use affinidi_tdk::secrets_resolver::secrets::Secret;
use console::style;
use dialoguer::{Input, theme::ColorfulTheme};
use did_peer::{
    DIDPeer, DIDPeerCreateKeys, DIDPeerKeys, DIDPeerService, PeerServiceEndPoint,
    PeerServiceEndPointLong, PeerServiceEndPointLongMap,
};
use serde_json::json;
use sha256::digest;
use ssi::{
    JWK,
    dids::{DIDBuf, DIDKey, document::service::Endpoint},
    jwk::Params,
    verification_methods::ssi_core::OneOrMany,
};
use std::error::Error;
struct LocalDidPeerKeys {
    v_d: Option<String>,
    v_x: Option<String>,
    e_d: Option<String>,
    e_x: Option<String>,
    e_y: Option<String>,
}

/// Creates a fully formed DID, with corresponding secrets
/// - service: Creates a service definition with the provided URI if Some
///   - [0] = URI
pub fn create_did(
    service: Option<Vec<String>>,
    auth_service: bool,
) -> Result<(String, Vec<Secret>), Box<dyn Error>> {
    // Generate keys for encryption and verification
    let v_ed25519_key = JWK::generate_ed25519().unwrap();

    let e_secp256k1_key = JWK::generate_secp256k1();

    let mut local_did_peer_keys = LocalDidPeerKeys {
        v_d: None,
        v_x: None,
        e_d: None,
        e_x: None,
        e_y: None,
    };

    if let Params::OKP(map) = v_ed25519_key.clone().params {
        local_did_peer_keys.v_d = Some(String::from(map.private_key.clone().unwrap()));
        local_did_peer_keys.v_x = Some(String::from(map.public_key.clone()));
    }

    if let Params::EC(map) = e_secp256k1_key.clone().params {
        local_did_peer_keys.e_d = Some(String::from(map.ecc_private_key.clone().unwrap()));
        local_did_peer_keys.e_x = Some(String::from(map.x_coordinate.clone().unwrap()));
        local_did_peer_keys.e_y = Some(String::from(map.y_coordinate.clone().unwrap()));
    }

    // Create the did:key DID's for each key above
    let v_did_key = DIDKey::generate(&v_ed25519_key).unwrap();
    let e_did_key = DIDKey::generate(&e_secp256k1_key).unwrap();

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
        let endpoints = service.iter().map(|uri| PeerServiceEndPointLongMap {
            uri: uri.to_string(),
            accept: vec!["didcomm/v2".into()],
            routing_keys: vec![],
        });
        vec![DIDPeerService {
            id: None,
            _type: "dm".into(),
            service_end_point: PeerServiceEndPoint::Long(PeerServiceEndPointLong::Map(
                OneOrMany::Many(endpoints.collect()),
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

    let secrets_json = vec![
        Secret::from_str(
            &format!("{}#key-1", did_peer),
            &json!({
                "crv": "Ed25519",
                "d":  local_did_peer_keys.v_d,
                "kty": "OKP",
                "x": local_did_peer_keys.v_x
            }),
        )?,
        Secret::from_str(
            &format!("{}#key-2", did_peer),
            &json!({
                "crv": "secp256k1",
                "d": local_did_peer_keys.e_d,
                "kty": "EC",
                "x": local_did_peer_keys.e_x,
                "y": local_did_peer_keys.e_y,
            }),
        )?,
    ];

    Ok((did_peer, secrets_json))
}

/// Helper function to resolve a DID and retrieve the URI address of the service endpoint
pub async fn get_service_address(did: &str) -> Result<String, Box<dyn Error>> {
    let did_resolver = DIDCacheClient::new(DIDCacheConfigBuilder::default().build()).await?;

    let resolve_response = did_resolver
        .resolve(DIDBuf::from_string(did.into())?.as_did())
        .await?;

    let uri = if let Some(service) = resolve_response.doc.service.first() {
        if let Some(end_point) = &service.service_endpoint {
            if let Some(endpoint) = end_point.first() {
                match endpoint {
                    Endpoint::Map(map) => {
                        if let Some(uri) = map.get("uri") {
                            uri.as_str()
                        } else {
                            None
                        }
                    }
                    Endpoint::Uri(uri) => Some(uri.as_str()),
                }
            } else {
                None
            }
        } else {
            None
        }
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

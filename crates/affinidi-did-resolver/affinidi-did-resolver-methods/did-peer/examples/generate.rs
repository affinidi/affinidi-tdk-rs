use affinidi_did_common::one_or_many::OneOrMany;
use affinidi_did_key::DIDKey;
use affinidi_secrets_resolver::{
    jwk::Params,
    secrets::{KeyType, SecretMaterial},
};
use did_peer::{
    DIDPeer, DIDPeerCreateKeys, DIDPeerKeys, DIDPeerService, PeerServiceEndPoint,
    PeerServiceEndPointLong, PeerServiceEndPointLongMap,
};

#[tokio::main]
async fn main() {
    // Generate keys for encryption and verification
    let (e_did_key, e_ed25519_key) = DIDKey::generate(KeyType::Ed25519).unwrap();
    let (v_did_key, v_ed25519_key) = DIDKey::generate(KeyType::Ed25519).unwrap();
    let (v2_did_key, v_secp256k1_key) = DIDKey::generate(KeyType::Secp256k1).unwrap();

    // Print the private keys in case you want to save them for later
    println!("Private keys:");
    if let SecretMaterial::JWK(jwk) = &e_ed25519_key.secret_material
        && let Params::OKP(params) = &jwk.params
    {
        println!(
            "E: private-key (d): {} {}",
            params.curve,
            params.d.clone().unwrap_or_default()
        );
        println!("E: public-key (x): {} {}", params.curve, params.x);
    }
    println!();

    if let SecretMaterial::JWK(jwk) = &v_ed25519_key.secret_material
        && let Params::OKP(params) = &jwk.params
    {
        println!(
            "V: private-key (d): {} {}",
            params.curve,
            params.d.clone().unwrap_or_default()
        );
        println!("V: public-key (x): {} {}", params.curve, params.x);
    }
    println!();

    if let SecretMaterial::JWK(jwk) = &v_secp256k1_key.secret_material
        && let Params::EC(params) = &jwk.params
    {
        println!(
            "V2: private-key: {} {}",
            params.curve,
            params.d.clone().unwrap_or_default()
        );
        println!("V2: public-key (x): {} {}", params.curve, params.x);
        println!("V2: public-key (y): {} {}", params.curve, params.y);
    }
    println!();

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
        DIDPeerCreateKeys {
            purpose: DIDPeerKeys::Encryption,
            type_: None,
            public_key_multibase: Some(v2_did_key[8..].to_string()),
        },
    ];

    // Create a service definition
    let services = vec![DIDPeerService {
        _type: "dm".into(),
        service_end_point: PeerServiceEndPoint::Long(PeerServiceEndPointLong::Map(OneOrMany::One(
            PeerServiceEndPointLongMap {
                uri: "https://localhost:7037".into(),
                accept: vec!["didcomm/v2".into()],
                routing_keys: vec![],
            },
        ))),
        id: None,
    }];

    // Create the did:peer DID
    let (did_peer, _) =
        DIDPeer::create_peer_did(&keys, Some(&services)).expect("Failed to create did:peer");

    println!("{did_peer}",);

    println!();

    // Resolve the did:peer DID to a Document
    let peer = DIDPeer;

    let document = match peer.resolve(&did_peer).await {
        Ok(res) => res,
        Err(e) => {
            println!("Error: {e:?}");
            return;
        }
    };

    println!(
        "DID Document:\n{}",
        serde_json::to_string_pretty(&document).unwrap()
    );

    println!();
    println!("Expand keys");
    let expanded = DIDPeer::expand_keys(&document).await;
    println!(
        "DID Document:\n{}",
        serde_json::to_string_pretty(&expanded.unwrap()).unwrap()
    );
}

use did_peer::{
    DIDPeer, DIDPeerCreateKeys, DIDPeerKeys, DIDPeerService, PeerServiceEndPoint,
    PeerServiceEndPointLong,
};
use ssi::{
    JWK,
    dids::{DID, DIDResolver},
    jwk::Params,
    multicodec::MultiEncoded,
};

#[tokio::main]
async fn main() {
    // Generate keys for encryption and verification
    let e_ed25519_key = JWK::generate_ed25519().unwrap();
    let v_ed25519_key = JWK::generate_ed25519().unwrap();
    let v_secp256k1_key = JWK::generate_secp256k1();

    // Print the private keys in case you want to save them for later
    println!("Private keys:");
    if let Params::OKP(map) = e_ed25519_key.clone().params {
        println!(
            "E: private-key (d): {} {}",
            map.curve,
            String::from(map.private_key.clone().unwrap())
        );
        println!(
            "E: public-key (x): {} {}",
            map.curve,
            String::from(map.public_key.clone())
        );
    }
    println!();

    if let Params::OKP(map) = v_ed25519_key.clone().params {
        println!(
            "V: private-key (d): {} {}",
            map.curve,
            String::from(map.private_key.clone().unwrap())
        );
        println!(
            "V: public-key (x): {} {}",
            map.curve,
            String::from(map.public_key.clone())
        );
    }
    println!();

    if let Params::EC(map) = v_secp256k1_key.clone().params {
        println!(
            "V2: private-key: {} {}",
            map.curve.clone().unwrap(),
            String::from(map.ecc_private_key.clone().unwrap())
        );
        println!(
            "V2: public-key (x): {} {}",
            map.curve.clone().unwrap(),
            String::from(map.x_coordinate.clone().unwrap())
        );
        println!(
            "V2: public-key (y): {} {}",
            map.curve.clone().unwrap(),
            String::from(map.y_coordinate.clone().unwrap())
        );
    }
    println!();

    let key = ssi::dids::DIDKey;

    // Create the did:key DID's for each key above
    let e_did_key = ssi::dids::DIDKey::generate(&e_ed25519_key).unwrap();
    let v_did_key = ssi::dids::DIDKey::generate(&v_ed25519_key).unwrap();
    let v2_did_key = ssi::dids::DIDKey::generate(&v_secp256k1_key).unwrap();

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
        service_end_point: PeerServiceEndPoint::Long(PeerServiceEndPointLong {
            uri: "https://localhost:7037".into(),
            accept: vec!["didcomm/v2".into()],
            routing_keys: vec![],
        }),
        id: None,
    }];

    // Create the did:peer DID
    let (did_peer, _) =
        DIDPeer::create_peer_did(&keys, Some(&services)).expect("Failed to create did:peer");

    println!("{}", did_peer);

    println!();

    // Resolve the did:peer DID to a Document
    let peer = DIDPeer;

    let output = match peer.resolve(DID::new::<String>(&did_peer).unwrap()).await {
        Ok(res) => res,
        Err(e) => {
            println!("Error: {:?}", e);
            return;
        }
    };

    println!(
        "DID Document:\n{}",
        serde_json::to_string_pretty(&output.document).unwrap()
    );
    println!("Metadata: {:?}", output.metadata);

    println!();
    println!("Expand keys");
    let expanded = DIDPeer::expand_keys(&output.document).await;
    println!(
        "DID Document:\n{}",
        serde_json::to_string_pretty(&expanded.unwrap()).unwrap()
    );

    let output = key
        .resolve(DID::new("did:key:z6Mkp89diy1PZkbUBDTpiqZBotddb1VV7JnY8qiZMGErUbFe").unwrap())
        .await
        .unwrap();

    println!("key :\n{:#?}", output.document);

    let a = multibase::decode("z6Mkp89diy1PZkbUBDTpiqZBotddb1VV7JnY8qiZMGErUbFe").unwrap();
    println!("{:?}", a);
    let b = MultiEncoded::new(&a.1).unwrap();
    let jwk = JWK::from_multicodec(b).unwrap();
    println!("{}", jwk);

    //let jwk = JWK::from
}

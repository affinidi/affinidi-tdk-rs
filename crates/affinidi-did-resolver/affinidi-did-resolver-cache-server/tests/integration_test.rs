use affinidi_did_common::{Document, one_or_many::OneOrMany};
use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};
use affinidi_did_resolver_cache_server::server::start;
use affinidi_secrets_resolver::secrets::Secret;
use did_peer::{
    DIDPeer, DIDPeerCreateKeys, DIDPeerKeyType, DIDPeerKeys, DIDPeerService, PeerServiceEndPoint,
    PeerServiceEndPointLong, PeerServiceEndPointLongMap,
};
use tokio::time::{Duration, sleep};

const DID_ETHR: &str = "did:ethr:0x1:0xb9c5714089478a327f09197987f16f9e5d936e8a";
const DID_KEY: &str = "did:key:z6MkiToqovww7vYtxm1xNM15u9JzqzUFZ1k7s7MazYJUyAxv";
const DID_PKH: &str =
    "did:pkh:solana:4sGjMW1sUnHzSxGspuhpqLDx6wiyjNtZ:CKg5d12Jhpej1JqtmxLJgaFqqeYjxgPqToJ4LBdvG9Ev";

#[tokio::test]
async fn test_cache_server() {
    //  Run cache server
    _start_cache_server().await;

    let did_peer = _create_and_validate_did_peer();

    // Build config with network
    let config = DIDCacheConfigBuilder::default()
        .with_network_mode("ws://127.0.0.1:8080/did/v1/ws")
        .with_cache_ttl(10)
        .build();

    // Resolve DIDs and add to cache
    let client = DIDCacheClient::new(config).await.unwrap();
    let dids: Vec<&str> = vec![&did_peer, DID_ETHR, DID_KEY, DID_PKH];
    let mut did_docs_vec: Vec<Document> = vec![];
    for did in dids.clone() {
        let res = client.resolve(did).await.unwrap();
        let doc = res.doc;
        did_docs_vec.push(doc);
        assert!(!res.cache_hit)
    }

    // Check if it was a cache hit, should be cache hit
    assert!(client.resolve(DID_ETHR).await.unwrap().cache_hit);

    // Match doc in cache with resolved doc
    let cache = client.get_cache().clone();
    for (i, did) in dids.clone().iter().enumerate() {
        let in_cache_doc = cache.get(&DIDCacheClient::hash_did(did)).await.unwrap();
        assert_eq!(in_cache_doc, did_docs_vec[i]);
    }
    client.remove(DID_PKH).await.unwrap();
    assert!(
        !client
            .get_cache()
            .contains_key(&DIDCacheClient::hash_did(DID_PKH))
    );

    sleep(Duration::from_secs(11)).await;
    // Validate cache expiry
    for did in dids.clone() {
        assert!(
            !client
                .get_cache()
                .contains_key(&DIDCacheClient::hash_did(did))
        );
    }
}

async fn _start_cache_server() {
    tokio::spawn(async move { start().await });
    println!("Server running");
}

fn _create_and_validate_did_peer() -> String {
    let (e_did_key, v_did_key, keys) = _get_keys(DIDPeerKeyType::Secp256k1, true);
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

    let (did_peer, _) = DIDPeer::create_peer_did(&keys, Some(&services)).unwrap();
    _validate_did_peer(&did_peer, &e_did_key, &v_did_key);

    did_peer
}

fn _validate_did_peer(did_peer: &str, e_did_key: &str, v_did_key: &str) {
    let parts: Vec<&str> = did_peer.split(":").collect();
    let mut method_ids: Vec<&str> = parts[2].split(".").collect();
    method_ids = method_ids[1..].to_vec();
    let keys_multibase = [v_did_key[8..].to_string(), e_did_key[8..].to_string()];

    method_ids.iter().take(2).for_each(|id| {
        assert!(keys_multibase.contains(&id[1..].to_string()));
    });

    assert_eq!(parts.len(), 3);
    assert_eq!(parts[1], "peer");
}

fn _get_keys(
    key_type: DIDPeerKeyType,
    with_pub_key: bool,
) -> (String, String, Vec<DIDPeerCreateKeys>) {
    let encryption_key = match key_type {
        DIDPeerKeyType::Ed25519 => Secret::generate_ed25519(None, None),
        DIDPeerKeyType::P256 => {
            Secret::generate_p256(None, None).expect("Couldn't create P256 secret")
        }
        DIDPeerKeyType::Secp256k1 => {
            Secret::generate_secp256k1(None, None).expect("Couldn't create secp256k1 secret")
        }
    };
    let verification_key = match key_type {
        DIDPeerKeyType::Ed25519 => Secret::generate_ed25519(None, None),
        DIDPeerKeyType::P256 => {
            Secret::generate_p256(None, None).expect("Couldn't create P256 secret")
        }
        DIDPeerKeyType::Secp256k1 => {
            Secret::generate_secp256k1(None, None).expect("Couldn't create secp256k1 secret")
        }
    };
    //  Create the did:key DID's for each key above
    let e_did_key = [
        "did:key:",
        &encryption_key
            .get_public_keymultibase()
            .expect("encryption multibase public-key"),
    ]
    .concat();
    let v_did_key = [
        "did:key:",
        &verification_key
            .get_public_keymultibase()
            .expect("verification multibase public-key"),
    ]
    .concat();

    // Put these keys in order and specify the type of each key (we strip the did:key: from the front)
    let keys = vec![
        DIDPeerCreateKeys {
            purpose: DIDPeerKeys::Verification,
            type_: Some(key_type.clone()),
            public_key_multibase: if with_pub_key {
                Some(v_did_key[8..].to_string())
            } else {
                None
            },
        },
        DIDPeerCreateKeys {
            purpose: DIDPeerKeys::Encryption,
            type_: Some(key_type.clone()),
            public_key_multibase: if with_pub_key {
                Some(e_did_key[8..].to_string())
            } else {
                None
            },
        },
    ];

    (e_did_key, v_did_key, keys)
}

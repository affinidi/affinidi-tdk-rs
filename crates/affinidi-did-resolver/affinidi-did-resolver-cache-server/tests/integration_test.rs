use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};
use affinidi_did_resolver_cache_server::server::start;
use did_peer::{
    DIDPeer, DIDPeerCreateKeys, DIDPeerKeyType, DIDPeerKeys, DIDPeerService, PeerServiceEndPoint,
    PeerServiceEndPointLong,
};
use ssi::{
    JWK,
    dids::{DIDBuf, Document},
};
use tokio::time::{Duration, sleep};

const DID_ETHR: &str = "did:ethr:0x1:0xb9c5714089478a327f09197987f16f9e5d936e8a";
const DID_JWK: &str = "did:jwk:eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6ImFjYklRaXVNczNpOF91c3pFakoydHBUdFJNNEVVM3l6OTFQSDZDZEgyVjAiLCJ5IjoiX0tjeUxqOXZXTXB0bm1LdG00NkdxRHo4d2Y3NEk1TEtncmwyR3pIM25TRSJ9";
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
    let dids: Vec<&str> = vec![&did_peer, DID_ETHR, DID_JWK, DID_KEY, DID_PKH];
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
        service_end_point: PeerServiceEndPoint::Long(PeerServiceEndPointLong {
            uri: "https://localhost:7037".into(),
            accept: vec!["didcomm/v2".into()],
            routing_keys: vec![],
        }),
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
) -> (DIDBuf, DIDBuf, Vec<DIDPeerCreateKeys>) {
    let encryption_key = match key_type {
        DIDPeerKeyType::Ed25519 => JWK::generate_ed25519().unwrap(),
        DIDPeerKeyType::P256 => JWK::generate_p256(),
        DIDPeerKeyType::Secp256k1 => JWK::generate_secp256k1(),
    };
    let verification_key = match key_type {
        DIDPeerKeyType::Ed25519 => JWK::generate_ed25519().unwrap(),
        DIDPeerKeyType::P256 => JWK::generate_p256(),
        DIDPeerKeyType::Secp256k1 => JWK::generate_secp256k1(),
    };
    //  Create the did:key DID's for each key above
    let e_did_key = ssi::dids::DIDKey::generate(&encryption_key).unwrap();
    let v_did_key = ssi::dids::DIDKey::generate(&verification_key).unwrap();

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

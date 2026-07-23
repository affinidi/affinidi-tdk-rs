// The integration test exercises the WebSocket transport via the cache-sdk's
// `network` mode, which is only available when the server is built with the
// `network` feature. Skip the whole module under `--no-default-features`.
#![cfg(feature = "network")]

use affinidi_did_common::{
    DID as DIDCommon, Document, PeerCreateKey, PeerKeyPurpose, PeerService, PeerServiceEndpoint,
    PeerServiceEndpointLong, one_or_many::OneOrMany,
};
use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};
use affinidi_did_resolver_cache_server::server::start_with_config;
use affinidi_secrets_resolver::secrets::Secret;
use std::{net::TcpListener as StdTcpListener, path::PathBuf};
use tokio::time::{Duration, sleep};

const DID_ETHR: &str = "did:ethr:0x1:0xb9c5714089478a327f09197987f16f9e5d936e8a";
const DID_KEY: &str = "did:key:z6MkiToqovww7vYtxm1xNM15u9JzqzUFZ1k7s7MazYJUyAxv";
const DID_PKH: &str =
    "did:pkh:solana:4sGjMW1sUnHzSxGspuhpqLDx6wiyjNtZ:CKg5d12Jhpej1JqtmxLJgaFqqeYjxgPqToJ4LBdvG9Ev";

#[tokio::test]
async fn test_cache_server() {
    //  Run cache server
    let port = _start_cache_server().await;

    let did_peer = _create_and_validate_did_peer();

    // Build config with network
    let config = DIDCacheConfigBuilder::default()
        .with_network_mode(&format!("ws://127.0.0.1:{port}/did/v1/ws"))
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
    // Sync Moka's internal state so expired entries are actually evicted
    client.get_cache().run_pending_tasks().await;

    // Immutable DID methods (key, peer, ethr, pkh) have no TTL — they stay
    // cached indefinitely. Only mutable methods (web, webvh, cheqd, scid)
    // expire after cache_ttl. Since all DIDs in this test are immutable,
    // they should still be present (except DID_PKH which was manually removed).
    assert!(
        client
            .get_cache()
            .contains_key(&DIDCacheClient::hash_did(&did_peer)),
        "immutable did:peer should survive beyond TTL"
    );
    assert!(
        client
            .get_cache()
            .contains_key(&DIDCacheClient::hash_did(DID_ETHR)),
        "immutable did:ethr should survive beyond TTL"
    );
    assert!(
        client
            .get_cache()
            .contains_key(&DIDCacheClient::hash_did(DID_KEY)),
        "immutable did:key should survive beyond TTL"
    );
    // DID_PKH was manually removed above, so it should still be absent
    assert!(
        !client
            .get_cache()
            .contains_key(&DIDCacheClient::hash_did(DID_PKH)),
        "manually removed did:pkh should remain absent"
    );
}

/// Start the cache server on an ephemeral port, wait until it answers, and
/// return the port the client should dial.
///
/// This used to hard-code 8080 for both server and client, spawn `start()` and
/// drop the `JoinHandle`. Three faults compounded (#656):
///
/// 1. **The bind error was discarded.** Dropping the handle threw away the
///    `Result`, so the test could not tell "port already taken" from "server
///    started fine".
/// 2. **Nothing waited for readiness.** The client was built immediately after
///    the spawn, racing the bind even when the port was free.
/// 3. **The port was fixed.** Anything else holding 8080 — a parallel run, a
///    stray `python -m http.server` — meant the client connected to *that*
///    process instead, which answers a plain 404 rather than a 101 upgrade.
///
/// Together they turned a port conflict into `NetworkTimeout` from the first
/// resolve, 15 seconds later, pointing at the network rather than at the port.
/// Two people diagnosed that by hand before the cause was found.
async fn _start_cache_server() -> u16 {
    // Ask the OS for a free port, then hand it to the server. A small window
    // remains between releasing it here and the server binding it; losing that
    // race now fails loudly below instead of silently.
    let port = StdTcpListener::bind("127.0.0.1:0")
        .expect("bind an ephemeral port")
        .local_addr()
        .expect("read the ephemeral port")
        .port();

    let config_path = _write_config_for_port(port);
    let server = tokio::spawn(async move { start_with_config(&config_path).await });

    // Poll the server's own health endpoint rather than a bare TCP connect:
    // on a port some other process holds, TCP would connect and tell us
    // nothing. This confirms *our* server is the one answering.
    let health = format!("http://127.0.0.1:{port}/did/healthchecker");
    let client = reqwest::Client::new();
    let mut ready = false;
    for _ in 0..100 {
        if server.is_finished() {
            break;
        }
        if let Ok(res) = client.get(&health).send().await
            && res.status().is_success()
        {
            ready = true;
            break;
        }
        sleep(Duration::from_millis(100)).await;
    }

    if !ready {
        if server.is_finished() {
            // Surface the real error — almost always a failed bind.
            panic!(
                "cache server exited before becoming ready: {:?}",
                server.await
            );
        }
        panic!("cache server did not become ready on 127.0.0.1:{port} within 10s");
    }

    println!("Server running on 127.0.0.1:{port}");
    port
}

/// Copy the shipped config, overriding only `listen_address`.
///
/// Rewriting one line rather than writing a minimal config from scratch keeps
/// the test running against the real configuration — including any settings
/// added to it later.
fn _write_config_for_port(port: u16) -> String {
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("conf/cache-conf.toml");
    let raw = std::fs::read_to_string(&src).expect("read the shipped cache-conf.toml");

    let mut out = String::with_capacity(raw.len());
    let mut replaced = false;
    for line in raw.lines() {
        if line.trim_start().starts_with("listen_address") {
            out.push_str(&format!("listen_address = \"127.0.0.1:{port}\"\n"));
            replaced = true;
        } else {
            out.push_str(line);
            out.push('\n');
        }
    }
    assert!(
        replaced,
        "conf/cache-conf.toml no longer has a listen_address line to override"
    );

    let path = std::env::temp_dir().join(format!("cache-conf-test-{port}.toml"));
    std::fs::write(&path, out).expect("write the test config");
    path.to_string_lossy().into_owned()
}

fn _create_and_validate_did_peer() -> String {
    let (e_did_key, v_did_key, keys) = _get_keys(true);
    let services = vec![PeerService {
        type_: "dm".into(),
        endpoint: PeerServiceEndpoint::Long(OneOrMany::One(PeerServiceEndpointLong {
            uri: "https://localhost:7037".into(),
            accept: vec!["didcomm/v2".into()],
            routing_keys: vec![],
        })),
        id: None,
    }];

    let (did_peer, _) = DIDCommon::generate_peer(&keys, Some(&services)).unwrap();
    let did_peer_str = did_peer.to_string();
    _validate_did_peer(&did_peer_str, &e_did_key, &v_did_key);

    did_peer_str
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

fn _get_keys(with_pub_key: bool) -> (String, String, Vec<PeerCreateKey>) {
    // Using Secp256k1 keys for this test
    let encryption_key =
        Secret::generate_secp256k1(None, None).expect("Couldn't create secp256k1 secret");
    let verification_key =
        Secret::generate_secp256k1(None, None).expect("Couldn't create secp256k1 secret");

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
    let keys = if with_pub_key {
        vec![
            PeerCreateKey::from_multibase(PeerKeyPurpose::Verification, v_did_key[8..].to_string()),
            PeerCreateKey::from_multibase(PeerKeyPurpose::Encryption, e_did_key[8..].to_string()),
        ]
    } else {
        // Without public key - not used in this test but preserved for completeness
        vec![]
    };

    (e_did_key, v_did_key, keys)
}

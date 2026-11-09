//! did:webs through the cache server.
//!
//! Its own test binary: each server start installs the process-wide tracing
//! subscriber, so only one server can start per test process.
#![cfg(feature = "network")]

use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};
use affinidi_did_resolver_cache_server::server::start_with_config;
use std::{net::TcpListener as StdTcpListener, path::PathBuf};
use tokio::time::{Duration, sleep};

/// The server resolves did:webs, under the same host policy as its other web
/// methods: a did:webs naming a loopback host is refused by that policy, not
/// reported as an unsupported method.
#[tokio::test]
async fn did_webs_is_resolved_under_the_host_policy() {
    let port = _start_cache_server().await;
    let config = DIDCacheConfigBuilder::default()
        .with_network_mode(&format!("ws://127.0.0.1:{port}/did/v1/ws"))
        .build();
    let client = DIDCacheClient::new(config).await.unwrap();

    let err = client
        .resolve("did:webs:127.0.0.1%3A1:ENro7uf0ePmiK3jdTo2YCdXLqW7z7xoP6qhhBou6gBLe")
        .await
        .expect_err("a loopback did:webs must be refused");
    let message = err.to_string();
    assert!(message.contains("host policy"), "{message}");
}

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

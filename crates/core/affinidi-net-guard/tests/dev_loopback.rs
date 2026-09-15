//! The `dev-loopback` feature, used from outside the crate the way a
//! consumer's development build would use it. Compiles to nothing without the
//! feature.
#![cfg(feature = "dev-loopback")]

use std::net::Ipv4Addr;

use affinidi_net_guard::{DevLoopback, EgressError, EgressPolicy, GuardedClientBuilder};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

fn dev_policy() -> EgressPolicy {
    EgressPolicy::public_internet()
        .with_dev_loopback(DevLoopback::acknowledge_ssrf_protection_disabled_for_loopback())
}

async fn serve_ok() -> u16 {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut head = [0u8; 4096];
                let _ = stream.read(&mut head).await;
                let _ = stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                    )
                    .await;
                let _ = stream.shutdown().await;
            });
        }
    });
    port
}

#[tokio::test]
async fn fetches_plain_http_from_a_loopback_literal_and_localhost() {
    let port = serve_ok().await;
    let policy = dev_policy();
    assert!(policy.is_dev_loopback());
    let client = GuardedClientBuilder::new(policy.clone()).build().unwrap();
    for raw in [
        format!("http://127.0.0.1:{port}/"),
        format!("http://localhost:{port}/"),
    ] {
        let url = policy.vet(&raw).unwrap();
        let response = client.get(&url).unwrap().send().await.unwrap();
        assert!(response.status().is_success(), "{raw}");
        assert_eq!(client.read_body_capped(response).await.unwrap(), b"ok");
    }
}

#[test]
fn still_refuses_private_metadata_embedded_loopback_and_plaintext_to_public_hosts() {
    let policy = dev_policy();
    for raw in [
        "http://10.0.0.5/",
        "http://169.254.169.254/",
        "http://[::ffff:127.0.0.1]/",
    ] {
        assert!(
            matches!(policy.vet(raw), Err(EgressError::BlockedAddress { .. })),
            "{raw}"
        );
    }
    assert!(matches!(
        policy.vet("http://example.com/"),
        Err(EgressError::SchemeNotAllowed(_))
    ));
}

#[tokio::test]
async fn a_public_client_refuses_a_url_vetted_under_dev_loopback() {
    let port = serve_ok().await;
    let vetted = dev_policy()
        .vet(&format!("http://127.0.0.1:{port}/"))
        .unwrap();
    let client = GuardedClientBuilder::new(EgressPolicy::public_internet())
        .build()
        .unwrap();
    assert!(client.get(&vetted).is_err());
}

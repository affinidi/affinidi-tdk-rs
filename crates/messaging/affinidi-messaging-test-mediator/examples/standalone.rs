//! Run the in-process [`TestMediator`] as a **standalone process**, so
//! out-of-process test clients — a separately-spawned daemon, a client running
//! inside a Docker container, a CI job on another host — can share one mediator
//! for local DIDComm testing. Prints the mediator DID + endpoints, then blocks
//! until the process is killed.
//!
//! Run from the affinidi-tdk-rs workspace:
//!   cargo run -p affinidi-messaging-test-mediator --example standalone
//!
//! ## Environment
//!
//! - `TEST_MEDIATOR_LISTEN` — bind address (`host:port`). Default `127.0.0.1:0`
//!   (loopback, OS-assigned port). Use `0.0.0.0:0` to bind every interface.
//! - `TEST_MEDIATOR_ADVERTISE_HOST` — host to advertise in the mediator's DID
//!   service endpoint instead of the bound address. Set this when clients reach
//!   the mediator from a different network namespace than loopback — e.g.
//!   `host.docker.internal` for clients in Docker containers. See
//!   [`TestMediatorBuilder::advertise_host`].
//!
//! ## Example — reachable from inside Docker containers
//!
//! ```sh
//! TEST_MEDIATOR_LISTEN=0.0.0.0:0 \
//! TEST_MEDIATOR_ADVERTISE_HOST=host.docker.internal \
//!   cargo run -p affinidi-messaging-test-mediator --example standalone
//! ```
//!
//! Binds all interfaces but puts `host.docker.internal:<port>` in the mediator's
//! DID, so a containerized client (which reaches the host via the Docker gateway,
//! not `127.0.0.1`) can both *connect to* and *receive replies through* the
//! mediator.

use affinidi_messaging_test_mediator::{AccessListModeType, TestMediator, acl::allow_all};

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Permissive ACL: any DID may connect/register and send/receive. Standalone
    // harnesses typically connect with arbitrary, unregistered DIDs, which the
    // default deny-by-default `ExplicitAllow` would 403.
    let mut builder = TestMediator::builder()
        .acl_mode(AccessListModeType::ExplicitDeny)
        .global_acl_default(allow_all());

    if let Ok(addr) = std::env::var("TEST_MEDIATOR_LISTEN") {
        builder = builder.listen_addr(
            addr.parse::<std::net::SocketAddr>()
                .expect("TEST_MEDIATOR_LISTEN must be host:port"),
        );
    }
    if let Ok(host) = std::env::var("TEST_MEDIATOR_ADVERTISE_HOST")
        && !host.is_empty()
    {
        builder = builder.advertise_host(host);
    }

    let mediator = builder.spawn().await?;
    println!("MEDIATOR_DID={}", mediator.did());
    println!("MEDIATOR_HTTP={}", mediator.endpoint());
    println!("MEDIATOR_WS={}", mediator.ws_endpoint());
    eprintln!("[test-mediator] running; kill the process to stop");

    std::future::pending::<()>().await;
    drop(mediator);
    Ok(())
}

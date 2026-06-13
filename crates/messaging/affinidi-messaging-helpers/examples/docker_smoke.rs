//! TI3 — smoke test for the docker-compose.test.yml stack.
//!
//! Against the composed mediator (default `http://localhost:7037`, embedded in
//! the fixed mediator `did:peer`), this generates a fresh Alice `did:peer`
//! homed at the mediator, authenticates, and sends a signed trust-ping —
//! exercising a full DIDComm message round-trip (PING out, PONG back). Exits
//! non-zero on any failure so a CI job can gate on it.
//!
//! Run against the running stack:
//!   cargo run -p affinidi-messaging-helpers --example docker_smoke
//!
//! Override the target with the `MEDIATOR_DID` env var (defaults to the fixed
//! TEST-ONLY identity in docker/test/conf/mediator.toml).

use std::{sync::Arc, time::Duration};

use affinidi_messaging_sdk::{
    ATM,
    config::ATMConfig,
    errors::ATMError,
    messages::{FetchDeletePolicy, fetch::FetchOptions},
    profiles::ATMProfile,
};
use affinidi_tdk::common::{TDKSharedState, config::TDKConfig};
use affinidi_tdk::dids::{DID, KeyType, PeerKeyRole};
use affinidi_tdk::secrets_resolver::SecretsResolver;
use tokio::time::sleep;

/// The fixed TEST-ONLY mediator `did:peer` from docker/test/conf/mediator.toml
/// (service endpoint `http://localhost:7037/mediator/v1`). TEST-ONLY.
const DEFAULT_MEDIATOR_DID: &str = "did:peer:2.Vz6Mksfa1ijceFf8yFmTSdRha6Ha2Lzzfuc68UyRAdpsC5pr6.Ez6LShyV6x81XmxvpyDpgwaXo27783iBBJPTeUtDgcvyKLDXP.SeyJ0IjoiZG0iLCJzIjpbeyJ1cmkiOiJodHRwOi8vbG9jYWxob3N0OjcwMzcvbWVkaWF0b3IvdjEiLCJhY2NlcHQiOlsiZGlkY29tbS92MiJdfSx7InVyaSI6IndzOi8vbG9jYWxob3N0OjcwMzcvbWVkaWF0b3IvdjEvd3MiLCJhY2NlcHQiOlsiZGlkY29tbS92MiJdfV19.SeyJ0IjoiQXV0aGVudGljYXRpb24iLCJzIjoiaHR0cDovL2xvY2FsaG9zdDo3MDM3L21lZGlhdG9yL3YxL2F1dGhlbnRpY2F0ZSIsImlkIjoiI2F1dGgifQ";

#[tokio::main]
async fn main() -> Result<(), ATMError> {
    let mediator_did =
        std::env::var("MEDIATOR_DID").unwrap_or_else(|_| DEFAULT_MEDIATOR_DID.to_string());
    println!("smoke: target mediator {mediator_did}");

    let tdk = Arc::new(
        TDKSharedState::new(
            TDKConfig::headless().map_err(|e| ATMError::ConfigError(e.to_string()))?,
        )
        .await?,
    );

    // Fresh Alice, homed at the mediator (DIDComm service endpoint = mediator DID).
    let (alice_did, secrets) = DID::generate_did_peer(
        vec![
            (PeerKeyRole::Verification, KeyType::Ed25519),
            (PeerKeyRole::Encryption, KeyType::X25519),
        ],
        Some(mediator_did.clone()),
    )
    .map_err(|e| ATMError::ConfigError(format!("generate Alice did:peer: {e}")))?;
    tdk.secrets_resolver().insert_vec(&secrets).await;
    println!("smoke: generated Alice {alice_did}");

    let atm = ATM::new(ATMConfig::builder().build()?, tdk).await?;

    // profile_add authenticates Alice against the mediator.
    let alice = ATMProfile::new(
        &atm,
        Some("Alice".to_string()),
        alice_did,
        Some(mediator_did.clone()),
    )
    .await?;
    let alice = atm.profile_add(&alice, false).await?;
    println!("smoke: authenticated against the mediator");

    // Signed trust-ping, expecting a PONG. Don't block on the response: over
    // plain HTTP the PONG is queued for Alice (not returned inline), so we send
    // then fetch it back — which is the full round-trip (PING -> mediator ->
    // PONG queued -> fetched).
    let sent = atm
        .trust_ping()
        .send_ping(&alice, &mediator_did, true, true, false)
        .await?;
    println!("smoke: PING sent (hash {})", sent.message_hash);

    // The PONG is queued asynchronously; poll briefly for it.
    let mut pong = None;
    for _ in 0..20 {
        let msgs = atm
            .fetch_messages(
                &alice,
                &FetchOptions {
                    limit: 10,
                    delete_policy: FetchDeletePolicy::Optimistic,
                    start_id: None,
                },
            )
            .await?;
        if let Some(msg) = msgs.success.into_iter().next() {
            pong = Some(msg.msg_id);
            break;
        }
        sleep(Duration::from_millis(500)).await;
    }

    match pong {
        Some(id) => {
            println!("smoke: trust-ping round-trip OK (PONG {id})");
            Ok(())
        }
        None => Err(ATMError::MsgReceiveError(
            "no PONG retrieved from the mediator within the timeout".to_string(),
        )),
    }
}

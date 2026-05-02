//! Cross-Mediator Forwarding Example
//!
//! Demonstrates message forwarding between two different mediators.
//! Alice uses one mediator, Bob uses a different mediator. Messages are
//! routed through both mediators, showing timing information.
//!
//! Supports a ping-pong mode for measuring round-trip latency over time.
//!
//! Usage:
//!   cargo run --example cross_mediator_forwarding -- \
//!     --alice-environment alice_env --bob-environment bob_env
//!
//! Both environments must be configured in the TDK environments file
//! with their respective mediator endpoints.

use affinidi_messaging_didcomm::message::Message;
use affinidi_messaging_sdk::{
    errors::ATMError,
    profiles::ATMProfile,
    protocols::mediator::acls::{AccessListModeType, MediatorACLSet},
};
use affinidi_tdk::{TDK, common::config::TDKConfig};
use clap::Parser;
use serde_json::json;
use std::time::{Duration, Instant, SystemTime};
use tracing::info;
use tracing_subscriber::filter;
use uuid::Uuid;

#[derive(Parser, Debug)]
#[command(
    version,
    about = "Cross-mediator forwarding example with latency measurement"
)]
struct Args {
    /// Environment name for Alice (must have Alice profile and mediator configured)
    #[arg(long, default_value = "alice")]
    alice_environment: String,

    /// Environment name for Bob (must have Bob profile and a DIFFERENT mediator configured)
    #[arg(long, default_value = "bob")]
    bob_environment: String,

    /// Path to the environments file (defaults to environments.json)
    #[arg(short, long)]
    path_environments: Option<String>,

    /// Enable ping-pong mode: continuously send messages back and forth
    /// measuring round-trip latency (max 1 message per second)
    #[arg(long)]
    ping_pong: bool,

    /// Number of ping-pong rounds (0 = infinite)
    #[arg(long, default_value = "10")]
    rounds: u32,
}

#[tokio::main]
async fn main() -> Result<(), ATMError> {
    let args: Args = Args::parse();

    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(filter::EnvFilter::from_default_env())
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("Logging failed, exiting...");

    println!("=== Cross-Mediator Forwarding Example ===");
    println!("Alice environment: {}", args.alice_environment);
    println!("Bob environment: {}", args.bob_environment);
    println!();

    // --- Setup Alice's TDK and mediator ---
    let alice_tdk = TDK::new(
        TDKConfig::builder()
            .with_environment_name(args.alice_environment.clone())
            .build()?,
        None,
    )
    .await?;

    let _shared = alice_tdk.get_shared_state();
    let alice_env = _shared.environment();
    let alice_atm = alice_tdk.atm.clone().unwrap();

    let tdk_alice = alice_env.profiles().get("Alice").ok_or_else(|| {
        ATMError::ConfigError(format!(
            "Alice profile not found in environment: {}",
            args.alice_environment
        ))
    })?;

    alice_tdk.add_profile(tdk_alice).await;
    let atm_alice = alice_atm
        .profile_add(
            &ATMProfile::from_tdk_profile(&alice_atm, tdk_alice).await?,
            true,
        )
        .await?;

    let alice_mediator_did = tdk_alice.mediator.clone().unwrap_or_default();
    println!("Alice DID: {}", atm_alice.inner.did);
    println!("Alice mediator: {}", alice_mediator_did);

    // --- Setup Bob's TDK and mediator ---
    let bob_tdk = TDK::new(
        TDKConfig::builder()
            .with_environment_name(args.bob_environment.clone())
            .build()?,
        None,
    )
    .await?;

    let _shared = bob_tdk.get_shared_state();
    let bob_env = _shared.environment();
    let bob_atm = bob_tdk.atm.clone().unwrap();

    let tdk_bob = bob_env.profiles().get("Bob").ok_or_else(|| {
        ATMError::ConfigError(format!(
            "Bob profile not found in environment: {}",
            args.bob_environment
        ))
    })?;

    bob_tdk.add_profile(tdk_bob).await;
    let atm_bob = bob_atm
        .profile_add(
            &ATMProfile::from_tdk_profile(&bob_atm, tdk_bob).await?,
            true,
        )
        .await?;

    let bob_mediator_did = tdk_bob.mediator.clone().unwrap_or_default();
    println!("Bob DID: {}", atm_bob.inner.did);
    println!("Bob mediator: {}", bob_mediator_did);
    println!();

    if alice_mediator_did == bob_mediator_did {
        println!("WARNING: Alice and Bob are using the same mediator.");
        println!("For cross-mediator forwarding, configure different mediators.");
        println!();
    }

    // --- Setup ACLs ---
    // Ensure Alice and Bob can communicate with each other
    setup_acls(&alice_atm, &atm_alice, &atm_bob, &bob_atm).await?;

    // --- Send message: Alice -> Bob ---
    println!("=== Alice -> Bob (through two mediators) ===");
    let alice_send_start = Instant::now();

    let msg_text = "Hello Bob! This message is routed through two mediators.";
    let msg_id = send_message(
        &alice_atm,
        &atm_alice,
        &atm_bob,
        &bob_mediator_did,
        msg_text,
    )
    .await?;

    println!(
        "  Alice sent message (id: {}) in {}ms",
        msg_id,
        alice_send_start.elapsed().as_millis()
    );

    // Bob receives
    let bob_receive_start = Instant::now();
    match bob_atm
        .message_pickup()
        .live_stream_get(&atm_bob, &msg_id, Duration::from_secs(15), true)
        .await?
    {
        Some(received) => {
            let receive_time = bob_receive_start.elapsed();
            let total_time = alice_send_start.elapsed();
            println!(
                "  Bob received message in {}ms (total: {}ms)",
                receive_time.as_millis(),
                total_time.as_millis()
            );
            println!("  Message body: {:?}", received.0.body);
        }
        None => {
            println!("  ERROR: Bob did not receive the message within timeout");
            return Ok(());
        }
    }
    println!();

    // --- Send response: Bob -> Alice ---
    println!("=== Bob -> Alice (return path through two mediators) ===");
    let bob_send_start = Instant::now();

    let response_text = "Hi Alice! Got your message. Routing works both ways!";
    let response_id = send_message(
        &bob_atm,
        &atm_bob,
        &atm_alice,
        &alice_mediator_did,
        response_text,
    )
    .await?;

    println!(
        "  Bob sent response (id: {}) in {}ms",
        response_id,
        bob_send_start.elapsed().as_millis()
    );

    // Alice receives
    let alice_receive_start = Instant::now();
    match alice_atm
        .message_pickup()
        .live_stream_get(&atm_alice, &response_id, Duration::from_secs(15), true)
        .await?
    {
        Some(received) => {
            let receive_time = alice_receive_start.elapsed();
            let total_time = bob_send_start.elapsed();
            println!(
                "  Alice received response in {}ms (total: {}ms)",
                receive_time.as_millis(),
                total_time.as_millis()
            );
            println!("  Message body: {:?}", received.0.body);
        }
        None => {
            println!("  ERROR: Alice did not receive the response within timeout");
            return Ok(());
        }
    }
    println!();

    // --- Ping-Pong Mode ---
    if args.ping_pong {
        println!("=== Ping-Pong Latency Measurement ===");
        println!(
            "Rounds: {} (0 = infinite, max 1 msg/sec)",
            if args.rounds == 0 {
                "infinite".to_string()
            } else {
                args.rounds.to_string()
            }
        );
        println!();

        let mut round = 0u32;
        let mut total_rtt_ms = 0u128;

        loop {
            round += 1;
            if args.rounds > 0 && round > args.rounds {
                break;
            }

            let rtt_start = Instant::now();

            // Alice -> Bob ping
            let ping_msg = format!("Ping #{round}");
            let ping_id = send_message(
                &alice_atm,
                &atm_alice,
                &atm_bob,
                &bob_mediator_did,
                &ping_msg,
            )
            .await?;

            match bob_atm
                .message_pickup()
                .live_stream_get(&atm_bob, &ping_id, Duration::from_secs(15), true)
                .await?
            {
                Some(_) => {}
                None => {
                    println!("  Round {round}: TIMEOUT waiting for ping");
                    continue;
                }
            }

            // Bob -> Alice pong
            let pong_msg = format!("Pong #{round}");
            let pong_id = send_message(
                &bob_atm,
                &atm_bob,
                &atm_alice,
                &alice_mediator_did,
                &pong_msg,
            )
            .await?;

            match alice_atm
                .message_pickup()
                .live_stream_get(&atm_alice, &pong_id, Duration::from_secs(15), true)
                .await?
            {
                Some(_) => {
                    let rtt = rtt_start.elapsed();
                    total_rtt_ms += rtt.as_millis();
                    let avg_rtt = total_rtt_ms / round as u128;
                    println!(
                        "  Round {round}: RTT = {}ms (avg: {}ms)",
                        rtt.as_millis(),
                        avg_rtt
                    );
                }
                None => {
                    println!("  Round {round}: TIMEOUT waiting for pong");
                    continue;
                }
            }

            // Rate limit: max 1 message per second
            let elapsed = rtt_start.elapsed();
            if elapsed < Duration::from_secs(1) {
                tokio::time::sleep(Duration::from_secs(1) - elapsed).await;
            }
        }

        if round > 1 {
            let completed = if args.rounds > 0 {
                round.min(args.rounds)
            } else {
                round - 1
            };
            println!();
            println!(
                "Ping-Pong complete: {} rounds, avg RTT: {}ms",
                completed,
                total_rtt_ms / completed as u128
            );
        }
    }

    println!();
    println!("=== Example complete ===");
    Ok(())
}

/// Send a message from sender to recipient through the recipient's mediator
async fn send_message(
    sender_atm: &affinidi_messaging_sdk::ATM,
    sender_profile: &std::sync::Arc<ATMProfile>,
    recipient_profile: &std::sync::Arc<ATMProfile>,
    recipient_mediator_did: &str,
    body_text: &str,
) -> Result<String, ATMError> {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let msg = Message::build(
        Uuid::new_v4().to_string(),
        "cross-mediator-test".to_string(),
        json!(body_text),
    )
    .to(recipient_profile.inner.did.clone())
    .from(sender_profile.inner.did.clone())
    .created_time(now)
    .expires_time(now + 60)
    .finalize();

    let msg_id = msg.id.clone();

    // Pack for recipient
    let packed_msg = sender_atm
        .pack_encrypted(
            &msg,
            &recipient_profile.inner.did,
            Some(&sender_profile.inner.did),
            Some(&sender_profile.inner.did),
        )
        .await?;

    // Wrap in forward envelope for the recipient's mediator
    let (_forward_id, forward_msg) = sender_atm
        .routing()
        .forward_message(
            sender_profile,
            false,
            &packed_msg.0,
            recipient_mediator_did,
            &recipient_profile.inner.did,
            None,
            None,
        )
        .await?;

    // Send via sender's mediator
    sender_atm
        .send_message(sender_profile, &forward_msg, &msg_id, false, false)
        .await?;

    Ok(msg_id)
}

/// Setup ACLs to allow Alice and Bob to communicate
async fn setup_acls(
    alice_atm: &affinidi_messaging_sdk::ATM,
    atm_alice: &std::sync::Arc<ATMProfile>,
    atm_bob: &std::sync::Arc<ATMProfile>,
    bob_atm: &affinidi_messaging_sdk::ATM,
) -> Result<(), ATMError> {
    // Get account info
    let alice_info = alice_atm
        .mediator()
        .account_get(atm_alice, None)
        .await?
        .expect("Alice account not found");

    let bob_info = bob_atm
        .mediator()
        .account_get(atm_bob, None)
        .await?
        .expect("Bob account not found");

    // Reset Alice ACLs
    let alice_acl_mode = MediatorACLSet::from_u64(alice_info.acls)
        .get_access_list_mode()
        .0;
    if let AccessListModeType::ExplicitAllow = alice_acl_mode {
        alice_atm
            .mediator()
            .access_list_add(atm_alice, None, &[&bob_info.did_hash])
            .await?;
    } else {
        alice_atm
            .mediator()
            .access_list_remove(atm_alice, None, &[&bob_info.did_hash])
            .await?;
    }

    // Reset Bob ACLs
    let bob_acl_mode = MediatorACLSet::from_u64(bob_info.acls)
        .get_access_list_mode()
        .0;
    if let AccessListModeType::ExplicitAllow = bob_acl_mode {
        bob_atm
            .mediator()
            .access_list_add(atm_bob, None, &[&alice_info.did_hash])
            .await?;
    } else {
        bob_atm
            .mediator()
            .access_list_remove(atm_bob, None, &[&alice_info.did_hash])
            .await?;
    }

    info!("ACLs configured for cross-mediator communication");
    Ok(())
}

//! Sends a message from Alice to Bob and then retrieves it.

use affinidi_messaging_didcomm::Message;
use affinidi_messaging_sdk::{
    ATM, config::ATMConfig, errors::ATMError, profiles::ATMProfile, protocols::Protocols,
};
use affinidi_tdk::common::{TDKSharedState, environments::TDKEnvironments};
use clap::Parser;
use serde_json::json;
use std::{
    env,
    time::{Duration, SystemTime},
};
use tracing::debug;
use tracing_subscriber::filter;
use uuid::Uuid;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Environment to use
    #[arg(short, long)]
    environment: Option<String>,

    /// Path to the environments file (defaults to environments.json)
    #[arg(short, long)]
    path_environments: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), ATMError> {
    let args: Args = Args::parse();

    let environment_name = if let Some(environment_name) = &args.environment {
        environment_name.to_string()
    } else if let Ok(environment_name) = env::var("TDK_ENVIRONMENT") {
        environment_name
    } else {
        "default".to_string()
    };

    let mut environment =
        TDKEnvironments::fetch_from_file(args.path_environments.as_deref(), &environment_name)?;
    println!("Using Environment: {}", environment_name);

    // construct a subscriber that prints formatted traces to stdout
    let subscriber = tracing_subscriber::fmt()
        // Use a more compact, abbreviated log format
        .with_env_filter(filter::EnvFilter::from_default_env())
        .finish();
    // use that subscriber to process traces emitted after this point
    tracing::subscriber::set_global_default(subscriber).expect("Logging failed, exiting...");

    let alice = if let Some(alice) = environment.profiles.get("Alice") {
        alice
    } else {
        return Err(ATMError::ConfigError(
            format!("Alice not found in Environment: {}", environment_name).to_string(),
        ));
    };

    let bob = if let Some(bob) = environment.profiles.get("Bob") {
        bob
    } else {
        return Err(ATMError::ConfigError(
            format!("Bob not found in Environment: {}", environment_name).to_string(),
        ));
    };

    let mut config = ATMConfig::builder();

    config = config.with_ssl_certificates(&mut environment.ssl_certificates);

    // Create a new ATM Client
    let tdk = TDKSharedState::default().await;
    let atm = ATM::new(config.build()?, tdk).await?;
    let protocols = Protocols::new();

    debug!("Enabling Alice's Profile");
    let alice = atm
        .profile_add(&ATMProfile::from_tdk_profile(&atm, alice).await?, true)
        .await?;

    debug!("Enabling Bob's Profile");
    let bob = atm
        .profile_add(&ATMProfile::from_tdk_profile(&atm, bob).await?, true)
        .await?;

    let start = SystemTime::now();

    // Ensure Environment has a valid mediator to forward through
    let mediator_did = if let Some(mediator) = environment.default_mediator {
        mediator.clone()
    } else {
        return Err(ATMError::ConfigError(
            "Environment Mediator not found".to_string(),
        ));
    };

    // Create message from Alice to Bob
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let msg = Message::build(
        Uuid::new_v4().into(),
        "Chatty Alice".into(),
        json!("Hello Bob!"),
    )
    .to(bob.inner.did.clone())
    .from(alice.inner.did.clone())
    .created_time(now)
    .expires_time(now + 10)
    .finalize();

    let msg_id = msg.id.clone();

    println!(
        "Plaintext Message from Alice to Bob msg_id({}):\n {:#?}",
        msg_id, msg
    );
    println!();

    let packed_msg = atm
        .pack_encrypted(
            &msg,
            &bob.inner.did,
            Some(&alice.inner.did),
            Some(&alice.inner.did),
        )
        .await?;

    println!(
        "Packed encrypted+signed message from Alice to Bob:\n{:#?}",
        packed_msg.0
    );

    println!();

    // Wrap it in a forward
    let (forward_id, forward_msg) = protocols
        .routing
        .forward_message(
            &atm,
            &alice,
            &packed_msg.0,
            &mediator_did,
            &bob.inner.did,
            None,
            None,
        )
        .await?;

    println!(
        "Forwarded message from Alice to Mediator:\n{:#?}",
        forward_msg
    );
    println!();

    // Send the message
    atm.send_message(&alice, &forward_msg, &forward_id, false, false)
        .await?;

    println!("Alice sent message to Bob");

    // Bob gets his messages
    println!();
    println!("Bob receiving messages");
    match protocols
        .message_pickup
        .live_stream_get(&atm, &bob, true, &msg_id, Duration::from_secs(5), true)
        .await?
    {
        Some(msg) => {
            println!();
            println!(
                "Decrypted Message from Alice to Bob msg_id({}):\n {:#?}\n",
                msg_id, msg.0
            );
        }
        None => {
            println!("No messages found. Exiting...");
        }
    }

    let end = SystemTime::now();
    println!(
        "Forwarding Example took {}ms in total",
        end.duration_since(start).unwrap().as_millis(),
    );

    Ok(())
}

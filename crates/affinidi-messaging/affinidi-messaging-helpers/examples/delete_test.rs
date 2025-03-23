use affinidi_messaging_didcomm::MessageBuilder;
use affinidi_messaging_sdk::{
    ATM,
    config::ATMConfig,
    errors::ATMError,
    messages::{DeleteMessageRequest, FetchDeletePolicy, Folder, fetch::FetchOptions},
    profiles::ATMProfile,
    protocols::Protocols,
};
use affinidi_tdk::common::{TDKSharedState, environments::TDKEnvironments};
use clap::Parser;
use serde_json::json;
use std::env;
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

    // Ensure Profile has a valid mediator to forward through
    let mediator_did = if let Some(mediator) = environment.default_mediator {
        mediator.clone()
    } else {
        return Err(ATMError::ConfigError(
            "Profile Mediator not found".to_string(),
        ));
    };

    // Delete all messages for Alice
    let response = atm
        .fetch_messages(
            &alice,
            &FetchOptions {
                limit: 100,
                delete_policy: FetchDeletePolicy::Optimistic,
                start_id: None,
            },
        )
        .await?;

    println!(
        "Alice existing messages ({}). Deleted all...",
        response.success.len()
    );

    // Delete all messages for Bob
    let response = atm
        .fetch_messages(
            &bob,
            &FetchOptions {
                limit: 100,
                delete_policy: FetchDeletePolicy::Optimistic,
                start_id: None,
            },
        )
        .await?;

    println!(
        "Bob existing messages ({}). Deleted all...",
        response.success.len()
    );

    // Send a message to Alice from Bob

    let message = MessageBuilder::new(
        Uuid::new_v4().to_string(),
        "test".to_string(),
        json!("Hello Alice"),
    )
    .from(bob.inner.did.clone())
    .to(alice.inner.did.clone())
    .finalize();

    let msg_id = message.id.clone();

    // Pack the message
    let packed = atm
        .pack_encrypted(
            &message,
            &alice.inner.did,
            Some(&bob.inner.did),
            Some(&bob.inner.did),
        )
        .await?;

    let forward = protocols
        .routing
        .forward_message(
            &atm,
            &bob,
            &packed.0,
            &mediator_did,
            &alice.inner.did,
            None,
            None,
        )
        .await?;

    println!(
        "Bob --> ALice msg_id({}) :: Bob --> Mediator forward msg_id({})",
        msg_id, forward.0,
    );

    atm.send_message(&bob, &forward.1, &forward.0, false, false)
        .await?;

    println!("Bob sent Alice a message");

    // See if Alice has a message waiting
    let response = atm.fetch_messages(&alice, &FetchOptions::default()).await?;

    println!(
        "Alice new message msg_id({})",
        response.success.first().unwrap().msg_id
    );

    let new_msg_id = response.success.first().unwrap().msg_id.clone();

    // See if Bob has a message waiting
    let response = atm.list_messages(&bob, Folder::Outbox).await?;

    println!(
        "Bob sent message msg_id({})",
        response.first().unwrap().msg_id
    );

    // Try to delete a fake message
    let response = atm
        .delete_messages_direct(
            &alice,
            &DeleteMessageRequest {
                message_ids: vec!["fake".to_string()],
            },
        )
        .await?;

    println!("Delete fake message: {:#?}", response);

    // Try to delete a real message
    let response = atm
        .delete_messages_direct(
            &alice,
            &DeleteMessageRequest {
                message_ids: vec![new_msg_id],
            },
        )
        .await?;

    println!("Deleted real message: {:#?}", response);

    Ok(())
}

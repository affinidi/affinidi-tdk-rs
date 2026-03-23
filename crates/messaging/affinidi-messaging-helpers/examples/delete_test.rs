use affinidi_messaging_didcomm::MessageBuilder;
use affinidi_messaging_sdk::{
    errors::ATMError,
    messages::{DeleteMessageRequest, FetchDeletePolicy, Folder, fetch::FetchOptions},
    profiles::ATMProfile,
    protocols::mediator::acls::{AccessListModeType, MediatorACLSet},
};
use affinidi_tdk::{TDK, common::config::TDKConfig};
use clap::Parser;
use serde_json::json;
use std::env;
use tracing::info;
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

    // construct a subscriber that prints formatted traces to stdout
    let subscriber = tracing_subscriber::fmt()
        // Use a more compact, abbreviated log format
        .with_env_filter(filter::EnvFilter::from_default_env())
        .finish();
    // use that subscriber to process traces emitted after this point
    tracing::subscriber::set_global_default(subscriber).expect("Logging failed, exiting...");

    // Instantiate TDK
    let tdk = TDK::new(
        TDKConfig::builder()
            .with_environment_name(environment_name.clone())
            .build()?,
        None,
    )
    .await?;

    let environment = &tdk.get_shared_state().environment;
    let atm = tdk.atm.clone().unwrap();

    // Activate Alice Profile
    let tdk_alice = if let Some(alice) = environment.profiles.get("Alice") {
        tdk.add_profile(alice).await;
        alice
    } else {
        return Err(ATMError::ConfigError(
            format!("Alice not found in Environment: {}", environment_name).to_string(),
        ));
    };

    let atm_alice = atm
        .profile_add(&ATMProfile::from_tdk_profile(&atm, tdk_alice).await?, true)
        .await?;

    let Some(alice_info) = atm.mediator().account_get(&atm_alice, None).await? else {
        panic!("Alice account not found on mediator");
    };

    info!("Alice profile active: {:?}", alice_info);
    let alice_acl_mode = MediatorACLSet::from_u64(alice_info.acls)
        .get_access_list_mode()
        .0;
    info!("Alice ACL Mode Type: {:?}", alice_acl_mode);

    // Activate Bob Profile
    let tdk_bob = if let Some(bob) = environment.profiles.get("Bob") {
        tdk.add_profile(bob).await;
        bob
    } else {
        return Err(ATMError::ConfigError(
            format!("Bob not found in Environment: {}", environment_name).to_string(),
        ));
    };
    let atm_bob = atm
        .profile_add(&ATMProfile::from_tdk_profile(&atm, tdk_bob).await?, true)
        .await?;

    let Some(bob_info) = atm.mediator().account_get(&atm_bob, None).await? else {
        panic!("Bob account not found on mediator");
    };

    info!("Bob profile active: {:?}", bob_info);
    let bob_acl_mode = MediatorACLSet::from_u64(bob_info.acls)
        .get_access_list_mode()
        .0;
    info!("Bob ACL Mode Type: {:?}", bob_acl_mode);

    // Reset ACL's as examples can get mixed up with back to back testing
    info!("Resetting Access Lists");

    // Reset Alice ACL's
    if let AccessListModeType::ExplicitAllow = alice_acl_mode {
        // Ensure Bob is added to Alice explicit allow list
        atm.mediator()
            .access_list_add(&atm_alice, None, &[&bob_info.did_hash])
            .await?;
    } else {
        // Ensure Bob is removed from Alice explicit deny list
        atm.mediator()
            .access_list_remove(&atm_alice, None, &[&bob_info.did_hash])
            .await?;
    }
    info!("Alice Access Lists reset");

    // Reset Bob ACL's
    if let AccessListModeType::ExplicitAllow = bob_acl_mode {
        // Ensure Bob is added to Bob explicit allow list
        atm.mediator()
            .access_list_add(&atm_bob, None, &[&alice_info.did_hash])
            .await?;
    } else {
        // Ensure Bob is removed from Bob explicit deny list
        atm.mediator()
            .access_list_remove(&atm_bob, None, &[&alice_info.did_hash])
            .await?;
    }
    info!("Bob Access Lists reset");

    // Ensure Profile has a valid mediator to forward through
    let mediator_did = if let Some(mediator) = &environment.default_mediator {
        mediator.to_string()
    } else {
        return Err(ATMError::ConfigError(
            "Profile Mediator not found".to_string(),
        ));
    };

    // Delete all messages for Alice
    let response = atm
        .fetch_messages(
            &atm_alice,
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
            &atm_bob,
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
    .from(atm_bob.inner.did.clone())
    .to(atm_alice.inner.did.clone())
    .finalize();

    let msg_id = message.id.clone();

    // Pack the message
    let packed = atm
        .pack_encrypted(
            &message,
            &atm_alice.inner.did,
            Some(&atm_bob.inner.did),
            Some(&atm_bob.inner.did),
            None,
        )
        .await?;

    let forward = atm
        .routing()
        .forward_message(
            &atm_bob,
            false,
            &packed.0,
            &mediator_did,
            &atm_alice.inner.did,
            None,
            None,
        )
        .await?;

    println!(
        "Bob --> ALice msg_id({}) :: Bob --> Mediator forward msg_id({})",
        msg_id, forward.0,
    );

    atm.send_message(&atm_bob, &forward.1, &forward.0, false, false)
        .await?;

    println!("Bob sent Alice a message");

    // See if Alice has a message waiting
    let response = atm
        .fetch_messages(&atm_alice, &FetchOptions::default())
        .await?;

    if response.success.is_empty() {
        println!("Alice has no messages");
        return Ok(());
    } else {
        println!(
            "Alice has messages: {:#?}",
            response.success.first().unwrap().msg_id
        );
    }

    let new_msg_id = response.success.first().unwrap().msg_id.clone();

    // See if Bob has a message waiting
    let response = atm.list_messages(&atm_bob, Folder::Outbox).await?;

    println!(
        "Bob sent message msg_id({})",
        response.first().unwrap().msg_id
    );

    // Try to delete a fake message
    let response = atm
        .delete_messages_direct(
            &atm_alice,
            &DeleteMessageRequest {
                message_ids: vec!["fake".to_string()],
            },
        )
        .await?;

    println!("Delete fake message: {:#?}", response);

    // Try to delete a real message
    let response = atm
        .delete_messages_direct(
            &atm_alice,
            &DeleteMessageRequest {
                message_ids: vec![new_msg_id],
            },
        )
        .await?;

    println!("Deleted real message: {:#?}", response);

    Ok(())
}

//! Sends a message from Alice to Bob and then retrieves it.

use affinidi_messaging_didcomm::{Message, PackEncryptedOptions};
use affinidi_messaging_sdk::{
    errors::ATMError,
    profiles::ATMProfile,
    protocols::{Protocols, mediator::acls::MediatorACLSet},
};
use affinidi_tdk::{TDK, common::config::TDKConfig};
use clap::Parser;
use serde_json::json;
use sha256::digest;
use std::{
    env,
    time::{Duration, SystemTime},
};
use tracing::{error, info};
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

    println!("Using Environment: {}", environment_name);

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
    let protocols = Protocols::new();

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

    let Some(alice_info) = protocols
        .mediator
        .account_get(&atm, &atm_alice, None)
        .await?
    else {
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

    // Reset ACL's as examples can get mixed up with back to back testing
    info!("Resetting Access Lists");

    // Override Alice ACL to enable send_forwarded
    // let mut new_acls = MediatorACLSet::from_u64(alice_info.acls);
    // let _ = new_acls.set_send_forwarded(false, false, true);

    // protocols
    //         .mediator
    //         .acls_set(&atm, &atm_alice, &alice_info.did_hash, &new_acls)
    //         .await?;

    let start = SystemTime::now();

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
    .to(atm_bob.inner.did.clone())
    .from(atm_alice.inner.did.clone())
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
            &atm_bob.inner.did,
            Some(&atm_alice.inner.did),
            Some(&atm_alice.inner.did),
            None,
        )
        .await?;

    println!(
        "Packed encrypted+signed message from Alice to Bob:\n{:#?}",
        packed_msg.0
    );

    let sent_digest = digest(&packed_msg.0);
    println!("TIMTAM: digest of packed message: {}", sent_digest);

    println!();

    // Wrap it in a forward
    // let bobs_mediator_did = tdk_bob.mediator.to_owned().unwrap();
    // let (_forward_id, forward_msg) = protocols
    //     .routing
    //     .forward_message(
    //         &atm,
    //         &atm_alice,
    //         false,
    //         &packed_msg.0,
    //         &bobs_mediator_did,
    //         &atm_bob.inner.did,
    //         None,
    //         None,
    //     )
    //     .await?;

    // println!(
    //     "Forwarded message from Alice to Mediator:\n{:#?}",
    //     forward_msg
    // );
    // println!();

    // Send the message
    match atm
        .send_message(&atm_alice, &packed_msg.0, &msg_id, false, false)
        .await
    {
        Ok(_) => {
            info!("Alice sent message to Mediator");
        }
        Err(e) => {
            error!("Error sending message: {:?}", e);
            return Ok(());
        }
    }

    // Bob gets his messages
    println!("trying to get msg_id: {}", msg_id);
    println!("Bob receiving messages");
    match protocols
        .message_pickup
        .live_stream_get(&atm, &atm_bob, &msg_id, Duration::from_secs(10), true)
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
        "Sending Example took {}ms in total",
        end.duration_since(start).unwrap().as_millis(),
    );

    // You can omit this, but may get an error as the status-report for the message delete will come in after secrets manager has been shutdown
    tokio::time::sleep(Duration::from_secs(1)).await;
    println!("Exiting...");

    Ok(())
}

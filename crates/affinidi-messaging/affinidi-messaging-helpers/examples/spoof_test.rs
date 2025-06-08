//! Tries to Spoof a message from Mallory to Bob, but pretending to be Alice.
//! Mallory send to Bob, but inner envelope pretends to be Alice

use affinidi_messaging_didcomm::Message;
use affinidi_messaging_sdk::{
    errors::ATMError,
    profiles::ATMProfile,
    protocols::{
        Protocols,
        mediator::acls::{AccessListModeType, MediatorACLSet},
    },
};
use affinidi_tdk::{TDK, common::config::TDKConfig};
use clap::Parser;
use serde_json::json;
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

    let Some(bob_info) = protocols.mediator.account_get(&atm, &atm_bob, None).await? else {
        panic!("Bob account not found on mediator");
    };

    info!("Bob profile active: {:?}", bob_info);
    let bob_acl_mode = MediatorACLSet::from_u64(bob_info.acls)
        .get_access_list_mode()
        .0;
    info!("Bob ACL Mode Type: {:?}", bob_acl_mode);

    // Activate Mallory Profile
    let tdk_mallory = if let Some(mallory) = environment.profiles.get("Mallory") {
        tdk.add_profile(mallory).await;
        mallory
    } else {
        return Err(ATMError::ConfigError(
            format!("Mallory not found in Environment: {}", environment_name).to_string(),
        ));
    };

    let atm_mallory = atm
        .profile_add(
            &ATMProfile::from_tdk_profile(&atm, tdk_mallory).await?,
            true,
        )
        .await?;

    let Some(mallory_info) = protocols
        .mediator
        .account_get(&atm, &atm_mallory, None)
        .await?
    else {
        panic!("Mallory account not found on mediator");
    };

    info!("Mallory profile active: {:?}", mallory_info);
    let mallory_acl_mode = MediatorACLSet::from_u64(mallory_info.acls)
        .get_access_list_mode()
        .0;
    info!("Mallory ACL Mode Type: {:?}", mallory_acl_mode);

    // Reset ACL's as examples can get mixed up with back to back testing
    info!("Resetting Access Lists");

    // Reset Alice ACL's (who has no access to either Bob or Mallory)
    if let AccessListModeType::ExplicitAllow = alice_acl_mode {
        // Ensure Bob and Mallory are removed from explicit allow list
        protocols
            .mediator
            .access_list_remove(&atm, &atm_alice, None, &[&mallory_info.did_hash])
            .await?;
    } else {
        // Ensure Mallory is removed from Bob explicit deny list
        protocols
            .mediator
            .access_list_add(
                &atm,
                &atm_alice,
                None,
                &[&bob_info.did_hash, &mallory_info.did_hash],
            )
            .await?;
    }
    info!("Alice Access Lists reset");

    // Reset Bob ACL's
    if let AccessListModeType::ExplicitAllow = bob_acl_mode {
        // Ensure Mallory is added to Bob explicit allow list
        protocols
            .mediator
            .access_list_add(&atm, &atm_bob, None, &[&mallory_info.did_hash])
            .await?;
    } else {
        // Ensure Mallory is removed from Bob explicit deny list
        protocols
            .mediator
            .access_list_remove(&atm, &atm_bob, None, &[&mallory_info.did_hash])
            .await?;
    }
    info!("Bob Access Lists reset");

    // Reset Mallory ACL's
    if let AccessListModeType::ExplicitAllow = mallory_acl_mode {
        // Ensure Bob is added to Mallory explicit allow list
        protocols
            .mediator
            .access_list_add(&atm, &atm_mallory, None, &[&bob_info.did_hash])
            .await?;
    } else {
        // Ensure Bob is removed from Mallory explicit deny list
        protocols
            .mediator
            .access_list_remove(&atm, &atm_mallory, None, &[&bob_info.did_hash])
            .await?;
    }
    info!("Mallory Access Lists reset");

    let start = SystemTime::now();

    // Create message from Mallory to Bob
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let msg = Message::build(
        Uuid::new_v4().into(),
        "Naughty Mallory".into(),
        json!("I am trying to be Alice!"),
    )
    .to(atm_bob.inner.did.clone())
    .from(atm_alice.inner.did.clone())
    .created_time(now)
    .expires_time(now + 10)
    .finalize();

    let msg_id = msg.id.clone();

    println!(
        "Plaintext Message from Mallory to Bob msg_id({}):\n {:#?}",
        msg_id, msg
    );
    println!();

    let packed_msg = atm
        .pack_encrypted(
            &msg,
            &atm_bob.inner.did,
            Some(&atm_mallory.inner.did),
            Some(&atm_mallory.inner.did),
            None,
        )
        .await?;

    println!(
        "Packed encrypted+signed message from Mallory to Bob:\n{:#?}",
        packed_msg.0
    );

    println!();

    // Wrap it in a forward
    let bobs_mediator_did = tdk_bob.mediator.to_owned().unwrap();
    let (_forward_id, forward_msg) = protocols
        .routing
        .forward_message(
            &atm,
            &atm_mallory,
            false,
            &packed_msg.0,
            &bobs_mediator_did,
            &atm_bob.inner.did,
            None,
            None,
        )
        .await?;

    println!(
        "Forwarded message from Mallory to Mediator:\n{:#?}",
        forward_msg
    );
    println!();

    // Send the message
    match atm
        .send_message(&atm_mallory, &forward_msg, &msg_id, false, false)
        .await
    {
        Ok(_) => {
            info!("Mallory sent message to Mediator");
        }
        Err(e) => {
            error!("Error sending message: {:?}", e);
            return Ok(());
        }
    }

    // Bob gets his messages
    println!();
    println!("Bob receiving messages");
    match protocols
        .message_pickup
        .live_stream_get(&atm, &atm_bob, &msg_id, Duration::from_secs(5), true)
        .await?
    {
        Some(msg) => {
            println!();
            println!(
                "Decrypted Message from Mallory to Bob msg_id({}):\n {:#?}\n",
                msg_id, msg.0
            );
            println!("Metadata:\n {:#?}\n", msg.1);
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

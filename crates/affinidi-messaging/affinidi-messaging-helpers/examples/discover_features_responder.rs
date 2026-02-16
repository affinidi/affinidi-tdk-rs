//! Example Discover Features 2.0 responder using the Affinidi Trust Messaging SDK
//!
//! Listens for incoming discover-features query messages via WebSocket and
//! responds with a disclosure of the features this agent supports.
//!
//! Press Ctrl+C to stop listening.

use affinidi_messaging_sdk::{
    ATM,
    config::ATMConfig,
    errors::ATMError,
    profiles::ATMProfile,
    protocols::discover_features::DiscoverFeatures,
};
use affinidi_tdk::common::{TDKSharedState, environments::TDKEnvironments};
use clap::Parser;
use std::{env, sync::Arc, time::Duration};
use tracing::{debug, error, info};
use tracing_subscriber::filter;

const QUERIES_TYPE: &str = "https://didcomm.org/discover-features/2.0/queries";

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Environment to use
    #[arg(short, long)]
    environment: Option<String>,

    /// Path to the environments file (defaults to environments.json)
    #[arg(short, long)]
    path_environments: Option<String>,

    /// Additional protocols to advertise (comma-separated URIs)
    #[arg(long, value_delimiter = ',')]
    protocols: Vec<String>,

    /// Goal codes to advertise (comma-separated)
    #[arg(long, value_delimiter = ',')]
    goal_codes: Vec<String>,

    /// Headers to advertise (comma-separated)
    #[arg(long, value_delimiter = ',')]
    headers: Vec<String>,
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

    // Instantiate TDK
    let tdk = Arc::new(TDKSharedState::default().await);

    // Configure tracing
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(filter::EnvFilter::from_default_env())
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("Logging failed, exiting...");

    let alice = if let Some(alice) = environment.profiles.get("Alice") {
        tdk.add_profile(alice).await;
        alice
    } else {
        return Err(ATMError::ConfigError(
            format!("Alice not found in Profile: {}", environment_name).to_string(),
        ));
    };

    // Build the discoverable features
    let mut protocols = vec![
        "https://didcomm.org/trust-ping/2.0".to_string(),
        "https://didcomm.org/discover-features/2.0".to_string(),
        "https://didcomm.org/messagepickup/3.0".to_string(),
    ];
    protocols.extend(args.protocols);

    let features = DiscoverFeatures {
        protocols,
        goal_codes: args.goal_codes,
        headers: args.headers,
    };

    println!("Advertising features:");
    println!("  Protocols:");
    for p in &features.protocols {
        println!("    {}", p);
    }
    if !features.goal_codes.is_empty() {
        println!("  Goal codes:");
        for g in &features.goal_codes {
            println!("    {}", g);
        }
    }
    if !features.headers.is_empty() {
        println!("  Headers:");
        for h in &features.headers {
            println!("    {}", h);
        }
    }

    let mut config = ATMConfig::builder();
    config = config
        .with_ssl_certificates(&mut environment.ssl_certificates)
        .with_discovery_features(features);

    // Create a new ATM Client
    let atm = ATM::new(config.build()?, tdk).await?;

    debug!("Enabling Alice's Profile");
    let alice = atm
        .profile_add(&ATMProfile::from_tdk_profile(&atm, alice).await?, false)
        .await?;

    let (my_did, _) = alice.dids()?;
    println!("\nListening as: {}", my_did);
    println!("Waiting for discover-features queries (Ctrl+C to stop)...\n");

    // Enable WebSocket for live message streaming
    atm.profile_enable_websocket(&alice).await?;

    // Listen loop
    loop {
        let response = atm
            .message_pickup()
            .live_stream_next(&alice, Some(Duration::from_secs(30)), true)
            .await?;

        let Some((msg, _metadata)) = response else {
            debug!("No message received, continuing to listen...");
            continue;
        };

        if msg.type_ != QUERIES_TYPE {
            debug!("Ignoring non-query message: {}", msg.type_);
            continue;
        }

        let from_did = match &msg.from {
            Some(from) => from.clone(),
            None => {
                error!("Received anonymous query, cannot respond (no from DID)");
                continue;
            }
        };

        info!("Received discover-features query from: {}", from_did);

        // Generate the disclosure from our configured state
        let state = atm.discover_features().get_discoverable_state();
        let features = state.read().await;
        let disclosure_msg =
            features.generate_disclosure_message(my_did, &from_did, &msg, None)?;
        drop(features);

        let disclosure_id = disclosure_msg.id.clone();
        debug!("Disclosure message: {:#?}", disclosure_msg);

        // Pack the disclosure for the querier
        let (packed_msg, _) = atm
            .pack_encrypted(
                &disclosure_msg,
                &from_did,
                Some(my_did),
                Some(my_did),
                None,
            )
            .await?;

        // Send the disclosure back
        atm.send_message(&alice, &packed_msg, &disclosure_id, false, true)
            .await?;

        println!("Sent disclosure response to: {}", from_did);
    }
}

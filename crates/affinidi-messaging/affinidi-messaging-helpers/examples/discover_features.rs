//! Example Discover Features 2.0 query using the Affinidi Trust Messaging SDK
//! Sends a discover-features query to a remote DID and displays the disclosure response.
//! Uses HTTPS to send the query and fetch the response.

use affinidi_messaging_sdk::{
    ATM,
    config::ATMConfig,
    errors::ATMError,
    messages::{FetchDeletePolicy, fetch::FetchOptions, sending::InboundMessageResponse},
    profiles::ATMProfile,
    protocols::discover_features::{
        DiscoverFeaturesDisclosure, DiscoverFeaturesQuery, FeatureType, Query,
    },
    transports::SendMessageResponse,
};
use affinidi_tdk::common::{TDKSharedState, environments::TDKEnvironments};
use clap::Parser;
use sha256::digest;
use std::{env, sync::Arc};
use tracing::{debug, error, info};
use tracing_subscriber::filter;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Environment to use
    #[arg(short, long)]
    environment: Option<String>,

    /// Path to the environments file (defaults to environments.json)
    #[arg(short, long)]
    path_environments: Option<String>,

    /// Remote DID to query
    #[arg(short, long)]
    did: String,

    /// Feature type to query: protocol, goal-code, or header
    #[arg(short, long, default_value = "protocol")]
    feature_type: String,

    /// Match pattern (supports trailing wildcard, e.g. "*" or "https://didcomm.org/trust-ping/*")
    #[arg(short, long, default_value = "*")]
    match_pattern: String,
}

fn parse_feature_type(s: &str) -> Result<FeatureType, ATMError> {
    match s {
        "protocol" => Ok(FeatureType::Protocol),
        "goal-code" | "goal_code" => Ok(FeatureType::GoalCode),
        "header" => Ok(FeatureType::Header),
        other => Err(ATMError::ConfigError(format!(
            "Unknown feature type: '{}'. Expected: protocol, goal-code, or header",
            other
        ))),
    }
}

#[tokio::main]
async fn main() -> Result<(), ATMError> {
    let args: Args = Args::parse();

    let feature_type = parse_feature_type(&args.feature_type)?;

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

    let bob = if let Some(bob) = environment.profiles.get("Bob") {
        tdk.add_profile(bob).await;
        bob
    } else {
        return Err(ATMError::ConfigError(
            format!("Bob not found in Profile: {}", environment_name).to_string(),
        ));
    };

    let mut config = ATMConfig::builder();
    config = config.with_ssl_certificates(&mut environment.ssl_certificates);

    // Create a new ATM Client
    let atm = ATM::new(config.build()?, tdk).await?;

    debug!("Enabling Bob's Profile");
    let bob = atm
        .profile_add(&ATMProfile::from_tdk_profile(&atm, bob).await?, false)
        .await?;

    // Get Bob's DID
    let (from_did, _) = bob.dids()?;

    println!("Sending discover-features query to: {}", args.did);
    println!(
        "  feature_type: {}, match: {}",
        feature_type, args.match_pattern
    );

    // Delete all existing messages for Bob
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

    // Generate the discover-features query message
    let msg = atm.discover_features().generate_query_message(
        from_did,
        &args.did,
        DiscoverFeaturesQuery {
            queries: vec![Query {
                feature_type,
                match_: args.match_pattern.clone(),
            }],
        },
    )?;

    let msg_id = msg.id.clone();
    debug!("Query message: {:#?}", msg);

    // Pack the message
    let (packed_msg, _) = atm
        .pack_encrypted(&msg, &args.did, Some(from_did), Some(from_did), None)
        .await?;

    let msg_hash = digest(&packed_msg);
    info!(
        "Packed query message: id={}, hash={}, bytes={}",
        msg_id,
        msg_hash,
        packed_msg.len()
    );

    // Send the packed message
    let response = atm
        .send_message(&bob, &packed_msg, &msg_id, false, true)
        .await?;

    if let SendMessageResponse::RestAPI(response) = response {
        let a: InboundMessageResponse =
            match serde_json::from_value(response.get("data").unwrap().to_owned()) {
                Ok(a) => a,
                Err(e) => {
                    error!("Error parsing response: {}", e);
                    return Ok(());
                }
            };

        if let InboundMessageResponse::Stored(_) = a {
            info!("Query message stored at mediator");
        } else {
            error!("Expected a Stored response");
            return Ok(());
        }
    } else {
        error!("Expected a RestAPI response");
        return Ok(());
    }

    // Fetch the disclosure response
    let msgs = atm
        .fetch_messages(
            &bob,
            &FetchOptions {
                limit: 10,
                delete_policy: FetchDeletePolicy::Optimistic,
                start_id: None,
            },
        )
        .await?;

    debug!("Fetched {} messages", msgs.success.len());

    // Unpack and look for disclosure messages
    let mut found_disclosure = false;
    for msg in msgs.success {
        if let Some(raw) = &msg.msg {
            let (unpacked, _) = atm.unpack(raw).await?;
            if unpacked.type_ == "https://didcomm.org/discover-features/2.0/disclose" {
                found_disclosure = true;
                match serde_json::from_value::<DiscoverFeaturesDisclosure>(unpacked.body) {
                    Ok(disclosure) => {
                        println!("\nDisclosure received:");
                        if disclosure.disclosures.is_empty() {
                            println!("  (no matching features disclosed)");
                        } else {
                            for d in &disclosure.disclosures {
                                println!("  {} : {}", d.feature_type, d.id);
                            }
                        }
                    }
                    Err(e) => {
                        error!("Failed to parse disclosure body: {}", e);
                    }
                }
            } else {
                debug!("Skipping non-disclosure message: {}", unpacked.type_);
            }
        }
    }

    if !found_disclosure {
        println!("\nNo disclosure response received yet. The remote agent may not have responded.");
    }

    atm.graceful_shutdown().await;
    Ok(())
}

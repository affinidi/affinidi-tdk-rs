/*!
 * Example of how to check an offer on Meeting Place
 */

use std::env;

use affinidi_did_authentication::DIDAuthentication;
use affinidi_meeting_place::errors::{MeetingPlaceError, Result};
use affinidi_tdk_common::{TDKSharedState, environments::TDKEnvironments};
use clap::{Parser, Subcommand};
use tracing_subscriber::filter;

/// Affinidi Meeting Place Check-Offer
#[derive(Parser)]
#[command(name = "meeting_place")]
#[command(bin_name = "meeting_place")]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Environment to use
    #[arg(short, long)]
    environment: Option<String>,

    /// Path to the environments file (defaults to environments.json)
    #[arg(short, long)]
    path_environments: Option<String>,

    /// Profile Name to use from the environment
    #[arg(short, long)]
    name_profile: Option<String>,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Check-Offer-Phrase
    CheckOfferPhrase(OfferPhraseArgs),
}

#[derive(Debug, Parser)]
#[command(version, about, long_about = None)]
struct OfferPhraseArgs {
    /// Meeting Place Offer Phrase
    #[arg(short, long)]
    phrase: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let args = Cli::parse();

    // construct a subscriber that prints formatted traces to stdout
    let subscriber = tracing_subscriber::fmt()
        // Use a more compact, abbreviated log format
        .with_env_filter(filter::EnvFilter::from_default_env())
        .finish();
    // use that subscriber to process traces emitted after this point
    tracing::subscriber::set_global_default(subscriber).expect("Logging failed, exiting...");

    let tdk = TDKSharedState::default().await;

    let environment_name = if let Some(environment_name) = &args.environment {
        environment_name.to_string()
    } else if let Ok(environment_name) = env::var("TDK_ENVIRONMENT") {
        environment_name
    } else {
        "default".to_string()
    };

    let environment =
        TDKEnvironments::fetch_from_file(args.path_environments.as_deref(), &environment_name)?;
    println!("Using Environment: {}", environment_name);

    let environment_profile = if let Some(profile_name) = &args.name_profile {
        let Some(profile) = environment.profiles.get(profile_name) else {
            return Err(MeetingPlaceError::TDK(format!(
                "Profile ({}) not found in environment ({})",
                profile_name, environment_name
            )));
        };
        tdk.add_profile(profile).await;
        profile
    } else if let Ok(profile_name) = env::var("TDK_PROFILE") {
        let Some(profile) = environment.profiles.get(&profile_name) else {
            return Err(MeetingPlaceError::TDK(format!(
                "Profile ({}) not found in environment ({})",
                profile_name, environment_name
            )));
        };
        tdk.add_profile(profile).await;
        profile
    } else if let Some(profile) = environment.profiles.values().next() {
        tdk.add_profile(profile).await;
        profile
    } else {
        return Err(MeetingPlaceError::TDK(format!(
            "No profiles found in environment ({})",
            environment_name
        )));
    };

    match args.command {
        Commands::CheckOfferPhrase(check_offer_phrase) => {}
    };

    Ok(())
}

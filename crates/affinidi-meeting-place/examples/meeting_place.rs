/*!
 * Example of how to check an offer on Meeting Place
 */

use affinidi_meeting_place::{
    MeetingPlace,
    errors::{MeetingPlaceError, Result},
    offers::{Offer, RegisterOffer},
};
use affinidi_tdk_common::{TDKSharedState, environments::TDKEnvironments};
use clap::{Parser, Subcommand};
use std::env;
use tracing::info;
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

    /// DID for MeetingPlace
    #[arg(short, long)]
    mp_did: String,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Check-Offer-Phrase
    CheckOfferPhrase(OfferPhraseArgs),

    /// Register-Offer
    RegisterOffer(Box<RegisterOfferArgs>),
}

#[derive(Debug, Parser)]
#[command(version, about, long_about = None)]
struct OfferPhraseArgs {
    /// Meeting Place Offer Phrase
    #[arg(short, long)]
    phrase: String,
}

#[derive(Debug, Parser)]
#[command(version, about, long_about = None)]
struct RegisterOfferArgs {
    /// Friendly UX Name for the offer
    #[arg(long)]
    offer_name: String,

    /// Description for the offer
    #[arg(long)]
    description: String,

    /// Mediator DID (will use default Environment if not specified)
    #[arg(long)]
    mediator_did: Option<String>,

    /// (Optional) Surname of the contact person
    #[arg(long)]
    contact_surname: Option<String>,

    /// (Optional) Given name of the contact person
    #[arg(long)]
    contact_given_name: Option<String>,

    /// (Optional) Email of the contact person
    #[arg(long)]
    contact_email: Option<String>,

    /// (Optional) Phone number of the contact person
    #[arg(long)]
    contact_phone: Option<String>,

    #[arg(long)]
    /// (Optional) ISO-8601 date-time (2024-12-31T23:59:59Z)
    valid_until: Option<String>,

    #[arg(long)]
    /// (Optional) Maximum number of times the offer can be used
    maximum_usage: Option<usize>,

    /// (Optional) Push notification token for the device
    #[arg(long)]
    device_token: Option<String>,

    /// (Optional) Platform Type
    #[arg(long)]
    platform_type: Option<u32>,

    /// (Optional) Custom Offer Phrase
    #[arg(long)]
    custom_phrase: Option<String>,

    /// (Optional) Contact Attributes
    #[arg(long)]
    contact_attributes: Option<u32>,
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

    let mp = MeetingPlace::new(args.mp_did);
    match args.command {
        Commands::CheckOfferPhrase(check_offer_phrase) => {
            let result = mp
                .check_offer_phrase(
                    &tdk,
                    environment_profile.clone(),
                    &check_offer_phrase.phrase,
                )
                .await?;
            info!("Offer Phrase is in use? {}", result);
        }
        Commands::RegisterOffer(register_offer) => {
            let mediator_did = if let Some(mediator_did) = register_offer.mediator_did {
                mediator_did
            } else if let Some(mediator_did) = &environment_profile.mediator {
                mediator_did.to_string()
            } else {
                return Err(MeetingPlaceError::TDK(
                    "No mediator DID specified and no default mediator in profile".to_string(),
                ));
            };

            let mut offer_details = RegisterOffer::create(
                &register_offer.offer_name,
                &register_offer.description,
                &environment_profile.did,
                &mediator_did,
            )?;

            if let Some(custom_phrase) = register_offer.custom_phrase {
                offer_details.custom_phrase(&custom_phrase);
            }

            let offer_details = offer_details.build(&tdk).await?;

            let mut offer = Offer::new_from_register_offer(offer_details);
            offer.register_offer(&mp, &tdk, environment_profile).await?;
            info!("Offer registered: {:#?}", offer.offer_details);
        }
    };

    Ok(())
}

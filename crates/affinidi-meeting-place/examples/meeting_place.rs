/*!
 * Example of how to check an offer on Meeting Place
 */

use affinidi_meeting_place::{
    MeetingPlace,
    errors::{MeetingPlaceError, Result},
    offers::{ContactAttributeType, Offer, PlatformType, RegisterOffer},
    vcard::Vcard,
};
use affinidi_tdk_common::{TDKSharedState, environments::TDKEnvironments, profiles::TDKProfile};
use clap::{Parser, Subcommand};
use std::{env, str::FromStr};
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
    /// Check-Offer
    Check(OfferPhraseArgs),

    /// Query-Offer-Phrase
    Query(OfferPhraseArgs),

    /// Register-Offer
    Register(Box<RegisterOfferArgs>),

    /// Deregister-Offer
    Deregister(OfferPhraseArgs),
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

    /// (Optional) Platform Type (APNS, APNS_SANDBOX, FCM, NONE)
    #[arg(long)]
    platform_type: Option<String>,

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
        Commands::Check(check_offer_phrase) => {
            let result = mp
                .check_offer_phrase(
                    &tdk,
                    environment_profile.clone(),
                    &check_offer_phrase.phrase,
                )
                .await?;
            info!("Offer Phrase is in use? {}", result);
        }
        Commands::Register(register_offer) => {
            let offer_details =
                _create_register_offer(&tdk, &register_offer, environment_profile).await?;

            let mut offer = Offer::new_from_register_offer(offer_details);
            let response = offer.register_offer(&mp, &tdk, environment_profile).await?;
            info!("Offer registered: {:#?}", response);
        }
        Commands::Query(query_offer) => {
            let result =
                Offer::query_offer(&mp, &tdk, environment_profile, &query_offer.phrase).await?;
            info!("Offer result: {:#?}", result);
        }
        Commands::Deregister(query_offer) => {
            let mut offer =
                Offer::query_offer(&mp, &tdk, environment_profile, &query_offer.phrase).await?;

            let result = offer
                .deregister_offer(&mp, &tdk, environment_profile)
                .await?;
            info!("Deregister result: {:#?}", result);
        }
    };

    Ok(())
}

/// Converts the CLI Arguments to a RegisterOffer
async fn _create_register_offer(
    tdk: &TDKSharedState,
    args: &RegisterOfferArgs,
    profile: &TDKProfile,
) -> Result<RegisterOffer> {
    let mediator_did = if let Some(mediator_did) = &args.mediator_did {
        mediator_did.to_owned()
    } else if let Some(mediator_did) = &profile.mediator {
        mediator_did.to_string()
    } else {
        return Err(MeetingPlaceError::TDK(
            "No mediator DID specified and no default mediator in profile".to_string(),
        ));
    };

    let mut offer_details = RegisterOffer::create(
        &args.offer_name,
        &args.description,
        &profile.did,
        &mediator_did,
    )?;

    // Create the vcard
    offer_details.vcard(Vcard::new(
        args.contact_given_name.clone(),
        args.contact_surname.clone(),
        args.contact_email.clone(),
        args.contact_phone.clone(),
    ));

    if let Some(valid_until) = &args.valid_until {
        let valid_until = chrono::DateTime::parse_from_rfc3339(valid_until)
            .map_err(|err| MeetingPlaceError::Error(format!("invalid valid_until timestamp. Must be in ISO 8601 format (2025-03-17T09:00:00-00:00)! Reason: {}", err)))?.to_utc();

        let now = chrono::Utc::now();
        let delta = valid_until - now;
        if delta.num_seconds() <= 0 {
            return Err(MeetingPlaceError::Error(
                "valid_until timestamp must be in the future".to_string(),
            ));
        }

        offer_details.valid_until(delta.to_std().map_err(|err| {
            MeetingPlaceError::Error(format!("invalid valid_until timestamp. Reason: {}", err))
        })?);
    }

    if let Some(maximum_usage) = args.maximum_usage {
        offer_details.maximum_usage(maximum_usage);
    }

    if let Some(device_token) = &args.device_token {
        offer_details.device_token(device_token);
    }

    if let Some(platform_type) = &args.platform_type {
        offer_details.platform_type(PlatformType::from_str(platform_type)?);
    }

    if let Some(contact_attributes) = args.contact_attributes {
        offer_details.contact_attributes(ContactAttributeType::from_u32(contact_attributes));
    }

    if let Some(custom_phrase) = &args.custom_phrase {
        offer_details.custom_phrase(custom_phrase);
    }

    offer_details.build(tdk).await
}

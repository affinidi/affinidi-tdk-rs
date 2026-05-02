/*!
 * Demonstrates the four core Meeting Place flows: check, query, register,
 * deregister an offer phrase. Loads its identity from a TDKEnvironments file.
 */

use affinidi_meeting_place::{
    MeetingPlace,
    errors::{MeetingPlaceError, Result},
    offers::{ContactAttributeType, Offer, PlatformType, RegisterOffer},
    vcard::Vcard,
};
use affinidi_tdk_common::{
    TDKSharedState, config::TDKConfig, environments::TDKEnvironments, profiles::TDKProfile,
};
use clap::{Parser, Subcommand};
use std::{env, str::FromStr};
use tracing::info;
use tracing_subscriber::filter;

#[derive(Parser)]
#[command(name = "meeting_place", bin_name = "meeting_place")]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Environment to use (defaults to `$TDK_ENVIRONMENT` or `"default"`).
    #[arg(short, long)]
    environment: Option<String>,

    /// Path to the environments file (defaults to `environments.json`).
    #[arg(short, long)]
    path_environments: Option<String>,

    /// Profile alias from the environment (defaults to `$TDK_PROFILE`, then
    /// the first profile in the environment).
    #[arg(short, long)]
    name_profile: Option<String>,

    /// DID for Meeting Place service.
    #[arg(short, long)]
    mp_did: String,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Check whether an offer phrase is in use.
    Check(OfferPhraseArgs),

    /// Query an offer by its phrase.
    Query(OfferPhraseArgs),

    /// Register a new offer.
    Register(Box<RegisterOfferArgs>),

    /// Deregister an offer by its phrase.
    Deregister(OfferPhraseArgs),
}

#[derive(Debug, Parser)]
struct OfferPhraseArgs {
    /// Meeting Place offer phrase.
    #[arg(short, long)]
    phrase: String,
}

#[derive(Debug, Parser)]
struct RegisterOfferArgs {
    #[arg(long)]
    offer_name: String,

    #[arg(long)]
    description: String,

    /// Mediator DID; defaults to the active profile's mediator.
    #[arg(long)]
    mediator_did: Option<String>,

    #[arg(long)]
    contact_surname: Option<String>,

    #[arg(long)]
    contact_given_name: Option<String>,

    #[arg(long)]
    contact_email: Option<String>,

    #[arg(long)]
    contact_phone: Option<String>,

    /// ISO-8601 timestamp; offer expires at this point.
    #[arg(long)]
    valid_until: Option<String>,

    #[arg(long)]
    maximum_usage: Option<usize>,

    #[arg(long)]
    device_token: Option<String>,

    /// Push platform (`APNS`, `APNS_SANDBOX`, `FCM`, `NONE`).
    #[arg(long)]
    platform_type: Option<String>,

    #[arg(long)]
    custom_phrase: Option<String>,

    #[arg(long)]
    contact_attributes: Option<u32>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let args = Cli::parse();

    tracing::subscriber::set_global_default(
        tracing_subscriber::fmt()
            .with_env_filter(filter::EnvFilter::from_default_env())
            .finish(),
    )
    .expect("Logging failed, exiting...");

    // Load environment + pick a profile.
    let environment_name = args
        .environment
        .clone()
        .or_else(|| env::var("TDK_ENVIRONMENT").ok())
        .unwrap_or_else(|| "default".to_string());
    let environment =
        TDKEnvironments::fetch_from_file(args.path_environments.as_deref(), &environment_name)?;
    println!("Using Environment: {environment_name}");

    let profile_name = args
        .name_profile
        .clone()
        .or_else(|| env::var("TDK_PROFILE").ok());

    let profile = match profile_name.as_deref() {
        Some(name) => environment.profile(name).cloned().ok_or_else(|| {
            MeetingPlaceError::Configuration(format!(
                "Profile ({name}) not found in environment ({environment_name})"
            ))
        })?,
        None => environment
            .profiles()
            .values()
            .next()
            .cloned()
            .ok_or_else(|| {
                MeetingPlaceError::Configuration(format!(
                    "No profiles found in environment ({environment_name})"
                ))
            })?,
    };

    // Build TDK shared state with this environment, then run the chosen command.
    let tdk = TDKSharedState::new(
        TDKConfig::builder()
            .with_load_environment(false)
            .with_use_atm(false)
            .with_environment(environment)
            .build()
            .map_err(MeetingPlaceError::from)?,
    )
    .await
    .map_err(MeetingPlaceError::from)?;
    tdk.add_profile(&profile).await;

    let mp = MeetingPlace::new(&tdk, args.mp_did).await?;
    match args.command {
        Commands::Check(check_offer_phrase) => {
            let result = mp
                .check_offer_phrase(&tdk, &profile, &check_offer_phrase.phrase)
                .await?;
            info!("Offer Phrase is in use? {result}");
        }
        Commands::Register(register_offer) => {
            let offer_details = create_register_offer(&tdk, &register_offer, &profile).await?;
            let mut offer = Offer::new_from_register_offer(offer_details);
            let response = offer.register_offer(&mp, &tdk, &profile).await?;
            info!("Offer registered: {response:#?}");
        }
        Commands::Query(query_offer) => {
            let result = Offer::query_offer(&mp, &tdk, &profile, &query_offer.phrase).await?;
            info!("Offer result: {result:#?}");
        }
        Commands::Deregister(query_offer) => {
            let mut offer = Offer::query_offer(&mp, &tdk, &profile, &query_offer.phrase).await?;
            let result = offer.deregister_offer(&mp, &tdk, &profile).await?;
            info!("Deregister result: {result:#?}");
        }
    };

    tdk.shutdown().await;
    Ok(())
}

/// Map CLI args into a `RegisterOffer`. Resolves the mediator from the
/// command line first, falling back to the profile's default mediator.
async fn create_register_offer(
    tdk: &TDKSharedState,
    args: &RegisterOfferArgs,
    profile: &TDKProfile,
) -> Result<RegisterOffer> {
    let mediator_did = args
        .mediator_did
        .clone()
        .or_else(|| profile.mediator.clone())
        .ok_or_else(|| {
            MeetingPlaceError::Configuration(
                "No mediator DID specified and no default mediator in profile".to_string(),
            )
        })?;

    let mut offer_details = RegisterOffer::create(
        &args.offer_name,
        &args.description,
        &profile.did,
        &mediator_did,
    )?;

    offer_details.vcard(Vcard::new(
        args.contact_given_name.clone(),
        args.contact_surname.clone(),
        args.contact_email.clone(),
        args.contact_phone.clone(),
    ));

    if let Some(valid_until) = &args.valid_until {
        let valid_until = chrono::DateTime::parse_from_rfc3339(valid_until)
            .map_err(|err| {
                MeetingPlaceError::Configuration(format!(
                    "invalid valid_until timestamp. Must be ISO-8601 (e.g. 2025-03-17T09:00:00-00:00): {err}"
                ))
            })?
            .to_utc();

        let delta = valid_until - chrono::Utc::now();
        if delta.num_seconds() <= 0 {
            return Err(MeetingPlaceError::Configuration(
                "valid_until must be in the future".to_string(),
            ));
        }

        offer_details.valid_until(delta.to_std().map_err(|err| {
            MeetingPlaceError::Configuration(format!("invalid valid_until: {err}"))
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

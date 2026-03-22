/*!
 * Utility to test or incorporate the DID Authentication flow into your application.
 */

use affinidi_did_authentication::DIDAuthentication;
use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};
use affinidi_secrets_resolver::{SecretsResolver, ThreadedSecretsResolver, secrets::Secret};
use affinidi_tdk_common::{
    create_http_client,
    environments::TDKEnvironments,
    errors::{Result, TDKError},
    profiles::TDKProfile,
};
use clap::{Parser, Subcommand};
use std::{
    env,
    io::{self, Read},
};
use tracing_subscriber::filter;

/// Affinidi DID Authentication Tool
#[derive(Parser)]
#[command(name = "did_auth")]
#[command(bin_name = "did_auth")]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Service DID
    #[arg(short, long, value_name = "DID")]
    service_did: String,

    /// How many times to retry auth?
    #[arg(short, long, default_value_t = 3, value_parser = clap::value_parser!(u8).range(1..10))]
    retry_limit: u8,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Use a DID defined in the environments file
    Environment(EnvironmentArgs),

    /// use a custom DID - will need to provide secrets to STDIN
    ManualEntry(ManualEntryArgs),
}

/// Use a DID defined in the environments file
#[derive(Debug, Parser)]
#[command(version, about, long_about = None)]
struct EnvironmentArgs {
    /// Environment to use
    #[arg(short, long)]
    environment: Option<String>,

    /// Profile Name to use from the environment
    #[arg(short, long)]
    name_profile: String,

    /// Path to the environments file (defaults to environments.json)
    #[arg(short, long)]
    path_environments: Option<String>,
}

#[derive(Debug, Parser)]
#[command(version, about, long_about = None)]
struct ManualEntryArgs {
    /// DID to use for authentication
    #[arg(short, long)]
    did: String,
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

    let (profile, secrets) = match args.command {
        Commands::Environment(env_args) => {
            let environment_name = if let Some(environment_name) = &env_args.environment {
                environment_name.to_string()
            } else if let Ok(environment_name) = env::var("TDK_ENVIRONMENT") {
                environment_name
            } else {
                "default".to_string()
            };

            let environment = TDKEnvironments::fetch_from_file(
                env_args.path_environments.as_deref(),
                &environment_name,
            )?;

            if let Some(profile) = environment.profiles.get(&env_args.name_profile) {
                (profile.clone(), profile.secrets.clone())
            } else {
                return Err(TDKError::Profile(format!(
                    "Couldn't find profile ({}) in environment ({})!",
                    env_args.name_profile, environment_name
                )));
            }
        }
        Commands::ManualEntry(manual_args) => {
            let mut secrets_buf = String::new();
            io::stdin()
                .read_to_string(&mut secrets_buf)
                .map_err(|e| TDKError::Authentication(format!("Couldn't read from STDIN: {e}")))?;
            let secrets: Vec<Secret> = serde_json::from_str(&secrets_buf).map_err(|e| {
                TDKError::Authentication(format!("DID Secrets not valid JSON: {e}"))
            })?;
            (
                TDKProfile::new("manual", &manual_args.did, None, vec![]),
                secrets,
            )
        }
    };

    let did_resolver = DIDCacheClient::new(DIDCacheConfigBuilder::default().build()).await?;
    let secrets_resolver = ThreadedSecretsResolver::new(None).await.0;
    secrets_resolver.insert_vec(&secrets).await;
    let client = create_http_client();

    // Attempt Authentication
    let mut did_auth = DIDAuthentication::new();

    match did_auth
        .authenticate(
            &profile.did,
            &args.service_did,
            &did_resolver,
            &secrets_resolver,
            &client,
            args.retry_limit as i32,
        )
        .await
    {
        Ok(_) => {
            println!(
                "{}",
                serde_json::to_string_pretty(&did_auth.tokens).map_err(|_| {
                    TDKError::AuthenticationAbort("INVALID AUTHORIZATION TOKENS RECEIVED".into())
                })?
            );
            Ok(())
        }
        Err(err) => Err(TDKError::AuthenticationAbort(format!(
            "Couldn't authenticate DID({}) against endpoint({}): {}",
            profile.did, args.service_did, err
        ))),
    }
}

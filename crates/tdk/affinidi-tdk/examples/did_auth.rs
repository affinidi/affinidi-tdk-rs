/*!
 * Utility to test or incorporate the DID Authentication flow into your application.
 *
 * Two modes:
 *  - `environment`: load a DID from a TDKEnvironments file.
 *  - `manual-entry`: read raw DID secrets JSON from stdin.
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
#[command(name = "did_auth", bin_name = "did_auth")]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Service DID to authenticate against.
    #[arg(short, long, value_name = "DID")]
    service_did: String,

    /// How many times to retry auth on transient failure.
    #[arg(short, long, default_value_t = 3, value_parser = clap::value_parser!(u8).range(1..10))]
    retry_limit: u8,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Use a DID defined in the environments file.
    Environment(EnvironmentArgs),

    /// Use a custom DID — secrets must be provided on STDIN as a JSON array.
    ManualEntry(ManualEntryArgs),
}

#[derive(Debug, Parser)]
struct EnvironmentArgs {
    /// Environment to use (defaults to `$TDK_ENVIRONMENT` or `"default"`).
    #[arg(short, long)]
    environment: Option<String>,

    /// Profile name within the environment.
    #[arg(short, long)]
    name_profile: String,

    /// Path to the environments file (defaults to `environments.json`).
    #[arg(short, long)]
    path_environments: Option<String>,
}

#[derive(Debug, Parser)]
struct ManualEntryArgs {
    /// DID to authenticate with.
    #[arg(short, long)]
    did: String,
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

    let (profile, secrets) = match args.command {
        Commands::Environment(env_args) => load_from_environment(env_args)?,
        Commands::ManualEntry(manual_args) => load_from_stdin(manual_args)?,
    };

    let did_resolver = DIDCacheClient::new(DIDCacheConfigBuilder::default().build()).await?;
    let secrets_resolver = ThreadedSecretsResolver::new(None).await.0;
    secrets_resolver.insert_vec(&secrets).await;
    let client = create_http_client(&[])?;

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
            "Couldn't authenticate DID({}) against endpoint({}): {err}",
            profile.did, args.service_did,
        ))),
    }
}

fn load_from_environment(args: EnvironmentArgs) -> Result<(TDKProfile, Vec<Secret>)> {
    let environment_name = args
        .environment
        .clone()
        .or_else(|| env::var("TDK_ENVIRONMENT").ok())
        .unwrap_or_else(|| "default".to_string());

    let environment =
        TDKEnvironments::fetch_from_file(args.path_environments.as_deref(), &environment_name)?;

    let mut profile = environment
        .profiles()
        .get(&args.name_profile)
        .ok_or_else(|| {
            TDKError::Profile(format!(
                "Couldn't find profile ({}) in environment ({})!",
                args.name_profile, environment_name
            ))
        })?
        .clone();

    let secrets = profile.take_secrets();
    Ok((profile, secrets))
}

fn load_from_stdin(args: ManualEntryArgs) -> Result<(TDKProfile, Vec<Secret>)> {
    let mut secrets_buf = String::new();
    io::stdin()
        .read_to_string(&mut secrets_buf)
        .map_err(|e| TDKError::Authentication(format!("Couldn't read from STDIN: {e}")))?;
    let secrets: Vec<Secret> = serde_json::from_str(&secrets_buf)
        .map_err(|e| TDKError::Authentication(format!("DID Secrets not valid JSON: {e}")))?;
    Ok((TDKProfile::new("manual", &args.did, None, vec![]), secrets))
}

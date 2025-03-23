//! Example using OOB Discovery to create and retrieve an invitation
//! Does not show the next steps of creating the connection, this is outside of the scope of this example

use affinidi_messaging_sdk::{
    ATM, config::ATMConfig, errors::ATMError, profiles::ATMProfile, protocols::Protocols,
};
use affinidi_tdk::common::{TDKSharedState, environments::TDKEnvironments};
use clap::Parser;
use std::env;
use tracing::debug;
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

    // construct a subscriber that prints formatted traces to stdout
    let subscriber = tracing_subscriber::fmt()
        // Use a more compact, abbreviated log format
        .with_env_filter(filter::EnvFilter::from_default_env())
        .finish();
    // use that subscriber to process traces emitted after this point
    tracing::subscriber::set_global_default(subscriber).expect("Logging failed, exiting...");

    let alice = if let Some(alice) = environment.profiles.get("Alice") {
        alice
    } else {
        return Err(ATMError::ConfigError(
            format!("Alice not found in Profile: {}", environment_name).to_string(),
        ));
    };

    let mut config = ATMConfig::builder();

    config = config.with_ssl_certificates(&mut environment.ssl_certificates);

    // Create a new ATM Client
    let tdk = TDKSharedState::default().await;
    let atm = ATM::new(config.build()?, tdk).await?;
    let protocols = Protocols::new();

    debug!("Enabling Alice's Profile");
    let alice = atm
        .profile_add(&ATMProfile::from_tdk_profile(&atm, alice).await?, true)
        .await?;

    let oob_id = protocols
        .oob_discovery
        .create_invite(&atm, &alice, None)
        .await?;

    println!("oob_id = {}", oob_id);
    println!();

    let endpoint = match &*alice.inner.mediator {
        Some(mediator) => mediator.rest_endpoint.as_ref().unwrap().to_string(),
        _ => {
            panic!("Alice's mediator is not set");
        }
    };

    let url = [&endpoint, "/oob?_oobid=", &oob_id].concat();
    println!("Attempting to retrieve an invitation: {}", url);
    let invitation = protocols.oob_discovery.retrieve_invite(&atm, &url).await?;

    println!(
        "Received invitation:\n{}",
        serde_json::to_string_pretty(&invitation).unwrap()
    );

    println!();
    let del_response = protocols
        .oob_discovery
        .delete_invite(&atm, &alice, &oob_id)
        .await?;

    println!("Delete response: deleted? {}", del_response);

    Ok(())
}

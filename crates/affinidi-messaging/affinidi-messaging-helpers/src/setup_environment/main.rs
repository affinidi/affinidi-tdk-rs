//! Helps configure the various configuration options, DIDs and keys for the actors in the examples.
//! This helps to create consistency in the examples and also to avoid code duplication.
use affinidi_messaging_helpers::common::{affinidi_logo, check_path};
use affinidi_tdk::{
    common::{environments::TDKEnvironments, profiles::TDKProfile},
    dids::{DID, KeyType},
};
use clap::Parser;
use console::{Style, Term, style};
use dialoguer::{Confirm, theme::ColorfulTheme};
use did_peer::DIDPeerKeys;
use std::error::Error;
use ui::{MediatorType, init_local_mediator, init_remote_mediator, local_remote_mediator};

mod mediator;
mod network;
mod ssl_certs;
mod ui;

/// Setups the environment for Affinidi Messaging
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Path to the environments file (defaults to environments.json)
    #[arg(short, long)]
    path_environments: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let term = Term::stdout();
    let _ = term.clear_screen();
    affinidi_logo::print_logo();
    // Ensure we are somewhere we should be...
    check_path()?;

    let args: Args = Args::parse();

    let theme = ColorfulTheme {
        values_style: Style::new().yellow().dim(),
        ..ColorfulTheme::default()
    };

    println!(
        "{}",
        style("Welcome to the Affinidi Messaging setup wizard").green(),
    );

    // Load environments if they already exist
    let mut environments = TDKEnvironments::load_file(
        &args
            .path_environments
            .unwrap_or("environments.json".to_string()),
    )?;

    // ************ Local or Remote? ************
    let environment_name;
    let type_;
    loop {
        let (t_, environment) = match local_remote_mediator(&theme, &environments)? {
            Some(m_t) => match m_t {
                MediatorType::Local => init_local_mediator(&theme, &mut environments).await?,
                MediatorType::Remote => init_remote_mediator(&theme, &mut environments).await?,
                MediatorType::Existing(profile) => {
                    (MediatorType::Existing(profile.clone()), Some(profile))
                }
            },
            _ => {
                println!("{}", style("Exiting...").color256(208));
                return Ok(());
            }
        };

        if let Some(environment) = environment {
            environment_name = environment;
            type_ = t_;
            break;
        }
    }

    let mut environment = if let Some(environment) = environments.get(&environment_name) {
        environment.to_owned()
    } else {
        return Err("Environment not found".into());
    };

    println!();
    println!(
        "  {}{}",
        style("Selected Environment: ").blue(),
        style(&environment_name).color256(208)
    );
    println!();

    // ************ Administration Account ************

    // ************ Friends ************

    if Confirm::with_theme(&theme)
        .with_prompt("You need some friends to run the examples! Would you like to auto-create some friends?")
        .default(true)
        .interact()?
    {

        fn _create_friend(alias: &str, mediator: Option<&str>) -> TDKProfile {
            let (did, secrets) = DID::generate_did_peer(vec![(DIDPeerKeys::Verification, KeyType::P256), (DIDPeerKeys::Verification, KeyType::Ed25519), (DIDPeerKeys::Encryption, KeyType::Secp256k1), (DIDPeerKeys::Encryption, KeyType::P256)], None).unwrap();
            TDKProfile {
                alias: alias.to_string(),
                did,
                secrets,
                mediator: mediator.map(|m| m.to_string()),
            }
        }

        environment.profiles.insert("Alice".into(), _create_friend("Alice", environment.default_mediator.as_deref()));
        println!("  {}{}", style("Friend Alice created with DID: ").blue(), style(&environment.profiles.get("Alice").unwrap().did).color256(208));
        environment.profiles.insert("Bob".into(), _create_friend("Bob", environment.default_mediator.as_deref()));
        println!("  {}{}", style("Friend Bob created with DID: ").blue(), style(&environment.profiles.get("Bob").unwrap().did).color256(208));
        environment.profiles.insert("Charlie".into(), _create_friend("Charlie", environment.default_mediator.as_deref()));
        println!("  {}{}", style("Friend Charlie created with DID: ").blue(), style(&environment.profiles.get("Charlie").unwrap().did).color256(208));
        environment.profiles.insert("Mallory".into(), _create_friend("Mallory", environment.default_mediator.as_deref()));
        println!("  {}{}{}{}", style("Friend(?) ").blue(), style("Mallory").red(), style(" created with DID: ").blue(), style(&environment.profiles.get("Mallory").unwrap().did).color256(208));
    }

    if Confirm::with_theme(&theme)
        .with_prompt(format!("Save friends to profile: {}?", environment_name))
        .default(true)
        .interact()?
    {
        environments.add(&environment_name, environment);
        environments.save()?;
    }

    if type_ == MediatorType::Local {
        println!();
        println!(
            "{}",
            style("You can now run the mediator locally using the following command:").blue()
        );
        println!(
            "  {}",
            style("cd affinidi-messaging-mediator && cargo run").color256(231)
        );
    }

    println!();
    println!(
        "{}",
        style(
            "You can set the environment variable TDK_ENVIRONMENT to use this profile in the examples."
        )
        .blue()
    );
    println!(
        "  {}",
        style(format!("export TDK_ENVIRONMENT={}", environment_name)).color256(208)
    );
    println!();
    Ok(())
}

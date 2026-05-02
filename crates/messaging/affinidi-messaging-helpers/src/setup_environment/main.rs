//! Helps configure the various configuration options, DIDs and keys for the actors in the examples.
//! This helps to create consistency in the examples and also to avoid code duplication.
use affinidi_messaging_helpers::common::{affinidi_logo, check_path};
use affinidi_tdk::{
    common::{environments::TDKEnvironments, profiles::TDKProfile},
    dids::{DID, KeyType, PeerKeyRole},
};
use clap::Parser;
use console::{Style, Term, style};
use dialoguer::{Confirm, theme::ColorfulTheme};
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
            let (did, secrets) = DID::generate_did_peer(vec![(PeerKeyRole::Verification, KeyType::P256), (PeerKeyRole::Verification, KeyType::Ed25519), (PeerKeyRole::Encryption, KeyType::Secp256k1), (PeerKeyRole::Encryption, KeyType::P256), (PeerKeyRole::Encryption, KeyType::X25519)], None).unwrap();
            TDKProfile::new(alias, &did, mediator, secrets)
        }

        let mediator = environment.default_mediator().map(str::to_owned);
        for friend in ["Alice", "Bob", "Charlie", "Mallory"] {
            let profile = _create_friend(friend, mediator.as_deref());
            let did = profile.did.clone();
            environment.add_profile(profile);
            let label = if friend == "Mallory" {
                format!("{}{}{}", style("Friend(?) ").blue(), style(friend).red(), style(" created with DID: ").blue())
            } else {
                format!("{}{}{}", style("Friend ").blue(), style(friend).blue(), style(" created with DID: ").blue())
            };
            println!("  {}{}", label, style(did).color256(208));
        }
    }

    if Confirm::with_theme(&theme)
        .with_prompt(format!("Save friends to profile: {environment_name}?"))
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
        style(format!("export TDK_ENVIRONMENT={environment_name}")).color256(208)
    );
    println!();
    Ok(())
}

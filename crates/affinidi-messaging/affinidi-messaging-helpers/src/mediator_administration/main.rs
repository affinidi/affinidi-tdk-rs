//! Example of how to manage administration accounts for the mediator
use account_management::account_management::account_management_menu;
use affinidi_messaging_helpers::common::{affinidi_logo::print_logo, check_path};
use affinidi_messaging_sdk::{
    ATM,
    config::ATMConfig,
    profiles::ATMProfile,
    protocols::{
        Protocols,
        mediator::acls::{AccessListModeType, MediatorACLSet},
    },
};
use affinidi_tdk::{
    common::{
        TDKSharedState,
        environments::{TDKEnvironment, TDKEnvironments},
    },
    secrets_resolver::SecretsResolver,
};
use ahash::AHashMap as HashMap;
use clap::Parser;
use console::{Style, Term, style};
use dialoguer::{Select, theme::ColorfulTheme};
use serde::Deserialize;
use serde_json::Value;
use sha256::digest;
use std::env;
use std::error::Error;
use tracing_subscriber::filter;
use ui::administration_accounts_menu;

mod account_management;
mod ui;

/// Affinidi Mediator Administration
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

/// Holds information from the mediator configuration
#[derive(Debug, Deserialize)]
struct SharedConfig {
    pub version: String,
    pub our_admin_hash: String,
    pub mediator_did_hash: String,
    pub acl_mode: AccessListModeType,
    pub global_acl_default: MediatorACLSet,
    pub queued_send_messages_soft: i32,
    pub queued_receive_messages_soft: i32,
}

impl SharedConfig {
    // Converts and loads a retrieved configuration into a basic config structure
    pub fn new(input: HashMap<String, Value>) -> Result<Self, Box<dyn Error>> {
        let version = if let Some(version) = input.get("version") {
            if let Some(version) = version.as_str() {
                version.to_string()
            } else {
                return Err("Couldn't find version in Mediator Configuration".into());
            }
        } else {
            return Err("Couldn't find version in Mediator Configuration".into());
        };

        let config = if let Some(config) = input.get("config") {
            match serde_json::from_value::<HashMap<String, Value>>(config.to_owned()) {
                Ok(config) => config,
                Err(_) => return Err("Couldn't parse Mediator Configuration".into()),
            }
        } else {
            return Err("Couldn't parse Mediator Configuration".into());
        };

        let mediator_did = if let Some(mediator_did) = config.get("mediator_did") {
            if let Some(mediator_did) = mediator_did.as_str() {
                mediator_did.to_string()
            } else {
                return Err("Couldn't find mediator_did in Mediator Configuration".into());
            }
        } else {
            return Err("Couldn't find mediator_did in Mediator Configuration".into());
        };

        let acl_mode = if let Some(acl_mode) = config
            .get("security")
            .and_then(|security| security.get("mediator_acl_mode"))
        {
            match serde_json::from_value::<AccessListModeType>(acl_mode.to_owned()) {
                Ok(acl_mode) => acl_mode,
                Err(_) => {
                    return Err("Couldn't find mediator_acl_mode in Mediator Configuration".into());
                }
            }
        } else {
            return Err("Couldn't find mediator_acl_mode in Mediator Configuration".into());
        };

        let global_acl_default = if let Some(global_acl_default) = config
            .get("security")
            .and_then(|security| security.get("global_acl_default"))
            .and_then(|acls| acls.get("acl"))
        {
            if let Some(global_acl_default) = global_acl_default.as_u64() {
                MediatorACLSet::from_u64(global_acl_default)
            } else {
                return Err("Couldn't find global_acl_default in Mediator Configuration".into());
            }
        } else {
            return Err("Couldn't find global_acl_default in Mediator Configuration".into());
        };

        let queued_send_messages_soft = if let Some(queued_send_message_soft) = config
            .get("limits")
            .and_then(|limits| limits.get("queued_send_messages_soft"))
        {
            if let Some(queued_send_message_soft) = queued_send_message_soft.as_i64() {
                queued_send_message_soft as i32
            } else {
                return Err(
                    "Couldn't find queued_send_messages_soft in Mediator Configuration".into(),
                );
            }
        } else {
            return Err("Couldn't find queued_send_messages_soft in Mediator Configuration".into());
        };

        let queued_receive_messages_soft = if let Some(queued_receive_message_soft) = config
            .get("limits")
            .and_then(|limits| limits.get("queued_receive_messages_soft"))
        {
            if let Some(queued_receive_message_soft) = queued_receive_message_soft.as_i64() {
                queued_receive_message_soft as i32
            } else {
                return Err(
                    "Couldn't find queued_receive_messages_soft in Mediator Configuration".into(),
                );
            }
        } else {
            return Err(
                "Couldn't find queued_receive_messages_soft in Mediator Configuration".into(),
            );
        };

        Ok(SharedConfig {
            version,
            acl_mode,
            global_acl_default,
            our_admin_hash: String::new(),
            mediator_did_hash: digest(mediator_did),
            queued_send_messages_soft,
            queued_receive_messages_soft,
        })
    }
}

async fn init() -> Result<(ColorfulTheme, ATMConfig, TDKEnvironment), Box<dyn Error>> {
    let args: Args = Args::parse();

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

    // construct a subscriber that prints formatted traces to stdout
    let subscriber = tracing_subscriber::fmt()
        // Use a more compact, abbreviated log format
        .with_env_filter(filter::EnvFilter::from_default_env())
        .finish();
    // use that subscriber to process traces emitted after this point
    tracing::subscriber::set_global_default(subscriber).expect("Logging failed, exiting...");

    let term = Term::stdout();
    let _ = term.clear_screen();
    print_logo();

    let theme = ColorfulTheme {
        values_style: Style::new().yellow().dim(),
        ..ColorfulTheme::default()
    };

    // determine the right path to config files
    check_path()?;

    println!(
        "{}",
        style("Welcome to the Affinidi Messaging Mediator Administration wizard").green(),
    );

    if environment.admin_did.is_none() {
        return Err("Admin DID not found in Environment".into());
    }

    let mut ssl_certificates = Vec::new();
    for certificate in &environment.ssl_certificates {
        ssl_certificates.push(certificate.to_string());
    }

    // Connect to the Mediator
    let config = ATMConfig::builder()
        .with_ssl_certificates(&mut ssl_certificates)
        .build()?;

    Ok((theme, config, environment))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let (theme, config, environment) = init().await?;

    let admin = if let Some(admin) = environment.admin_did {
        admin
    } else {
        return Err("Admin DID not found in Environment".into());
    };

    // Create a new ATM Client
    let tdk = TDKSharedState::default().await;
    tdk.secrets_resolver.insert_vec(&admin.secrets).await;
    let atm = ATM::new(config, tdk).await?;
    let protocols = Protocols::new();

    // Create the admin profile and enable it
    let admin_profile = ATMProfile::from_tdk_profile(&atm, &admin).await?;
    let admin = atm.profile_add(&admin_profile, true).await?;

    println!("{}", style("Admin account connected...").green());

    println!("{}", style("Fetching Mediator Configuration...").blue());
    let shared_config: HashMap<String, Value> =
        serde_json::from_value(protocols.mediator.get_config(&atm, &admin).await?)?;
    let mut mediator_config = SharedConfig::new(shared_config)?;
    println!(
        "{}{}{}{}{}",
        style("Mediator server(").green(),
        style(admin_profile.dids()?.1).color256(208),
        style(") version(").green(),
        style(&mediator_config.version).color256(208),
        style("). Configuration loaded successfully").green()
    );

    mediator_config.our_admin_hash = digest(admin.dids()?.0);

    loop {
        println!();
        let selections = &["Account Management", "Administration Accounts", "Quit"];

        let selection = Select::with_theme(&theme)
            .with_prompt("Select an action?")
            .default(0)
            .items(&selections[..])
            .interact()
            .unwrap();

        println!();
        match selection {
            0 => {
                account_management_menu(&atm, &admin, &protocols, &theme, &mediator_config).await?;
            }
            1 => {
                administration_accounts_menu(&atm, &admin, &protocols, &theme, &mediator_config)
                    .await;
            }
            2 => {
                println!("Quitting");
                break;
            }
            _ => {
                println!("Invalid selection");
            }
        }
    }

    Ok(())
}

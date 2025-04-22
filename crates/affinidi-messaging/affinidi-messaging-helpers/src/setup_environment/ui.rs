use crate::{
    mediator::{MediatorConfig, read_config_file},
    network::fetch_well_known_did,
    ssl_certs::create_ssl_certs,
};
use affinidi_messaging_helpers::common::did::{create_did, get_service_address};
use affinidi_tdk::{
    common::{
        environments::{TDKEnvironment, TDKEnvironments},
        profiles::TDKProfile,
    },
    dids::{DID, KeyType},
};
use console::style;
use dialoguer::{Confirm, Input, Select, theme::ColorfulTheme};
use did_peer::DIDPeerKeys;
use regex::Regex;
use std::{error::Error, path::Path};
use toml::Value;

/// Local or Remote mediator
#[derive(PartialEq)]
pub enum MediatorType {
    Local,
    Remote,
    Existing(String),
}

pub(crate) fn local_remote_mediator(
    theme: &ColorfulTheme,
    environments: &TDKEnvironments,
) -> Result<Option<MediatorType>, Box<dyn Error>> {
    println!();

    let mut selections = vec![
        "Local Mediator Configuration".to_string(),
        "Remote Mediator Configuration".to_string(),
    ];
    if !environments.is_empty() {
        selections.push("Select Existing Environment?".to_string());
    }

    selections.push("Exit".to_string());

    loop {
        let type_ = Select::with_theme(theme)
            .with_prompt("Configure local or remote mediator?")
            .default(0)
            .items(&selections[..])
            .interact()?;

        if type_ == selections.len() - 1 {
            return Ok(None);
        }

        match type_ {
            0 => return Ok(Some(MediatorType::Local)),
            1 => return Ok(Some(MediatorType::Remote)),
            2 => {
                if environments.is_empty() {
                    unreachable!("No environments to manage");
                } else if let Some(profile) = select_profile(theme, environments)? {
                    return Ok(Some(profile));
                }
            }
            _ => unreachable!(),
        }
    }
}

fn select_profile(
    theme: &ColorfulTheme,
    environments: &TDKEnvironments,
) -> Result<Option<MediatorType>, Box<dyn Error>> {
    let mut selections: Vec<String> = environments.environments();

    selections.push("Back to Main Menu".to_string());

    let profile = Select::with_theme(theme)
        .with_prompt("Select Profile")
        .default(0)
        .items(&selections[..])
        .interact()?;

    if profile == selections.len() - 1 {
        // Go back to the previous menu
        Ok(None)
    } else {
        Ok(Some(MediatorType::Existing(
            selections[profile].to_string(),
        )))
    }
}

/// Saves an environment to environments
fn save_environment(
    theme: &ColorfulTheme,
    environments: &mut TDKEnvironments,
    environment: TDKEnvironment,
    name: &str,
) -> Result<Option<String>, Box<dyn Error>> {
    println!();
    match Input::<String>::with_theme(theme)
        .with_prompt("Save environment with name?")
        .with_initial_text(name)
        .interact_text()
    {
        Ok(name) => {
            if Confirm::with_theme(theme)
                .with_prompt(format!("Save Environment: {}?", name))
                .default(true)
                .interact()?
            {
                if environments.add(&name, environment) {
                    println!("  {}", style("Environment added").green());
                } else {
                    println!("  {}", style("Environment replaced").color256(208));
                }

                environments.save()?;
                println!("  {}", style("Environments saved...").green());
                Ok(Some(name))
            } else {
                println!("  {}", style("Environment not saved").red());
                Ok(None)
            }
        }
        _ => Err("Environment name not provided".into()),
    }
}

/// Initialize remote mediator configuration
/// Expected that the remote mediator is already up and running
pub(crate) async fn init_remote_mediator(
    theme: &ColorfulTheme,
    environments: &mut TDKEnvironments,
) -> Result<(MediatorType, Option<String>), Box<dyn Error>> {
    fn _ask_for_remote_address(theme: &ColorfulTheme) -> Result<String, Box<dyn Error>> {
        let address = Input::with_theme(theme)
            .with_prompt("Remote Mediator Address")
            .default("https://localhost:7037/v1/mediator".to_string())
            .interact_text()?;

        Ok(address)
    }

    fn _ask_for_remote_did(theme: &ColorfulTheme) -> Result<String, Box<dyn Error>> {
        let did = Input::with_theme(theme)
            .with_prompt("Remote Mediator DID")
            .report(false)
            .interact()?;

        Ok(did)
    }

    fn _ssl_cert(theme: &ColorfulTheme) -> Result<Option<String>, Box<dyn Error>> {
        if Confirm::with_theme(theme)
            .with_prompt("Do you need to provide an SSL certificate?")
            .interact()?
        {
            loop {
                let cert = Input::with_theme(theme)
                    .with_prompt("SSL Certificate Path")
                    .interact_text()?;

                if Path::new(&cert).exists() {
                    println!("  {}", style("SSL Certificate exists").green());
                    return Ok(Some(cert));
                } else {
                    println!("  {}", style("File does not exist!").red());
                }
            }
        } else {
            Ok(None)
        }
    }

    fn _admin_did(mediator: &str, theme: &ColorfulTheme) -> Option<TDKProfile> {
        if Confirm::with_theme(theme)
            .with_prompt("Do you want to create an Admin account?")
            .default(true)
            .interact()
            .unwrap()
        {
            let (did, secrets) = DID::generate_did_peer(
                vec![
                    (DIDPeerKeys::Verification, KeyType::Ed25519),
                    (DIDPeerKeys::Encryption, KeyType::Secp256k1),
                ],
                None,
            )
            .unwrap();
            let admin_did = TDKProfile::new("Admin", &did, Some(mediator), secrets);
            println!(
                "  {}{}",
                style("Admin DID: ").blue(),
                style(&admin_did.did).color256(208)
            );
            Some(admin_did)
        } else if Confirm::with_theme(theme)
            .with_prompt("Do you have an Admin DID?")
            .interact()
            .unwrap()
        {
            let admin_did = Input::with_theme(theme)
                .with_prompt("Admin DID")
                .interact_text()
                .unwrap();

            println!(
                "  {}{}",
                style("Admin DID provided: ").blue(),
                style(&admin_did).color256(208)
            );
            println!(
                "  {}",
                style("You MUST edit the profile to add the Admin keys!")
                    .blink()
                    .red()
            );
            Some(TDKProfile {
                alias: "Admin".to_string(),
                did: admin_did,
                mediator: Some(mediator.to_string()),
                secrets: vec![],
            })
        } else {
            None
        }
    }

    let mediator_did;
    let mut network_address;

    if !Confirm::with_theme(theme)
        .with_prompt("The remote mediator must be already running. Continue?")
        .default(true)
        .interact()?
    {
        return Err("Remote Mediator must be running!".into());
    }

    if Confirm::with_theme(theme)
        .with_prompt("Do you know the DID of the remote Mediator?")
        .default(true)
        .interact()?
    {
        mediator_did = _ask_for_remote_did(theme)?;
        // extract the remote address from the did
        network_address = get_service_address(&mediator_did).await?;
        println!(
            "  {}{}",
            style("Mediator address from DID: ").green(),
            style(&network_address).color256(208)
        );
        if !Confirm::with_theme(theme)
            .with_prompt("Do you want to use this mediator address?")
            .default(true)
            .interact()?
        {
            network_address = _ask_for_remote_address(theme)?;
        }

        println!(
            "  {}",
            style("Checking if the mediator is reachable...").yellow()
        );
        let well_known_did = fetch_well_known_did(&network_address).await?;
        if well_known_did != mediator_did {
            println!(
                " {}",
                style("Mediator well-known DID does not match the provided DID!").red()
            );
            return Err("Well-known DID does not match the provided DID".into());
        }
        println!(
            " {}",
            style("Mediator is reachable and DID/address match...").green()
        );
    } else {
        network_address = _ask_for_remote_address(theme)?;
        // Connect to the mediator and get the well-known DID
        mediator_did = fetch_well_known_did(&network_address).await?;
        println!(
            "  {}{}",
            style("Well-known DID fetched successfully: ").green(),
            style(&mediator_did).color256(208)
        );
    }

    // We need to know where the SSL Certificate is if needed?
    let mut ssl_certificates = Vec::new();
    if let Some(ssl_cert) = _ssl_cert(theme)? {
        ssl_certificates.push(ssl_cert)
    }

    // Get admin account info
    let admin_did = _admin_did(&mediator_did, theme);

    let environment = TDKEnvironment {
        default_mediator: Some(mediator_did.clone()),
        profiles: std::collections::HashMap::new(),
        admin_did,
        ssl_certificates,
    };

    Ok((
        MediatorType::Remote,
        save_environment(theme, environments, environment, "remote")?,
    ))
}

/// Initialize local mediator configuration
pub(crate) async fn init_local_mediator(
    theme: &ColorfulTheme,
    environments: &mut TDKEnvironments,
) -> Result<(MediatorType, Option<String>), Box<dyn Error>> {
    /// Rewrite the network address from listen address to localhost
    /// - config: Mediator Configuration
    fn _rewrite_network_address(config: &Value) -> Result<String, Box<dyn Error>> {
        // example: listen address = "0.0.0.0:7037"
        let re = Regex::new(r"[^:]*:?(\d*)?").unwrap();

        let server_block = if let Some(server) = config.get("server") {
            server
        } else {
            return Err("Could not find server configuration block".into());
        };

        let listen_address = if let Some(listen_address) = server_block.get("listen_address") {
            if let Some(listen_address) = listen_address.as_str() {
                listen_address
            } else {
                return Err("server.listen_address isn't a string".into());
            }
        } else {
            return Err("Could not find listen_address in server configuration block".into());
        };

        if let Some(groups) = re.captures(listen_address) {
            if groups.len() == 2 {
                if let Some(api_prefix) = server_block.get("api_prefix") {
                    if let Some(api_prefix) = api_prefix.as_str() {
                        return Ok(format!(
                            "https://localhost:{}{}",
                            &groups[1],
                            api_prefix.trim_end_matches("/")
                        ));
                    }
                }
            }
        }
        Err("Could not determine network address from mediator configuration".into())
    }

    // Handles picking the mediator address from the configuration or create a new one
    fn _mediator_address(
        config: &Value,
        new_config: &mut MediatorConfig,
        theme: &ColorfulTheme,
    ) -> Result<(), Box<dyn Error>> {
        if let Some(mediator_did) = config.get("mediator_did") {
            if let Some(mediator_did) = mediator_did.as_str() {
                let mediator_did = if let Some(mediator_did) = mediator_did.strip_prefix("did://") {
                    mediator_did
                } else {
                    mediator_did
                };

                println!(
                    "  {}{}",
                    style("Mediator DID: ").blue(),
                    style(mediator_did).color256(208)
                );
                if Confirm::with_theme(theme)
                    .with_prompt("Use existing Mediator DID?")
                    .default(true)
                    .interact()?
                {
                    new_config.mediator_did = Some(mediator_did.to_string());
                    println!("  {}", style("You will need to ensure that the secrets for the Mediator DID are saved as well!!!").cyan());
                    return Ok(());
                }
            }
        }

        let response = create_did(Some("https://localhost:7037/v1/mediator".into()), true)?;
        new_config.mediator_did = Some(response.0.clone());
        new_config.mediator_secrets = Some(response.1);
        println!(
            "  {} {}",
            style("Mediator DID created: ").blue().bold(),
            style(&response.0).color256(208)
        );

        Ok(())
    }

    // Setup the initial mediator configuration
    println!();
    let mut new_mediator_config = MediatorConfig::default();
    let mediator_config = read_config_file("affinidi-messaging-mediator/conf/mediator.toml")?;

    println!("Configuring local mediator...");

    _mediator_address(&mediator_config, &mut new_mediator_config, theme)?;

    println!();
    if Confirm::with_theme(theme)
        .with_prompt("Create new JWT authorization secrets?")
        .default(true)
        .interact()?
    {
        new_mediator_config.create_jwt_secrets()?;
    }

    // Creating new Admin account
    let (did, secrets) = DID::generate_did_peer(
        vec![
            (DIDPeerKeys::Verification, KeyType::Ed25519),
            (DIDPeerKeys::Encryption, KeyType::Secp256k1),
        ],
        None,
    )
    .unwrap();
    let admin_did = TDKProfile::new(
        "Admin",
        &did,
        new_mediator_config.mediator_did.as_deref(),
        secrets,
    );
    new_mediator_config.admin_did = Some(admin_did.did.clone());

    println!();
    if Confirm::with_theme(theme)
        .with_prompt("Save mediator configuration?")
        .default(true)
        .interact()?
    {
        new_mediator_config.save_config()?;
    }

    println!();
    if Confirm::with_theme(theme)
        .with_prompt("Create local SSL certificates and root authority for testing/development?")
        .default(true)
        .interact()?
    {
        create_ssl_certs()?;
        println!(
            "  {}{}{}",
            style("SSL certificates etc saved to (").blue(),
            style("./affinidi-messaging-mediator/conf/keys/").color256(201),
            style(")").blue()
        );
    }

    let environment = TDKEnvironment {
        default_mediator: new_mediator_config.mediator_did.clone(),
        profiles: std::collections::HashMap::new(),
        admin_did: Some(admin_did),
        ssl_certificates: vec!["./affinidi-messaging-mediator/conf/keys/client.chain".to_string()],
    };
    Ok((
        MediatorType::Local,
        save_environment(theme, environments, environment, "local")?,
    ))
}

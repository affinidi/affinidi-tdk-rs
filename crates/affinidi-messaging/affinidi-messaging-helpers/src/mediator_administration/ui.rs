//! UI Related functions
use affinidi_messaging_sdk::{
    ATM, profiles::ATMProfile, protocols::mediator::accounts::AccountType,
};
use console::style;
use dialoguer::{Confirm, Input, MultiSelect, Select, theme::ColorfulTheme};
use regex::Regex;
use sha256::digest;
use std::{slice, sync::Arc};

use crate::SharedConfig;

pub(crate) async fn administration_accounts_menu(
    atm: &ATM,
    profile: &Arc<ATMProfile>,
    theme: &ColorfulTheme,
    shared_config: &SharedConfig,
) {
    let selections = &[
        "List Administration DIDs",
        "Add Administration rights to a DID (will create if it doesn't exist)",
        "Strip Administration rights from a DID (DID will be set back to Standard)",
        "Back",
    ];

    loop {
        let selection = Select::with_theme(theme)
            .with_prompt("Select an action?")
            .default(0)
            .items(&selections[..])
            .interact()
            .unwrap();

        match selection {
            0 => {
                list_admins(atm, profile, shared_config).await;
            }
            1 => add_admin(atm, profile, theme).await,
            2 => strip_admins(atm, profile, shared_config, theme).await,
            3 => {
                break;
            }
            _ => {
                println!("Invalid selection");
            }
        }
    }
}

/// List first 100 Administration DIDs
pub(crate) async fn list_admins(atm: &ATM, profile: &Arc<ATMProfile>, config: &SharedConfig) {
    match atm.mediator().list_admins(profile, None, None).await {
        Ok(admins) => {
            println!(
                "{}",
                style("Listing Administration DIDs (SHA256 Hashed DID's). NOTE: Will only list first 100 admin accounts!").green()
            );

            for (idx, admin) in admins.accounts.iter().enumerate() {
                print!(
                    "  {}",
                    style(format!("{}: {}", idx, admin.did_hash)).yellow(),
                );
                let (role, color) = match admin._type {
                    AccountType::Mediator => (admin._type.to_string(), 27_u8),
                    AccountType::RootAdmin => (admin._type.to_string(), 127_u8),
                    AccountType::Admin => (admin._type.to_string(), 129_u8),
                    _ => ("Unknown".into(), 1_u8),
                };
                print!(" {}", style(format!("({role})")).color256(color));
                if admin.did_hash.as_bytes() == config.our_admin_hash.as_bytes() {
                    print!(" {}", style("(our Admin account)").color256(208));
                }

                println!();
            }
        }
        Err(e) => {
            println!("{}", style(format!("Error: {e}")).red());
        }
    }
}

/// Add new Administration DID
pub(crate) async fn add_admin(atm: &ATM, profile: &Arc<ATMProfile>, theme: &ColorfulTheme) {
    println!("Adding new Administration DID (type exit to quit this dialog)");

    let input: String = Input::with_theme(theme)
        .with_prompt("DID to add")
        .validate_with(|input: &String| -> Result<(), &str> {
            let re = Regex::new(r"did:\w*:\w*").unwrap();
            if re.is_match(input) || input == "exit" {
                Ok(())
            } else {
                Err("Invalid DID format")
            }
        })
        .interact_text()
        .unwrap();

    if input == "exit" {
        return;
    }

    if Confirm::with_theme(theme)
        .with_prompt(format!("Do you want to add DID ({})?", &input))
        .interact()
        .unwrap()
    {
        match atm
            .mediator()
            .add_admins(profile, slice::from_ref(&input))
            .await
        {
            Ok(result) => {
                if result == 1 {
                    println!(
                        "{}",
                        style(format!("Successfully added DID ({})", &input)).green()
                    );
                    println!(
                        "  {}{}",
                        style("DID Hash: ").green(),
                        style(digest(&input)).yellow()
                    );
                } else {
                    println!(
                        "{}",
                        style(format!("DID ({}) already exists", &input)).color256(208)
                    );
                }
            }
            Err(e) => {
                println!("{}", style(format!("Error: {e}")).red());
            }
        }
    }
}

pub(crate) async fn strip_admins(
    atm: &ATM,
    profile: &Arc<ATMProfile>,
    config: &SharedConfig,
    theme: &ColorfulTheme,
) {
    match atm.mediator().list_admins(profile, None, None).await {
        Ok(admins) => {
            // remove the mediator administrator account from the list
            let admins: Vec<String> = admins
                .accounts
                .iter()
                .filter_map(|x| {
                    if x.did_hash.as_bytes() != config.our_admin_hash.as_bytes()
                        && x.did_hash.as_bytes() != config.mediator_did_hash.as_bytes()
                    {
                        Some(x.did_hash.clone())
                    } else {
                        None
                    }
                })
                .collect();

            if admins.is_empty() {
                println!("{}", style("No Admin DIDs can be stripped").red());
                println!();
                return;
            }
            let dids = MultiSelect::with_theme(theme)
                .with_prompt("Select DIDs to remove (space to select, enter to continue)?")
                .items(&admins)
                .report(false)
                .interact()
                .unwrap();

            if dids.is_empty() {
                println!("{}", style("No Admin DIDs selected").red());
                return;
            }

            println!();
            println!(
                "{}",
                style("Stripping admin rights from the following DIDs:").green()
            );
            for did in &dids {
                println!("  {}", style(&admins[did.to_owned()]).yellow());
            }

            if Confirm::with_theme(theme)
                .with_prompt("Do you want to strip admin access from the selected DIDs?")
                .interact()
                .unwrap()
            {
                let admins = dids
                    .iter()
                    .map(|&idx| admins[idx].clone())
                    .collect::<Vec<_>>();
                match atm.mediator().strip_admins(profile, &admins).await {
                    Ok(result) => {
                        println!(
                            "{}",
                            style(format!("Stripped admin rights from {result} DIDs")).green()
                        );
                    }
                    Err(e) => {
                        println!("{}", style(format!("Error: {e}")).red());
                    }
                }
            }
        }
        Err(e) => {
            println!("{}", style(format!("Error: {e}")).red());
        }
    }
}

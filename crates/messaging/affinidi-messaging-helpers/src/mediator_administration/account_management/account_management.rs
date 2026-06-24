use crate::{SharedConfig, account_management::acl_management::manage_account_acls};
use affinidi_messaging_helpers::common::did::manually_enter_did_or_hash;
use affinidi_messaging_sdk::{ATM, profiles::ATMProfile};
use console::style;
use dialoguer::{Input, Select, theme::ColorfulTheme};
use regex::Regex;
use std::sync::Arc;
use trust_tasks_rs::specs::messaging::account;

/// All the `messaging/account/*` Trust Tasks return a per-module `Account` struct,
/// but they share one schema. This converts any of them back to the canonical
/// `account::get::v0_1::Account` we hold across the screen.
fn to_get_account<T: serde::Serialize>(a: &T) -> account::get::v0_1::Account {
    serde_json::from_value(serde_json::to_value(a).expect("serialize"))
        .expect("messaging Account types share one schema")
}

pub(crate) async fn account_management_menu(
    atm: &ATM,
    profile: &Arc<ATMProfile>,
    theme: &ColorfulTheme,
    mediator_config: &SharedConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let selections = &["Select and Manage Accounts", "Create an Account", "Back"];

    loop {
        println!();
        let selection = Select::with_theme(theme)
            .with_prompt("Select an action?")
            .default(0)
            .items(&selections[..])
            .interact()
            .unwrap();

        match selection {
            0 => {
                select_did(atm, profile, theme, mediator_config).await?;
            }
            1 => {
                create_account_menu(atm, profile, theme, mediator_config).await?;
            }
            2 => {
                return Ok(());
            }
            _ => {
                println!("Invalid selection");
            }
        }
    }
}

pub(crate) async fn create_account_menu(
    atm: &ATM,
    profile: &Arc<ATMProfile>,
    theme: &ColorfulTheme,
    mediator_config: &SharedConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let Some(new_did_hash) = manually_enter_did_or_hash(theme) else {
        println!("No new account created...");
        return Ok(());
    };

    // Does this account exist? A missing account is an Err, so existence is is_ok().
    if atm
        .trust_tasks()
        .account_get(profile, Some(new_did_hash.clone()))
        .await
        .is_ok()
    {
        println!(
            "{}",
            style("Account already exists on the Mediator").yellow()
        );
        return Ok(());
    }

    // Create the account
    let account = atm
        .trust_tasks()
        .account_add(
            profile,
            new_did_hash.clone(),
            account::add::v0_1::AccountType::Standard,
            None,
        )
        .await?;

    println!("{}", style("Created account successfully").green());

    manage_account_menu(atm, profile, theme, mediator_config, &to_get_account(&account)).await
}

pub(crate) async fn manage_account_menu(
    atm: &ATM,
    profile: &Arc<ATMProfile>,
    theme: &ColorfulTheme,
    mediator_config: &SharedConfig,
    account: &account::get::v0_1::Account,
) -> Result<(), Box<dyn std::error::Error>> {
    let selections = &[
        "Modify ACLs",
        "Change Account Type",
        "Change Queue Limits",
        "Delete Account",
        "Back",
    ];

    let mut account = account.clone();
    loop {
        println!();
        println!(
            "{} {}  {} {} {} {}",
            style("Selected DID: ").yellow(),
            style(account.did.as_str()).color256(208),
            style("ACL:").yellow(),
            style(format!("{:?}", account.acl)).blue().bold(),
            style("Access List Count:").yellow(),
            style(account.access_list_count.unwrap_or(0)).blue().bold()
        );

        println!(
            "{} {:<12} {} {} {} {}",
            style("Selected DID Account Type:").yellow(),
            style(account.account_type.to_string()).blue().bold(),
            style("Mediator ACL Mode:").yellow(),
            style(&mediator_config.acl_mode).blue().bold(),
            style("Default ACL:").yellow(),
            style(format!(
                "{:064b}",
                &mediator_config.global_acl_default.to_u64()
            ))
            .blue()
            .bold()
        );

        let queue_send_limit = account
            .queue_limits
            .as_ref()
            .and_then(|q| q.send_queue_limit);
        let queue_receive_limit = account
            .queue_limits
            .as_ref()
            .and_then(|q| q.receive_queue_limit);

        println!(
            "{} {} {} {} {} {} {} {} {} {} {} {} {}",
            style("Stats").yellow(),
            style("INBOX Count:").yellow(),
            style(account.receive_queue_count.unwrap_or(0)).blue().bold(),
            style("INBOX bytes").yellow(),
            style(account.receive_queue_bytes.unwrap_or(0)).blue().bold(),
            style("OUTBOX Count:").yellow(),
            style(account.receive_queue_count.unwrap_or(0)).blue().bold(),
            style("OUTBOX bytes").yellow(),
            style(account.receive_queue_bytes.unwrap_or(0)).blue().bold(),
            style("Send Q Limit:").yellow(),
            style(
                queue_send_limit
                    .unwrap_or(mediator_config.queued_send_messages_soft as i64)
            )
            .blue()
            .bold(),
            style("Receive Q Limit:").yellow(),
            style(
                queue_receive_limit
                    .unwrap_or(mediator_config.queued_receive_messages_soft as i64)
            )
            .blue()
            .bold()
        );

        println!();
        let selection = Select::with_theme(theme)
            .with_prompt("Select an action?")
            .default(0)
            .items(&selections[..])
            .interact()
            .unwrap();

        match selection {
            0 => {
                // Modify ACLs
                match manage_account_acls(atm, profile, theme, mediator_config, &account).await {
                    Ok(a) => {
                        account = a;
                    }
                    Err(err) => {
                        println!("{}", style(format!("Error modifying ACLs: {err}")).red())
                    }
                }
            }
            1 => {
                // Change Account Type
                match _change_account_type(atm, profile, theme, &account).await {
                    Ok(updated) => {
                        account = updated;
                    }
                    Err(err) => println!(
                        "{}",
                        style(format!("Error changing account type: {err}")).red()
                    ),
                }
            }
            2 => {
                // Change Queue Limits
                match _change_account_queue_limit(atm, profile, theme, &account).await {
                    Ok(Some(updated)) => {
                        account = updated;
                    }
                    Ok(None) => {}
                    Err(err) => println!(
                        "{}",
                        style(format!("Error changing account queue_limit: {err}")).red()
                    ),
                }
            }
            3 => {
                // Delete Account
                match atm
                    .trust_tasks()
                    .account_remove(profile, Some(account.did.as_str().to_string()))
                    .await
                {
                    Ok(_) => {
                        println!("{}", style("Account deleted successfully").green());
                        return Ok(());
                    }
                    Err(err) => {
                        println!("{}", style(format!("Error deleting account: {err}")).red())
                    }
                }
            }
            4 => {
                // Return to previous menu
                return Ok(());
            }
            _ => {
                println!("Invalid selection");
            }
        }
    }
}

async fn _change_account_type(
    atm: &ATM,
    profile: &Arc<ATMProfile>,
    theme: &ColorfulTheme,
    account: &account::get::v0_1::Account,
) -> Result<account::get::v0_1::Account, Box<dyn std::error::Error>> {
    let options = [
        account::change_type::v0_1::AccountType::Standard,
        account::change_type::v0_1::AccountType::Admin,
        account::change_type::v0_1::AccountType::RootAdmin,
        account::change_type::v0_1::AccountType::Mediator,
    ];

    let mut selections = options
        .iter()
        .map(|t| t.to_string())
        .collect::<Vec<String>>();

    selections.push("Back".to_string());

    let selection = Select::with_theme(theme)
        .with_prompt("Select Account Type?")
        .default(0)
        .items(&selections[..])
        .interact()
        .unwrap();

    if selection == selections.len() - 1 {
        // No change, exit gracefully
        return Ok(account.clone());
    }

    let new_type = options[selection];
    println!("Changing account type to: {new_type}");

    // Compare current account type to the requested one (variants are equivalent
    // across modules, so compare via their string representation).
    if new_type.to_string() == account.account_type.to_string() {
        // No change, exit gracefully
        Ok(account.clone())
    } else {
        let updated = atm
            .trust_tasks()
            .account_change_type(profile, account.did.as_str().to_string(), new_type)
            .await
            .map_err(|e| e.to_string())?;
        println!("{}", style("Account type changed successfully").green());
        Ok(to_get_account(&updated))
    }
}

async fn _change_account_queue_limit(
    atm: &ATM,
    profile: &Arc<ATMProfile>,
    theme: &ColorfulTheme,
    account: &account::get::v0_1::Account,
) -> Result<Option<account::get::v0_1::Account>, Box<dyn std::error::Error>> {
    let send_input = Input::with_theme(theme)
        .with_prompt("New Send Queue Limit? (-2 = Reset, -1 = Unlimited, n = limit, blank = no change, exit = cancel")
        .validate_with(|input: &String| -> Result<(), &str> {
            let re = Regex::new(r"\d*|exit").unwrap();
            if input == "exit" || input.is_empty() {
                Ok(())
            } else if re.is_match(input) {
                match input.parse::<i64>() {
                    Ok(limit) => {
                        if limit < -2 {
                            Err("Invalid queue limit")
                        } else {
                            Ok(())
                        }
                    }
                    Err(_) => {
                        Err("Couldn't parse queue_limit")
                    }
                }
            } else {
                Err("Invalid queue limit")
            }
        }).allow_empty(true)
        .interact_text()
        .unwrap();

    if send_input == "exit" {
        return Ok(None);
    }

    println!("Changing account send queue_limit to: {send_input}");
    let send_queue_limit: Option<i64> = if send_input.is_empty() {
        None
    } else {
        match send_input.parse::<i64>() {
            Ok(limit) => Some(limit),
            Err(e) => {
                println!("{}", style(format!("Couldn't parse number: {e}")).red());
                return Err("Couldn't parse queue_limit".into());
            }
        }
    };

    let receive_input = Input::with_theme(theme)
        .with_prompt("New Receive Queue Limit? (-2 = Reset, -1 = Unlimited, n = limit, blank = no change, exit = cancel")
        .validate_with(|input: &String| -> Result<(), &str> {
            let re = Regex::new(r"\d*|exit").unwrap();
            if input == "exit" || input.is_empty() {
                Ok(())
            } else if re.is_match(input) {
                match input.parse::<i64>() {
                    Ok(limit) => {
                        if limit < -2 {
                            Err("Invalid queue limit")
                        } else {
                            Ok(())
                        }
                    }
                    Err(_) => {
                        Err("Couldn't parse queue_limit")
                    }
                }
            } else {
                Err("Invalid queue limit")
            }
        }).allow_empty(true)
        .interact_text()
        .unwrap();

    if receive_input == "exit" {
        return Ok(None);
    }

    println!("Changing account receive queue_limit to: {receive_input}");
    let receive_queue_limit: Option<i64> = if receive_input.is_empty() {
        None
    } else {
        match receive_input.parse::<i64>() {
            Ok(limit) => Some(limit),
            Err(e) => {
                println!("{}", style(format!("Couldn't parse number: {e}")).red());
                return Err("Couldn't parse queue_limit".into());
            }
        }
    };

    let updated = atm
        .trust_tasks()
        .account_change_queue_limits(
            profile,
            Some(account.did.as_str().to_string()),
            send_queue_limit,
            receive_queue_limit,
        )
        .await
        .map_err(|e| e.to_string())?;
    println!(
        "{}",
        style(format!(
            "Account queue_limits changed successfully {updated:#?}"
        ))
        .green()
    );
    Ok(Some(to_get_account(&updated)))
}

/// Picks the target DID
/// returns the selected DID Hash
/// returns None if the user cancels the selection
pub(crate) async fn select_did(
    atm: &ATM,
    profile: &Arc<ATMProfile>,
    theme: &ColorfulTheme,
    mediator_config: &SharedConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    loop {
        let selection = Select::with_theme(theme)
            .with_prompt("Select an action?")
            .default(0)
            .items([
                "Scan existing DIDs on Mediator?",
                "Manually enter DID or DID Hash?",
                "Back",
            ])
            .interact()
            .unwrap();

        match selection {
            0 => {
                println!("Scan existing DIDs on Mediator");

                if let Some(account) =
                    _select_from_existing_dids(atm, profile, theme, None, mediator_config).await?
                {
                    manage_account_menu(atm, profile, theme, mediator_config, &account).await?;
                }
            }
            1 => {
                if let Some(did_hash) = manually_enter_did_or_hash(theme) {
                    // Look up the Account for this DID (a missing account is an Err)
                    if let Ok(account) =
                        atm.trust_tasks().account_get(profile, Some(did_hash)).await
                    {
                        manage_account_menu(atm, profile, theme, mediator_config, &account).await?;
                    }
                }
            }
            2 => return Ok(()),
            _ => {
                println!("Invalid selection");
            }
        }
    }
}

async fn _select_from_existing_dids(
    atm: &ATM,
    profile: &Arc<ATMProfile>,
    theme: &ColorfulTheme,
    cursor: Option<String>,
    mediator_config: &SharedConfig,
) -> Result<Option<account::get::v0_1::Account>, Box<dyn std::error::Error>> {
    let dids = atm
        .trust_tasks()
        .account_list(profile, cursor, Some(2))
        .await?;

    if dids.accounts.is_empty() {
        println!("{}", style("No DIDs found").red());
        println!();
        return Ok(None);
    }

    let mut did_list: Vec<String> = Vec::new();
    for account in &dids.accounts {
        let blocked = account.acl.blocked.unwrap_or(false);
        let local = account.acl.local.unwrap_or(false);

        did_list.push(format!(
            "{} {} {:^8} {:^6} {:?}",
            account.did.as_str(),
            style(format!("{:^12}", account.account_type.to_string())).blue(),
            if blocked {
                style("Yes").red().bold()
            } else {
                style("No").green()
            },
            if local {
                style("Yes").green().bold()
            } else {
                style("No").red()
            },
            style(format!("{:?}", account.acl)).cyan(),
        ));
    }
    let mut load_more_flag = false;
    let next_cursor = dids.next_cursor.as_ref().map(|c| c.to_string());
    if next_cursor.is_some() {
        did_list.push("Load more DIDs...".to_string());
        load_more_flag = true;
    }

    did_list.push("Back".to_string());

    println!(
        "  DID SHA-256 Hash                                                 Account Type Blocked? Local? ACL Flags"
    );
    let selected = Select::with_theme(theme)
        .with_prompt("Select DID (space to select, enter to continue)?")
        .items(&did_list)
        .interact()
        .unwrap();

    if selected == did_list.len() - 2 && load_more_flag {
        Box::pin(_select_from_existing_dids(
            atm,
            profile,
            theme,
            next_cursor,
            mediator_config,
        ))
        .await
    } else if selected == did_list.len() - 1 {
        // Exit gracefully
        Ok(None)
    } else {
        Ok(Some(to_get_account(&dids.accounts[selected])))
    }
}

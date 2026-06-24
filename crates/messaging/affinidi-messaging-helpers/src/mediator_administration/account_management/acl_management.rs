/*!
 * Handles ACL management tasks for an account
 */

use crate::SharedConfig;
use affinidi_messaging_helpers::common::did::manually_enter_did_or_hash;
use affinidi_messaging_sdk::{ATM, profiles::ATMProfile};
use console::style;
use dialoguer::{MultiSelect, Select, theme::ColorfulTheme};
use std::sync::Arc;
use trust_tasks_rs::specs::messaging::{account, acl};

/// Convert a partial / per-module `MediatorAcl` into the canonical
/// `account::get::v0_1::MediatorAcl` we hold on the account across the screen.
fn to_get_acl<T: serde::Serialize>(acl: &T) -> account::get::v0_1::MediatorAcl {
    serde_json::from_value(serde_json::to_value(acl).expect("serialize"))
        .expect("messaging MediatorAcl types share one schema")
}

pub(crate) async fn manage_account_acls(
    atm: &ATM,
    profile: &Arc<ATMProfile>,
    theme: &ColorfulTheme,
    mediator_config: &SharedConfig,
    account: &account::get::v0_1::Account,
) -> Result<account::get::v0_1::Account, Box<dyn std::error::Error>> {
    let selections = &[
        "Modify ACL Flags",
        "Access List - List",
        "Access List - Add",
        "Access List - Remove",
        "Access List - Search",
        "Access List - Clear",
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

        println!();

        let selection = Select::with_theme(theme)
            .with_prompt("Select an action?")
            .default(0)
            .items(&selections[..])
            .interact()
            .unwrap();

        match selection {
            0 => {
                // Modify ACL Flags
                account.acl = _modify_acl_flags(atm, profile, theme, &account).await?;
            }
            1 => {
                // Access List - List
                _access_list_list(atm, profile, &account).await?;
            }
            2 => {
                // Access List - Add
                if _access_list_add(atm, profile, theme, &account)
                    .await?
                    .is_some()
                {
                    account.access_list_count = Some(account.access_list_count.unwrap_or(0) + 1);
                }
            }
            3 => {
                // Access List - Remove
                let removed = _access_list_remove(atm, profile, theme, &account).await? as u64;
                account.access_list_count =
                    Some(account.access_list_count.unwrap_or(0).saturating_sub(removed));
            }
            4 => {
                // Access List - Search
                _access_list_get(atm, profile, theme, &account).await?;
            }
            5 => {
                // Access List - Clear
                _access_list_clear(atm, profile, &account).await?;
                account.access_list_count = Some(0);
            }
            6 => break,
            _ => println!("Invalid selection"),
        }
    }
    Ok(account)
}

async fn _modify_acl_flags(
    atm: &ATM,
    profile: &Arc<ATMProfile>,
    theme: &ColorfulTheme,
    account: &account::get::v0_1::Account,
) -> Result<account::get::v0_1::MediatorAcl, Box<dyn std::error::Error>> {
    println!("self-change? : If set, allows the DID to change its own ACL flag");

    let acl = &account.acl;
    let selections = [
        (
            "Access List Mode: explicit_deny if set, explicit_allow if not",
            acl.access_list_mode
                == Some(account::get::v0_1::MediatorAclAccessListMode::ExplicitDeny),
        ),
        (
            "blocked - DID is blocked from authentication?",
            acl.blocked.unwrap_or(false),
        ),
        (
            "local - DID is able to store messages locally?",
            acl.local.unwrap_or(false),
        ),
        ("send_messages?", acl.send_messages.unwrap_or(false)),
        ("receive_messages?", acl.receive_messages.unwrap_or(false)),
        (
            "send_forwarded_messages?",
            acl.send_forwarded.unwrap_or(false),
        ),
        (
            "receive_forwarded_messages?",
            acl.receive_forwarded.unwrap_or(false),
        ),
        ("create_invites?", acl.create_invites.unwrap_or(false)),
        (
            "anon_receive_messages?",
            acl.anon_receive.unwrap_or(false),
        ),
        (
            "access_list self-change?",
            acl.self_manage_list.unwrap_or(false),
        ),
        (
            "queue send limits self-change?",
            acl.self_manage_send_queue_limit.unwrap_or(false),
        ),
        (
            "queue receive limits self-change?",
            acl.self_manage_receive_queue_limit.unwrap_or(false),
        ),
    ];

    // returns a vector of chosen indices
    let selection = MultiSelect::with_theme(theme)
        .with_prompt("Select an action? (space to select, enter to confirm)")
        .items_checked(selections)
        .report(false)
        .interact()
        .unwrap();

    // convert the selection to an array of bools
    let mut flags = [false; 12];
    for s in selection {
        flags[s] = true;
    }

    // Build a full ACL set from the chosen flags.
    let new_acl = acl::set::v0_1::MediatorAcl {
        access_list_mode: Some(if flags[0] {
            acl::set::v0_1::MediatorAclAccessListMode::ExplicitDeny
        } else {
            acl::set::v0_1::MediatorAclAccessListMode::ExplicitAllow
        }),
        blocked: Some(flags[1]),
        local: Some(flags[2]),
        send_messages: Some(flags[3]),
        receive_messages: Some(flags[4]),
        send_forwarded: Some(flags[5]),
        receive_forwarded: Some(flags[6]),
        create_invites: Some(flags[7]),
        anon_receive: Some(flags[8]),
        self_manage_list: Some(flags[9]),
        self_manage_send_queue_limit: Some(flags[10]),
        self_manage_receive_queue_limit: Some(flags[11]),
        ..Default::default()
    };

    // Compare against the current ACL (both normalised to JSON; MediatorAcl
    // does not derive PartialEq).
    if serde_json::to_value(to_get_acl(&new_acl)).ok()
        == serde_json::to_value(&account.acl).ok()
    {
        println!("{}", style("No changes made").yellow());
        return Ok(account.acl.clone());
    }
    println!("New ACLs: {new_acl:?}");

    match atm
        .trust_tasks()
        .acl_set(profile, account.did.as_str().to_string(), new_acl.clone())
        .await
    {
        Ok(updated) => {
            println!("{}", style("ACLs updated").green());
            Ok(to_get_acl(&updated))
        }
        Err(e) => {
            println!("{}", style(format!("Error updating ACLs: {e}")).red());
            Ok(to_get_acl(&new_acl))
        }
    }
}

async fn _access_list_list(
    atm: &ATM,
    profile: &Arc<ATMProfile>,
    account: &account::get::v0_1::Account,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut cursor: Option<String> = None;
    loop {
        let list = atm
            .trust_tasks()
            .access_list_list(profile, Some(account.did.as_str().to_string()), cursor, None)
            .await?;

        for hash in &list.entries {
            println!("{}", style(hash.as_str()).blue());
        }

        if let Some(next_cursor) = list.next_cursor {
            cursor = Some(next_cursor.to_string());
        } else {
            break;
        }
    }
    Ok(())
}

async fn _access_list_add(
    atm: &ATM,
    profile: &Arc<ATMProfile>,
    theme: &ColorfulTheme,
    account: &account::get::v0_1::Account,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    if let Some(hash) = manually_enter_did_or_hash(theme) {
        atm.trust_tasks()
            .access_list_add(
                profile,
                Some(account.did.as_str().to_string()),
                vec![hash.clone()],
            )
            .await?;
        Ok(Some(hash))
    } else {
        Ok(None)
    }
}

async fn _access_list_remove(
    atm: &ATM,
    profile: &Arc<ATMProfile>,
    theme: &ColorfulTheme,
    account: &account::get::v0_1::Account,
) -> Result<usize, Box<dyn std::error::Error>> {
    if let Some(hash) = manually_enter_did_or_hash(theme) {
        let response = atm
            .trust_tasks()
            .access_list_remove(
                profile,
                Some(account.did.as_str().to_string()),
                vec![hash],
            )
            .await?;
        Ok(response.removed.len())
    } else {
        Ok(0)
    }
}

async fn _access_list_get(
    atm: &ATM,
    profile: &Arc<ATMProfile>,
    theme: &ColorfulTheme,
    account: &account::get::v0_1::Account,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(hash) = manually_enter_did_or_hash(theme) {
        let result = atm
            .trust_tasks()
            .access_list_get(
                profile,
                Some(account.did.as_str().to_string()),
                vec![hash],
            )
            .await?;

        println!("{}", style("DID Hashes Found:").blue());
        for hash in &result.present {
            println!("  {}", style(hash.as_str()).blue());
        }
        if result.present.is_empty() {
            println!("{}", style("No DID Hashes found").yellow());
        }
    }
    Ok(())
}

async fn _access_list_clear(
    atm: &ATM,
    profile: &Arc<ATMProfile>,
    account: &account::get::v0_1::Account,
) -> Result<(), Box<dyn std::error::Error>> {
    atm.trust_tasks()
        .access_list_clear(profile, Some(account.did.as_str().to_string()))
        .await?;
    Ok(())
}

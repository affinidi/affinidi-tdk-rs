/*!
*   Tasks relating to editing an existing webvh DID go here
*/
use crate::{
    ConfigInfo, edit_did_document,
    updating::{
        authorization::update_authorization_keys, watchers::modify_watcher_params,
        witness::modify_witness_params,
    },
};
use anyhow::Result;
use console::style;
use dialoguer::{Confirm, Input, Select, theme::ColorfulTheme};
use did_webvh::{DIDWebVHError, log_entry::LogEntry, parameters::Parameters};

mod authorization;
mod watchers;
mod witness;

pub async fn edit_did() -> Result<()> {
    let file_path: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("DID LogEntry File?")
        .default("did.jsonl".to_string())
        .interact()
        .unwrap();

    let (log_entry, meta_data) = LogEntry::get_log_entry_from_file(&file_path, None, None, None)?;

    // Load the secrets
    let mut config_info = ConfigInfo::read_from_file("secrets.json")
        .map_err(|e| DIDWebVHError::ParametersError(format!("Failed to read secrets: {}", e)))?;

    println!(
        "{}\n{}",
        style("Log Entry Parameters:").color256(69),
        style(serde_json::to_string_pretty(&log_entry.parameters).unwrap()).color256(34),
    );
    println!();
    println!(
        "{}\n{}\n\n{}",
        style("Log Entry Metadata:").color256(69),
        style(serde_json::to_string_pretty(&meta_data).unwrap()).color256(34),
        style("Successfully Loaded").color256(34).blink(),
    );

    println!();

    let menu = vec![
        "Create a new Log Entry (Modify DID Document or Parameters)?",
        "Move to a new domain (portability)?",
        "Revoke this DID?",
        "Back",
    ];

    loop {
        let selection = Select::with_theme(&ColorfulTheme::default())
            .with_prompt("Action")
            .items(&menu)
            .default(0)
            .interact()
            .unwrap();

        match selection {
            0 => {
                create_log_entry(&log_entry, &mut config_info)?;
            }
            1 => {
                println!("{}", style("Migrate to a new domain").color256(69));
            }
            2 => {
                println!("{}", style("Revoke this DID").color256(69));
            }
            3 => {
                break;
            }
            _ => {
                println!("{}", style("Invalid selection...").color256(196));
                continue;
            }
        }
    }

    Ok(())
}

fn create_log_entry(log_entry: &LogEntry, config_info: &mut ConfigInfo) -> Result<()> {
    println!(
        "{}",
        style("Modifying DID Document and/or Parameters").color256(69)
    );

    // ************************************************************************
    // Change the DID Document?
    // ************************************************************************
    let new_state = if Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt("Edit the DID Document?")
        .default(false)
        .interact()?
    {
        edit_did_document(&log_entry.state)?
    } else {
        log_entry.state.clone()
    };

    // ************************************************************************
    // Change webvh Parameters
    // ************************************************************************
    let new_params = update_parameters(log_entry, config_info)?;
    let diff_params = log_entry.parameters.diff(&new_params)?;
    println!("{}", serde_json::to_string_pretty(&diff_params).unwrap());

    Ok(())
}

/// Run UI for creating new parameter set
/// Returns: New Parameters
fn update_parameters(old_log_entry: &LogEntry, secrets: &mut ConfigInfo) -> Result<Parameters> {
    let mut new_params = Parameters::default();

    // ************************************************************************
    // Portability
    // ************************************************************************
    update_authorization_keys(old_log_entry, &mut new_params, secrets)?;
    println!(
        "{}{}{}",
        style("Pre-rotation (").color256(69),
        if new_params.pre_rotation_active {
            style("enabled").color256(34)
        } else {
            style("disabled").color256(214)
        },
        style(")").color256(69)
    );
    println!(
        "{}\n{}",
        style("nextKeyHashes: ").color256(69),
        style(serde_json::to_string_pretty(&new_params.next_key_hashes).unwrap()).color256(34)
    );
    println!(
        "{}\n{}",
        style("updateKeys: ").color256(69),
        style(serde_json::to_string_pretty(&new_params.update_keys).unwrap()).color256(34)
    );

    // ************************************************************************
    // Portability
    // ************************************************************************
    if let Some(portable) = old_log_entry.parameters.portable {
        if portable {
            // Portable
            if Confirm::with_theme(&ColorfulTheme::default())
                .with_prompt("Disable portability for this DID?")
                .default(false)
                .interact()
                .map_err(|e| {
                    DIDWebVHError::ParametersError(format!(
                        "Invalid selection on portability: {}",
                        e
                    ))
                })?
            {
                // Disable portability
                new_params.portable = Some(false);
            } else {
                // Keep portability
                new_params.portable = Some(true);
            }
        }
    }

    // ************************************************************************
    // Witnesses
    // ************************************************************************
    let old_witness = if let Some(witnesses) = &old_log_entry.parameters.witness {
        witnesses
    } else {
        &None
    };

    modify_witness_params(old_witness.as_ref(), &mut new_params, secrets)?;

    // ************************************************************************
    // Watchers
    // ************************************************************************
    let old_watchers = if let Some(watchers) = &old_log_entry.parameters.watchers {
        watchers
    } else {
        &None
    };

    modify_watcher_params(old_watchers.as_ref(), &mut new_params)?;

    // ************************************************************************
    // TTL
    // ************************************************************************
    modify_ttl_params(&old_log_entry.parameters.ttl, &mut new_params)?;

    Ok(new_params)
}

/// Modify the TTL for this DID?
fn modify_ttl_params(ttl: &Option<u32>, params: &mut Parameters) -> Result<()> {
    print!("{}", style("Existing TTL: ").color256(69));
    let current_ttl = if let Some(ttl) = ttl {
        println!("{}", style(ttl).color256(34));
        ttl.to_owned()
    } else {
        println!("{}", style("NOT SET").color256(214));
        0_u32
    };

    if Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt("Change the TTL?")
        .default(false)
        .interact()?
    {
        let new_ttl: u32 = Input::with_theme(&ColorfulTheme::default())
            .with_prompt("New TTL (0 = Disable TTL)?")
            .default(current_ttl)
            .interact()?;

        if new_ttl == 0 {
            // Disable TTL
            params.ttl = None;
        } else {
            // Set new TTL
            params.ttl = Some(new_ttl);
        }
    } else {
        // Keep existing TTL
        if current_ttl == 0 {
            params.ttl = None;
        } else {
            params.ttl = Some(current_ttl);
        }
    }

    Ok(())
}

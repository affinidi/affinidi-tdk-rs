/*!
*   Tasks relating to editing an existing webvh DID go here
*/
use crate::{
    ConfigInfo, edit_did_document,
    updating::{authorization::update_authorization_keys, witness::modify_witness_params},
};
use anyhow::Result;
use console::style;
use dialoguer::{Confirm, Input, Select, theme::ColorfulTheme};
use did_webvh::{DIDWebVHError, log_entry::LogEntry, parameters::Parameters};

mod authorization;
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
        "Modify DID",
        "Move to a new domain (portability)?",
        "Revoke this DID?",
        "Back",
    ];

    loop {
        let selection = Select::with_theme(&ColorfulTheme::default())
            .with_prompt("Editing DID")
            .items(&menu)
            .default(0)
            .interact()
            .unwrap();

        match selection {
            0 => {
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
                let new_params = update_parameters(&log_entry, &mut config_info)?;
                let diff_params = log_entry.parameters.diff(&new_params)?;
                println!("{}", serde_json::to_string_pretty(&diff_params).unwrap());
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

    // ************************************************************************
    // TTL
    // ************************************************************************

    Ok(new_params)
}

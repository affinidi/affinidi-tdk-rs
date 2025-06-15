/*!
*   Tasks relating to editing an existing webvh DID go here
*/
use affinidi_secrets_resolver::secrets::Secret;
use anyhow::{Result, bail};
use console::style;
use dialoguer::{Confirm, Editor, Input, MultiSelect, Select, theme::ColorfulTheme};
use did_webvh::{DIDWebVHError, log_entry::LogEntry, parameters::Parameters};

use crate::{ConfigInfo, edit_did_document};

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
                let new_state = edit_did_document(&log_entry.state)?;
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

    // Update Keys
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

    // Turn portability off
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

    Ok(new_params)
}

/// Handles all possible states of updating updateKeys including pre-rotation and non-pre-rotation
/// modes. updateKeys and NextKeyHashes are modified here
/// Returns authorization key for this update
fn update_authorization_keys(
    old_log_entry: &LogEntry,
    new_params: &mut Parameters,
    existing_secrets: &mut ConfigInfo,
) -> Result<()> {
    // What mode are we operating in?
    if old_log_entry.parameters.pre_rotation_active {
        // Pre-Rotation mode

        // Disable pre-rotation mode?
        if Confirm::with_theme(&ColorfulTheme::default())
            .with_prompt("Disable pre-rotation mode?")
            .default(false)
            .interact()?
        {
            // Disabling pre-rotation mode
            new_params.pre_rotation_active = false;
            new_params.next_key_hashes = Some(None);
            let update_keys = select_update_keys_from_next_hashes(
                &old_log_entry.parameters.next_key_hashes,
                &existing_secrets
                    .update_keys
                    .get(&old_log_entry.version_id)
                    .unwrap_or(&Vec::new()),
            )?;
            let mut tmp_keys = Vec::new();
            for key in update_keys {
                tmp_keys.push(key.get_public_keymultibase()?);
            }
            new_params.update_keys = Some(Some(tmp_keys));
            return Ok(());
        }
    } else {
        // Non pre-rotation mode
    }
    Ok(())
}

/// What update key will we use? Must be from an existing set of keys authorized keys
/// Returns array of Secrets
fn select_update_keys_from_next_hashes(
    next_key_hashes: &Option<Option<Vec<String>>>,
    existing_secrets: &[Secret],
) -> Result<Vec<Secret>> {
    let Some(Some(hashes)) = next_key_hashes else {
        bail!("No next key hashes found for pre-rotation mode".to_string());
    };

    let selected = MultiSelect::with_theme(&ColorfulTheme::default())
        .with_prompt("Which pre-rotated keys do you want to use for this LogEntry update?")
        .items(hashes)
        .interact()
        .unwrap();

    let mut selected_secrets = Vec::new();
    for i in selected {
        ConfigInfo::find_secret(&hashes[i], existing_secrets)
            .map(|secret| selected_secrets.push(secret))
            .ok_or_else(|| {
                DIDWebVHError::ParametersError(format!(
                    "Couldn't find a matching Secret key for hash: {}",
                    hashes[i]
                ))
            })?;
    }

    Ok(selected_secrets)
}

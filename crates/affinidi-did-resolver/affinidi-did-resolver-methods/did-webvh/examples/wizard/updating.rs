/*!
*   Tasks relating to editing an existing webvh DID go here
*/
use affinidi_secrets_resolver::secrets::Secret;
use anyhow::{Result, bail};
use console::style;
use dialoguer::{Confirm, Input, MultiSelect, Select, theme::ColorfulTheme};
use did_webvh::{DIDWebVHError, log_entry::LogEntry, parameters::Parameters};

use crate::{ConfigInfo, create_next_key_hashes, edit_did_document, get_keys};

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
                let new_state = if Confirm::with_theme(&ColorfulTheme::default())
                    .with_prompt("Edit the DID Document?")
                    .default(false)
                    .interact()?
                {
                    edit_did_document(&log_entry.state)?
                } else {
                    log_entry.state.clone()
                };
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

    // updateKeys and nextKeyHashes
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
                existing_secrets,
            )?;
            let mut tmp_keys = Vec::new();
            for key in update_keys {
                tmp_keys.push(key.get_public_keymultibase()?);
            }
            new_params.update_keys = Some(Some(tmp_keys.clone()));
            new_params.active_update_keys = tmp_keys;
        } else {
            // Staying in pre-rotation mode
            new_params.pre_rotation_active = true;

            // Select update_keys for this update
            let update_keys = select_update_keys_from_next_hashes(
                &old_log_entry.parameters.next_key_hashes,
                existing_secrets,
            )?;
            let mut tmp_keys = Vec::new();
            for key in update_keys {
                tmp_keys.push(key.get_public_keymultibase()?);
            }
            new_params.update_keys = Some(Some(tmp_keys.clone()));
            new_params.active_update_keys = tmp_keys;

            // Create new next_key_hashes
            let next_key_hashes = create_next_key_hashes(existing_secrets)?;
            if next_key_hashes.is_empty() {
                bail!("No next key hashes created for pre-rotation mode");
            }
            new_params.next_key_hashes = Some(Some(next_key_hashes.clone()));
        }
    } else {
        // Non pre-rotation mode
        new_params.active_update_keys = old_log_entry.parameters.active_update_keys.clone();
        new_params.pre_rotation_active = false;

        // Do you want to enable pre-rotation mode?
        if Confirm::with_theme(&ColorfulTheme::default())
            .with_prompt("Enable pre-rotation mode?")
            .default(false)
            .interact()?
        {
            // Enable pre-rotation mode
            new_params.update_keys = None;
            let next_key_hashes = create_next_key_hashes(existing_secrets)?;
            if next_key_hashes.is_empty() {
                bail!("No next key hashes created for pre-rotation mode");
            }
            new_params.next_key_hashes = Some(Some(next_key_hashes.clone()));
        } else {
            // Stay in non pre-rotation mode
            // check if modify updateKeys
            modify_update_keys(new_params, existing_secrets)?;
        }
    }
    Ok(())
}

/// What update key will we use? Must be from an existing set of keys authorized keys
/// Returns array of Secrets
fn select_update_keys_from_next_hashes(
    next_key_hashes: &Option<Option<Vec<String>>>,
    existing_secrets: &ConfigInfo,
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
        existing_secrets
            .find_secret_by_hash(&hashes[i])
            .map(|secret| selected_secrets.push(secret.to_owned()))
            .ok_or_else(|| {
                DIDWebVHError::ParametersError(format!(
                    "Couldn't find a matching Secret key for hash: {}",
                    hashes[i]
                ))
            })?;
    }

    Ok(selected_secrets)
}

/// Any changes to the updateKeys?
fn modify_update_keys(params: &mut Parameters, existing_secrets: &mut ConfigInfo) -> Result<()> {
    if Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt("Do you want to change authorization keys going forward from this update?")
        .default(false)
        .interact()?
    {
        let mut new_update_keys = Vec::new();

        let selected = MultiSelect::with_theme(&ColorfulTheme::default())
            .with_prompt("Which existing authorization keys do you want to keep?")
            .items(&params.active_update_keys)
            .interact()
            .unwrap();

        // Add new keys
        for i in selected {
            new_update_keys.push(params.active_update_keys[i].clone());
        }

        // Do we want to add new keys?
        if Confirm::with_theme(&ColorfulTheme::default())
            .with_prompt("Would you like to create new update keys to add to the authorized keys?")
            .default(false)
            .interact()?
        {
            let keys = get_keys()?;
            for k in keys {
                new_update_keys.push(k.get_public_keymultibase()?);
                existing_secrets.add_key(&k);
            }
        }

        params.update_keys = Some(Some(new_update_keys));
    } else {
        // No changes made to existing authorization keys
        params.update_keys = None;
    }

    Ok(())
}

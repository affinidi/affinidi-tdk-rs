/*!
*   Revokes a webvh DID, this means it can no longer be updated or is valid from that date.
*
*   If key pre-rotation is in place, then two new LogEntries will be created
*   1. Stop key rotation
*   2. Deactivate the DID
*/

use anyhow::{Result, anyhow, bail};
use console::style;
use dialoguer::{Confirm, theme::ColorfulTheme};
use did_webvh::{DIDWebVHState, parameters::Parameters};

use crate::ConfigInfo;

/// Revokes a webvh DID method
pub async fn revoke_did(
    file_path: &str,
    didwebvh: &mut DIDWebVHState,
    secrets: &ConfigInfo,
) -> Result<()> {
    println!(
        "{}",
        style("** DANGER ** : You are about to revoke a DID!")
            .color256(9)
            .blink()
    );

    let last_entry = didwebvh
        .log_entries
        .last()
        .ok_or_else(|| anyhow!("No LogEntries found!"))?;

    let our_did = if let Some(did) = last_entry.log_entry.state.get("id") {
        if let Some(did) = did.as_str() {
            did.to_string()
        } else {
            bail!("Couldn't convert DID to string!");
        }
    } else {
        bail!("Couldn't find ID in DID Document!");
    };

    if Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt(format!(
            "Are you sure you want to deactivate the DID({})?",
            our_did
        ))
        .default(false)
        .interact()?
    {
        if last_entry.log_entry.parameters.pre_rotation_active {
            // Need to deactivate pre-rotation
            println!(
                "{}",
                style("Key pre-rotation is active, must disable first! disabling...").color256(214)
            );
            deactivate_pre_rotation(didwebvh, secrets).await?;
            if let Some(log_entry) = didwebvh.log_entries.last() {
                log_entry.log_entry.save_to_file(file_path)?;
                println!(
                    "{}{}{}",
                    style(&log_entry.log_entry.version_id).color256(141),
                    style(": ").color256(69),
                    style("Key Pre-rotation has been disabled").color256(34)
                );
            } else {
                bail!("SDK Error: Should be a LogEntry here!");
            }
        }

        // Revoke the DID!
        revoke_entry(didwebvh, secrets).await?;
        if let Some(log_entry) = didwebvh.log_entries.last() {
            log_entry.log_entry.save_to_file(file_path)?;
            println!(
                "{}{}{}{}{}",
                style(&log_entry.log_entry.version_id).color256(141),
                style(": ").color256(69),
                style("DID (").color256(9),
                style(&our_did).color256(141),
                style(") has been revoked!").color256(9)
            );
        } else {
            bail!("SDK Error: Should be a LogEntry here!");
        }
    }
    Ok(())
}

/// Creates a LogEntry that turns off pre-rotation
async fn deactivate_pre_rotation(didwebvh: &mut DIDWebVHState, secrets: &ConfigInfo) -> Result<()> {
    let last_entry = didwebvh
        .log_entries
        .last()
        .ok_or_else(|| anyhow!("No LogEntries found!"))?;

    // Create new Parameters with a valid updateKey from previous LogEntry
    let new_update_key =
        if let Some(Some(next_key_hashes)) = &last_entry.log_entry.parameters.next_key_hashes {
            if let Some(hash) = next_key_hashes.first() {
                if let Some(secret) = secrets.find_secret_by_hash(hash) {
                    secret.to_owned()
                } else {
                    bail!("No secret found for next key hash: {}", hash);
                }
            } else {
                bail!("No next key hashes available!");
            }
        } else {
            bail!("Expecting nextKeyHashes, but doesn't exist!");
        };

    let new_params = Parameters {
        update_keys: Some(Some(vec![new_update_key.get_public_keymultibase()?])),
        ..Default::default()
    };

    didwebvh
        .create_log_entry(
            None,
            &last_entry.log_entry.state.clone(),
            &new_params,
            &new_update_key,
        )
        .map_err(|e| anyhow!("Couldn't create LogEntry: {}", e))?;

    Ok(())
}

/// Final LogEntry
async fn revoke_entry(didwebvh: &mut DIDWebVHState, secrets: &ConfigInfo) -> Result<()> {
    let last_entry = didwebvh
        .log_entries
        .last()
        .ok_or_else(|| anyhow!("No LogEntries found!"))?;

    // Create new Parameters with a valid updateKey from previous LogEntry
    let new_update_key =
        if let Some(Some(update_keys)) = &last_entry.log_entry.parameters.update_keys {
            if let Some(key) = update_keys.first() {
                if let Some(secret) = secrets.find_secret_by_public_key(key) {
                    secret.to_owned()
                } else {
                    bail!("No secret found for update key: {}", key);
                }
            } else {
                bail!("No update key available!");
            }
        } else {
            bail!("Expecting updateKeys, but doesn't exist!");
        };

    let new_params = Parameters {
        deactivated: true,
        ..Default::default()
    };

    didwebvh
        .create_log_entry(
            None,
            &last_entry.log_entry.state.clone(),
            &new_params,
            &new_update_key,
        )
        .map_err(|e| anyhow!("Couldn't create LogEntry: {}", e))?;

    Ok(())
}

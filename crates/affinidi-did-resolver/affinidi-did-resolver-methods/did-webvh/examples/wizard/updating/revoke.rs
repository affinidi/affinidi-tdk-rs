/*!
*   Revokes a webvh DID, this means it can no longer be updated or is valid from that date.
*
*   If key pre-rotation is in place, then two new LogEntries will be created
*   1. Stop key rotation
*   2. Deactivate the DID
*/

use anyhow::{Result, bail};
use console::style;
use dialoguer::{Confirm, theme::ColorfulTheme};
use did_webvh::{log_entry::LogEntry, parameters::Parameters};

use crate::ConfigInfo;

/// Revokes a webvh DID method
pub async fn revoke_did(file_path: &str, log_entry: &LogEntry, secrets: &ConfigInfo) -> Result<()> {
    println!(
        "{}",
        style("** DANGER ** : You are about to revoke a DID!")
            .color256(9)
            .blink()
    );

    let our_did = if let Some(did) = log_entry.state.get("id") {
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
        let log_entry = if log_entry.parameters.pre_rotation_active {
            // Need to deactivate pre-rotation
            println!(
                "{}",
                style("Key pre-rotation is active, must disable first! disabling...").color256(214)
            );
            let new_entry = deactivate_pre_rotation(log_entry, secrets).await?;
            new_entry.save_to_file(file_path)?;
            println!(
                "{}{}{}",
                style(&new_entry.version_id).color256(141),
                style(": ").color256(69),
                style("Key Pre-rotation has been disabled").color256(34)
            );
            new_entry
        } else {
            log_entry.clone()
        };

        // Revoke the DID!
        let revoke_entry = revoke_entry(&log_entry, secrets).await?;
        revoke_entry.save_to_file(file_path)?;
        println!(
            "{}{}{}{}{}",
            style(&revoke_entry.version_id).color256(141),
            style(": ").color256(69),
            style("DID (").color256(9),
            style(&our_did).color256(141),
            style(") has been revoked!").color256(9)
        );
    }
    Ok(())
}

/// Creates a LogEntry that turns off pre-rotation
async fn deactivate_pre_rotation(log_entry: &LogEntry, secrets: &ConfigInfo) -> Result<LogEntry> {
    // Create new Parameters with a valid updateKey from previous LogEntry
    let new_update_key = if let Some(Some(next_key_hashes)) = &log_entry.parameters.next_key_hashes
    {
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
    let diff = log_entry.parameters.diff(&new_params)?;

    Ok(
        LogEntry::create_new_log_entry(log_entry, None, &log_entry.state, &diff, &new_update_key)
            .await?,
    )
}

/// Final LogEntry
async fn revoke_entry(log_entry: &LogEntry, secrets: &ConfigInfo) -> Result<LogEntry> {
    // Create new Parameters with a valid updateKey from previous LogEntry
    let new_update_key = if let Some(Some(update_keys)) = &log_entry.parameters.update_keys {
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
    let diff = log_entry.parameters.diff(&new_params)?;

    Ok(
        LogEntry::create_new_log_entry(log_entry, None, &log_entry.state, &diff, &new_update_key)
            .await?,
    )
}

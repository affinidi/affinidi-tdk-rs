//! Handles the migration (portability) of a DID
//! from an existing URL to a new URL
//!
//! 1. portable Parameter must be true
//! 2. SCID must be the same
//! 3. DID Doc must have alsoKnownAs attribute set to prior DID

use crate::ConfigInfo;
use anyhow::{Result, anyhow, bail};
use console::style;
use dialoguer::{Confirm, Input, theme::ColorfulTheme};
use did_webvh::{DIDWebVHState, url::WebVHURL};
use regex::Regex;
use url::Url;

/// Revokes a webvh DID method
pub fn migrate_did(
    file_path: &str,
    didwebvh: &mut DIDWebVHState,
    secrets: &ConfigInfo,
) -> Result<()> {
    let Some(log_entry) = didwebvh.log_entries.last() else {
        bail!("There must at least be a first LogEntry for this DID to migrate it");
    };

    if log_entry.validated_parameters.portable != Some(true) {
        bail!("Portable parameter must be true to migrate a webvh DID!");
    }

    let did = log_entry
        .log_entry
        .state
        .get("id")
        .ok_or_else(|| anyhow::anyhow!("DID not found in the log entry state"))?
        .as_str();

    let did_url = WebVHURL::parse_did_url(did.unwrap())?;

    println!(
        "\n{}",
        style("** DANGER ** : You are about to migrate this DID to a new URL!")
            .color256(9)
            .blink()
    );

    // Get the new URL
    println!(
        "{} {}",
        style("Current DID URL:").color256(69),
        style(&did_url.get_http_url()?).color256(45)
    );

    let new_url: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("New URL")
        .with_initial_text(did_url.get_http_url()?)
        .interact_text()?;

    let new_url = Url::parse(&new_url).map_err(|_| anyhow!("Invalid URL format"))?;

    let mut new_did_url = WebVHURL::parse_url(&new_url)?;
    new_did_url.scid = did_url.scid.clone();

    println!(
        "\n{} {}\n",
        style("New DID:").color256(69),
        style(&new_did_url.to_string()).color256(141)
    );

    if !Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt("Migrate to this new URL?")
        .default(true)
        .interact()?
    {
        return Ok(());
    }

    // Modify the DID Doc and create new LogEntry
    let did_doc: String = serde_json::to_string(&log_entry.log_entry.state)?;

    let new_did_doc = did_doc.replace(&did_url.to_string(), &new_did_url.to_string());

    let mut new_did_doc = serde_json::to_value(&new_did_doc)?;

    Ok(())
}

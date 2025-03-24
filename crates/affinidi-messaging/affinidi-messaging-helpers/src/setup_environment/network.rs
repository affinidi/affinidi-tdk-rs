//! Network related functions go here
//! Fetching well-known DID or other interactions with a remote mediator

use std::error::Error;

use console::style;
use serde_json::Value;

pub(crate) async fn fetch_well_known_did(address: &str) -> Result<String, Box<dyn Error>> {
    println!("  {}", style("Fetching well-known DID...").yellow());

    let body = reqwest::get([address, "/.well-known/did"].concat()).await?;

    let values: Value = serde_json::from_str::<serde_json::Value>(&body.text().await?)?;

    if let Some(data) = values.get("data") {
        if let Some(did) = data.as_str() {
            return Ok(did.to_string());
        }
    }

    Err("Failed to fetch well-known DID".into())
}

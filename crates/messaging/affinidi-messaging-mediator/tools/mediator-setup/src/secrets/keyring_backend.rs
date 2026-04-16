use affinidi_secrets_resolver::secrets::Secret;
use base64::prelude::*;
use keyring::Entry;

const SERVICE_NAME: &str = "affinidi-mediator";
const SECRETS_USER: &str = "secrets";

/// Store mediator secrets in the OS keyring.
pub fn store_secrets(mediator_did: &str, secrets: &[Secret]) -> anyhow::Result<()> {
    let json = serde_json::to_string(secrets)?;
    let encoded = BASE64_URL_SAFE_NO_PAD.encode(json.as_bytes());

    let entry = Entry::new(SERVICE_NAME, SECRETS_USER)
        .map_err(|e| anyhow::anyhow!("Failed to create keyring entry: {e}"))?;
    entry
        .set_password(&encoded)
        .map_err(|e| anyhow::anyhow!("Failed to store secrets in keyring: {e}"))?;

    // Also store the DID for reference
    let did_entry = Entry::new(SERVICE_NAME, "mediator-did")
        .map_err(|e| anyhow::anyhow!("Failed to create keyring entry for DID: {e}"))?;
    did_entry
        .set_password(mediator_did)
        .map_err(|e| anyhow::anyhow!("Failed to store DID in keyring: {e}"))?;

    println!("  Secrets stored in OS keyring (service: {SERVICE_NAME})");
    Ok(())
}

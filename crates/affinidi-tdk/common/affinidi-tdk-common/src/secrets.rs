/*!
*   Common methods to save and load secrets
*/

use crate::{TDKSharedState, errors::TDKError};
use affinidi_secrets_resolver::{SecretsResolver, secrets::Secret};
use base64::{Engine, prelude::BASE64_STANDARD_NO_PAD};
use keyring::Entry;

/// Need to create a new entry to identify secrets for a specific service and DID
fn entry(service_id: &str, did: &str) -> Result<Entry, TDKError> {
    Entry::new(service_id, did).map_err(|e| {
        TDKError::Secrets(format!(
            "Failed to generate entry for service_id: {}, did: {}. Error: {}",
            service_id, did, e,
        ))
    })
}

/// Deletes secret from keyring
/// service_id: unique identifier for the service
/// did: DID to delete all secrets for
pub fn delete_did_secret(service_id: &str, did: &str) -> Result<(), TDKError> {
    let entry = entry(service_id, did)?;
    let _ = entry.delete_credential();
    Ok(())
}

/// Saves secrets for a DID to the keyring
/// service_id: unique identifier for the service
/// did: DID to save secrets for
pub fn save_secrets_locally(
    service_id: &str,
    did: &str,
    secrets: &[Secret],
) -> Result<(), TDKError> {
    let entry = entry(service_id, did)?;
    entry
        .set_secret(
            BASE64_STANDARD_NO_PAD
                .encode(serde_json::to_string(secrets).unwrap().as_bytes())
                .as_bytes(),
        )
        .map_err(|e| {
            TDKError::Secrets(format!(
                "Failed to save secrets for service_id: {}, did: {}. Error: {}",
                service_id, did, e,
            ))
        })?;
    Ok(())
}

impl TDKSharedState {
    /// Retrieves secrets for a DID from the keyring
    /// auto loads secrets into the secrets resolver
    pub async fn load_secrets(&self, service_id: &str, did: &str) -> Result<(), TDKError> {
        let entry = entry(service_id, did)?;
        let secret = entry.get_secret().map_err(|e| {
            TDKError::Secrets(format!(
                "Failed to load secrets for service_id: {}, did: {}. Error: {}",
                service_id, did, e,
            ))
        })?;
        let secrets: Vec<Secret> = serde_json::from_slice(
            BASE64_STANDARD_NO_PAD
                .decode(secret)
                .map_err(|e| {
                    TDKError::Secrets(format!(
                        "Failed to decode secrets for service_id: {}, did: {}. Error: {}",
                        service_id, did, e,
                    ))
                })?
                .as_slice(),
        )
        .map_err(|e| {
            TDKError::Secrets(format!(
                "Failed to parse secrets for service_id: {}, did: {}. Error: {}",
                service_id, did, e,
            ))
        })?;

        self.secrets_resolver.insert_vec(&secrets).await;
        Ok(())
    }
}

/*!
*   Common methods to save and load secrets
*/

use crate::{TDKSharedState, errors::TDKError};
use affinidi_secrets_resolver::{SecretsResolver, secrets::Secret};
use base64::{Engine, prelude::BASE64_STANDARD_NO_PAD};
use keyring_core::Entry;
use std::sync::OnceLock;

/// Registers the platform-native credential store as keyring-core's default
/// the first time a secret operation runs in this process. Idempotent and
/// no-ops if a default store has already been set by the host application.
fn ensure_default_store() -> Result<(), TDKError> {
    static INIT: OnceLock<Result<(), String>> = OnceLock::new();
    INIT.get_or_init(|| {
        if keyring_core::get_default_store().is_some() {
            return Ok(());
        }
        let store = build_platform_store()?;
        keyring_core::set_default_store(store);
        Ok(())
    })
    .clone()
    .map_err(TDKError::Secrets)
}

#[cfg(target_os = "macos")]
fn build_platform_store() -> Result<std::sync::Arc<keyring_core::api::CredentialStore>, String> {
    apple_native_keyring_store::keychain::Store::new()
        .map(|s| s as std::sync::Arc<keyring_core::api::CredentialStore>)
        .map_err(|e| format!("Failed to initialise macOS Keychain store: {e}"))
}

#[cfg(target_os = "ios")]
fn build_platform_store() -> Result<std::sync::Arc<keyring_core::api::CredentialStore>, String> {
    apple_native_keyring_store::protected::Store::new()
        .map(|s| s as std::sync::Arc<keyring_core::api::CredentialStore>)
        .map_err(|e| format!("Failed to initialise iOS protected-data store: {e}"))
}

#[cfg(target_os = "windows")]
fn build_platform_store() -> Result<std::sync::Arc<keyring_core::api::CredentialStore>, String> {
    windows_native_keyring_store::Store::new()
        .map(|s| s as std::sync::Arc<keyring_core::api::CredentialStore>)
        .map_err(|e| format!("Failed to initialise Windows Credential Manager store: {e}"))
}

#[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "openbsd"))]
fn build_platform_store() -> Result<std::sync::Arc<keyring_core::api::CredentialStore>, String> {
    dbus_secret_service_keyring_store::Store::new()
        .map(|s| s as std::sync::Arc<keyring_core::api::CredentialStore>)
        .map_err(|e| format!("Failed to initialise Secret Service store: {e}"))
}

#[cfg(not(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "windows",
    target_os = "linux",
    target_os = "freebsd",
    target_os = "openbsd",
)))]
fn build_platform_store() -> Result<std::sync::Arc<keyring_core::api::CredentialStore>, String> {
    Err("No keyring-core platform store is bundled for this target OS".to_string())
}

/// Need to create a new entry to identify secrets for a specific service and DID
fn entry(service_id: &str, did: &str) -> Result<Entry, TDKError> {
    ensure_default_store()?;
    Entry::new(service_id, did).map_err(|e| {
        TDKError::Secrets(format!(
            "Failed to generate entry for service_id: {service_id}, did: {did}. Error: {e}",
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
                "Failed to save secrets for service_id: {service_id}, did: {did}. Error: {e}",
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
                "Failed to load secrets for service_id: {service_id}, did: {did}. Error: {e}",
            ))
        })?;
        let secrets: Vec<Secret> = serde_json::from_slice(
            BASE64_STANDARD_NO_PAD
                .decode(secret)
                .map_err(|e| {
                    TDKError::Secrets(format!(
                        "Failed to decode secrets for service_id: {service_id}, did: {did}. Error: {e}",
                    ))
                })?
                .as_slice(),
        )
        .map_err(|e| {
            TDKError::Secrets(format!(
                "Failed to parse secrets for service_id: {service_id}, did: {did}. Error: {e}",
            ))
        })?;

        self.secrets_resolver.insert_vec(&secrets).await;
        Ok(())
    }
}

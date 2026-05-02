/*!
 * Platform-keyring-backed secret storage for TDK profiles.
 *
 * Secrets are stored in the host OS native credential store (macOS Keychain,
 * Windows Credential Manager, or freedesktop Secret Service on Linux/BSD) via
 * `keyring-core` 1.x.
 *
 * # Threat model
 *
 * - **At rest**: secrets are encrypted by the OS and only accessible to processes
 *   running as the user that owns the keychain (and only while that keychain is
 *   unlocked). On macOS / Windows this is the user's logged-in session; on Linux
 *   it is the user's Secret Service-managed login keyring.
 * - **In memory**: decoded `Vec<Secret>` is held in process memory until it is
 *   inserted into the [`affinidi_secrets_resolver`] and then dropped. We do not
 *   currently zeroize the JSON intermediate. Mitigation: keep load windows short
 *   and prefer `load_into` which hands secrets to the resolver immediately.
 * - **Storage format**: raw UTF-8 JSON bytes of `Vec<Secret>`. Earlier versions
 *   (`affinidi-tdk-common <= 0.5.x`) wrapped the JSON in `BASE64_STANDARD_NO_PAD`;
 *   [`KeyringStore::read`] auto-detects and silently migrates legacy entries on
 *   read. The legacy reader will be removed in 0.8.
 *
 * # Default-store registration
 *
 * The platform-native store is registered with `keyring-core` lazily on the first
 * keyring operation. Apps that want to surface initialisation errors at startup
 * (e.g. "Secret Service not available") can call [`init_keyring`] explicitly.
 * If a host application has already registered its own
 * [`keyring_core::set_default_store`], we respect it and do not override.
 */

use crate::errors::TDKError;
use affinidi_secrets_resolver::{SecretsResolver, secrets::Secret};
use base64::{Engine, prelude::BASE64_STANDARD_NO_PAD};
use keyring_core::{Entry, error::Error as KeyringError};
use std::sync::{Arc, Mutex, OnceLock};
use tracing::{debug, warn};

/// A handle to the platform-native credential store, scoped to a single
/// `service_id` namespace.
///
/// The `service_id` is the application-defined namespace under which secrets are
/// grouped in the OS keyring. All operations on this handle share the same
/// namespace; pass the per-DID identifier as the `did` argument to each method.
///
/// # Example
///
/// ```ignore
/// use affinidi_tdk_common::secrets::KeyringStore;
///
/// let store = KeyringStore::new("my-app");
/// store.save("did:example:123", &secrets)?;
/// let loaded = store.read("did:example:123")?;
/// store.delete("did:example:123")?;
/// ```
#[derive(Debug, Clone, Copy)]
pub struct KeyringStore<'a> {
    service_id: &'a str,
}

impl<'a> KeyringStore<'a> {
    /// Create a new `KeyringStore` handle bound to a service namespace.
    pub const fn new(service_id: &'a str) -> Self {
        Self { service_id }
    }

    /// The service namespace this store operates on.
    pub const fn service_id(&self) -> &'a str {
        self.service_id
    }

    /// Build the underlying `keyring-core` entry for a given DID, ensuring the
    /// platform store has been registered first.
    fn entry(&self, did: &str) -> Result<Entry, TDKError> {
        ensure_default_store()?;
        Entry::new(self.service_id, did).map_err(|e| {
            TDKError::Secrets(format!(
                "Failed to build keyring entry (service_id={}, did={did}): {e}",
                self.service_id
            ))
        })
    }

    /// Persist `secrets` to the OS keyring under this store's `service_id` and
    /// the given `did`.
    ///
    /// Any existing entry for the same `(service_id, did)` is overwritten.
    pub fn save(&self, did: &str, secrets: &[Secret]) -> Result<(), TDKError> {
        let entry = self.entry(did)?;
        let bytes = serde_json::to_vec(secrets).map_err(|e| {
            TDKError::Secrets(format!(
                "Failed to serialise secrets (service_id={}, did={did}): {e}",
                self.service_id
            ))
        })?;
        entry.set_secret(&bytes).map_err(|e| {
            TDKError::Secrets(format!(
                "Failed to write keyring entry (service_id={}, did={did}): {e}",
                self.service_id
            ))
        })
    }

    /// Read and deserialise the secrets stored under `(service_id, did)`.
    ///
    /// Auto-migrates legacy entries written by `affinidi-tdk-common <= 0.5.x`
    /// (which wrapped the JSON in `BASE64_STANDARD_NO_PAD`). When a legacy
    /// entry is detected the read succeeds and the entry is opportunistically
    /// rewritten in the new raw-JSON format (rewrite failures are logged but
    /// do not fail the read).
    pub fn read(&self, did: &str) -> Result<Vec<Secret>, TDKError> {
        let entry = self.entry(did)?;
        let bytes = entry.get_secret().map_err(|e| {
            TDKError::Secrets(format!(
                "Failed to read keyring entry (service_id={}, did={did}): {e}",
                self.service_id
            ))
        })?;

        if let Ok(secrets) = serde_json::from_slice::<Vec<Secret>>(&bytes) {
            return Ok(secrets);
        }

        let decoded = BASE64_STANDARD_NO_PAD.decode(&bytes).map_err(|e| {
            TDKError::Secrets(format!(
                "Keyring entry (service_id={}, did={did}) is neither valid JSON nor legacy base64: {e}",
                self.service_id
            ))
        })?;
        let secrets: Vec<Secret> = serde_json::from_slice(&decoded).map_err(|e| {
            TDKError::Secrets(format!(
                "Keyring entry (service_id={}, did={did}) decoded as base64 but JSON parse failed (entry corrupted or not written by this library): {e}",
                self.service_id
            ))
        })?;

        debug!(
            service_id = self.service_id,
            did, "migrating legacy base64 keyring entry to raw JSON"
        );
        if let Err(e) = self.save(did, &secrets) {
            warn!(
                service_id = self.service_id,
                did,
                error = %e,
                "failed to upgrade legacy keyring entry; will retry on next read"
            );
        }

        Ok(secrets)
    }

    /// Delete the keyring entry for `did` under this store's `service_id`.
    ///
    /// Returns `Ok(())` if the entry was deleted *or* if no entry existed.
    /// Other errors (platform store unavailable, permission denied) are
    /// propagated as [`TDKError::Secrets`].
    pub fn delete(&self, did: &str) -> Result<(), TDKError> {
        let entry = self.entry(did)?;
        match entry.delete_credential() {
            Ok(()) => Ok(()),
            Err(KeyringError::NoEntry) => Ok(()),
            Err(e) => Err(TDKError::Secrets(format!(
                "Failed to delete keyring entry (service_id={}, did={did}): {e}",
                self.service_id
            ))),
        }
    }

    /// Read secrets for `did` and insert them into the supplied resolver.
    ///
    /// Convenience over [`read`](Self::read) +
    /// [`SecretsResolver::insert_vec`]. Generic over any
    /// [`SecretsResolver`] implementation.
    pub async fn load_into<R: SecretsResolver>(
        &self,
        did: &str,
        resolver: &R,
    ) -> Result<(), TDKError> {
        let secrets = self.read(did)?;
        resolver.insert_vec(&secrets).await;
        Ok(())
    }
}

/// Eagerly register the platform-native credential store with `keyring-core`.
///
/// Apps that want to surface platform-store initialisation failures (e.g.
/// "Secret Service is not running") at startup rather than on the first secret
/// operation should call this once during boot. Idempotent — safe to call from
/// multiple threads. If the host application has already registered its own
/// store via [`keyring_core::set_default_store`], this function does nothing.
pub fn init_keyring() -> Result<(), TDKError> {
    ensure_default_store()
}

fn ensure_default_store() -> Result<(), TDKError> {
    static INIT: OnceLock<()> = OnceLock::new();
    static INIT_LOCK: Mutex<()> = Mutex::new(());

    // Fast path: already initialised (no lock).
    if INIT.get().is_some() {
        return Ok(());
    }

    // Slow path: serialise initialisation across threads. We do not cache
    // the failure result inside `INIT`, so a transient failure (e.g. D-Bus
    // unavailable at boot) can be retried on the next call.
    let _guard = INIT_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    // Re-check after taking the lock — another thread may have completed
    // initialisation while we were waiting.
    if INIT.get().is_some() {
        return Ok(());
    }
    if keyring_core::get_default_store().is_some() {
        let _ = INIT.set(());
        return Ok(());
    }
    let store = build_platform_store()?;
    keyring_core::set_default_store(store);
    let _ = INIT.set(());
    Ok(())
}

#[cfg(target_os = "macos")]
fn build_platform_store() -> Result<Arc<keyring_core::api::CredentialStore>, TDKError> {
    apple_native_keyring_store::keychain::Store::new()
        .map(|s| s as Arc<keyring_core::api::CredentialStore>)
        .map_err(|e| TDKError::Secrets(format!("macOS Keychain init failed: {e}")))
}

#[cfg(target_os = "ios")]
fn build_platform_store() -> Result<Arc<keyring_core::api::CredentialStore>, TDKError> {
    apple_native_keyring_store::protected::Store::new()
        .map(|s| s as Arc<keyring_core::api::CredentialStore>)
        .map_err(|e| TDKError::Secrets(format!("iOS protected-data store init failed: {e}")))
}

#[cfg(target_os = "windows")]
fn build_platform_store() -> Result<Arc<keyring_core::api::CredentialStore>, TDKError> {
    windows_native_keyring_store::Store::new()
        .map(|s| s as Arc<keyring_core::api::CredentialStore>)
        .map_err(|e| TDKError::Secrets(format!("Windows Credential Manager init failed: {e}")))
}

#[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "openbsd"))]
fn build_platform_store() -> Result<Arc<keyring_core::api::CredentialStore>, TDKError> {
    dbus_secret_service_keyring_store::Store::new()
        .map(|s| s as Arc<keyring_core::api::CredentialStore>)
        .map_err(|e| TDKError::Secrets(format!("Secret Service init failed: {e}")))
}

#[cfg(not(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "windows",
    target_os = "linux",
    target_os = "freebsd",
    target_os = "openbsd",
)))]
fn build_platform_store() -> Result<Arc<keyring_core::api::CredentialStore>, TDKError> {
    Err(TDKError::Secrets(
        "No keyring-core platform store is bundled for this target OS".to_string(),
    ))
}

// Keyring tests live in tests/keyring_store.rs (separate process,
// isolated from the lib's unit-test OnceLock state on the platform-store
// registration).

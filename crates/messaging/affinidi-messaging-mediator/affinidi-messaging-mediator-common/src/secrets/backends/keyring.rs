//! OS keyring backend.
//!
//! Maps every secret `key` to a keyring entry `(service, user)` where
//! `service` is whatever the operator chose via `keyring://<service>` and
//! `user` is the secret key itself (forward-slashes allowed — the `keyring`
//! crate passes them through verbatim on all platforms we target).
//!
//! Value encoding: base64url of the raw bytes, because `keyring_core::Entry`
//! stores UTF-8 strings and our stored bytes are binary envelopes.
//!
//! Feature-gated behind `secrets-keyring`; when the feature is off
//! [`open`] returns `BackendUnavailable` with a pointer at the required
//! cargo feature.
//!
//! # Which store, and one operational caveat
//!
//! Since keyring 4 there is no built-in store — see [`install_default_store`].
//! macOS uses the Keychain; Linux uses the **kernel keyutils** keyring.
//!
//! Keyutils keeps credentials in kernel memory, so on Linux **secrets stored
//! here do not survive a reboot**. That is not new — `keyring 3`'s
//! `linux-native` selected the same backend — but it is worth stating plainly,
//! because it makes `keyring://` a poor choice for a Linux mediator's operating
//! secrets unless something re-seeds them on start. The persistent alternatives
//! (Secret Service via D-Bus) need a session bus and an unlocked collection that
//! a headless host does not have, which is exactly why they are not the default
//! here. Operators wanting durable storage on Linux should use one of the other
//! backends (`vault://`, `k8s://`, cloud secret managers).

use crate::secrets::error::{Result, SecretStoreError};
use crate::secrets::store::DynSecretStore;
use crate::secrets::url::BackendUrl;

#[cfg(feature = "secrets-keyring")]
use crate::secrets::store::SecretStore;
#[cfg(feature = "secrets-keyring")]
use async_trait::async_trait;
#[cfg(feature = "secrets-keyring")]
use base64::Engine;
#[cfg(feature = "secrets-keyring")]
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;

const BACKEND_LABEL: &str = "keyring";

/// Register the platform credential store with `keyring-core`, once per process.
///
/// keyring 4 ships no built-in store: `keyring_core::Entry` talks to whatever
/// was installed via `set_default_store`, and errors if nothing was. That is the
/// whole reason this was a migration rather than a version bump — the choice
/// below is ours to make, and is deliberately the one `keyring 3` made for us.
///
/// macOS gets the Keychain, matching `keyring 3`'s `apple-native`. Linux gets
/// **kernel keyutils**, matching `linux-native` — *not* Secret Service, which is
/// what the `keyring` facade's `v1` shim picks. Secret Service needs a D-Bus
/// session with an unlocked collection; a headless mediator host has neither, so
/// that substitution would fail at first secret access rather than at boot.
///
/// `set_default_store` is process-wide, so this is latched: `open()` can be
/// called more than once (config reload, tests) and the outcome — including a
/// failure — has to be the same every time.
#[cfg(feature = "secrets-keyring")]
fn install_default_store() -> Result<()> {
    static INSTALLED: std::sync::OnceLock<std::result::Result<(), String>> =
        std::sync::OnceLock::new();

    match INSTALLED.get_or_init(install_platform_store) {
        Ok(()) => Ok(()),
        Err(reason) => Err(SecretStoreError::BackendUnavailable {
            backend: BACKEND_LABEL,
            reason: reason.clone(),
        }),
    }
}

#[cfg(all(feature = "secrets-keyring", target_os = "macos"))]
fn install_platform_store() -> std::result::Result<(), String> {
    let store = apple_native_keyring_store::keychain::Store::new()
        .map_err(|e| format!("could not open the macOS Keychain store: {e}"))?;
    keyring_core::set_default_store(store);
    Ok(())
}

#[cfg(all(feature = "secrets-keyring", target_os = "linux"))]
fn install_platform_store() -> std::result::Result<(), String> {
    let store = linux_keyutils_keyring_store::Store::new()
        .map_err(|e| format!("could not open the Linux keyutils store: {e}"))?;
    keyring_core::set_default_store(store);
    Ok(())
}

/// Every other target. Failing here is the point: with no store installed,
/// `keyring_core::Entry` would error on first use with nothing useful to say,
/// and a secrets backend is the wrong place to discover that.
#[cfg(all(
    feature = "secrets-keyring",
    not(any(target_os = "macos", target_os = "linux"))
))]
fn install_platform_store() -> std::result::Result<(), String> {
    Err(
        "no OS keyring store is compiled in for this platform; the mediator \
         supports the macOS Keychain and Linux kernel keyutils"
            .to_string(),
    )
}

#[cfg(feature = "secrets-keyring")]
pub(crate) fn open(url: BackendUrl) -> Result<DynSecretStore> {
    let BackendUrl::Keyring { service } = url else {
        return Err(SecretStoreError::Other(
            "internal error: keyring backend received non-keyring URL".into(),
        ));
    };
    install_default_store()?;
    Ok(std::sync::Arc::new(KeyringStore { service }))
}

#[cfg(not(feature = "secrets-keyring"))]
pub(crate) fn open(_url: BackendUrl) -> Result<DynSecretStore> {
    Err(SecretStoreError::BackendUnavailable {
        backend: BACKEND_LABEL,
        reason: "compiled without the 'secrets-keyring' feature; \
                 rebuild with `cargo build --features secrets-keyring` to enable"
            .into(),
    })
}

#[cfg(feature = "secrets-keyring")]
pub struct KeyringStore {
    service: String,
}

#[cfg(feature = "secrets-keyring")]
impl KeyringStore {
    fn entry(&self, key: &str) -> Result<keyring_core::Entry> {
        keyring_core::Entry::new(&self.service, key).map_err(|e| SecretStoreError::Unreachable {
            backend: BACKEND_LABEL,
            reason: format!("could not open keyring entry '{}/{key}': {e}", self.service),
        })
    }
}

#[cfg(feature = "secrets-keyring")]
#[async_trait]
impl SecretStore for KeyringStore {
    fn backend(&self) -> &'static str {
        BACKEND_LABEL
    }

    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let entry = self.entry(key)?;
        let raw = match entry.get_password() {
            Ok(s) => s,
            Err(keyring_core::Error::NoEntry) => return Ok(None),
            Err(e) => {
                return Err(SecretStoreError::Unreachable {
                    backend: BACKEND_LABEL,
                    reason: format!("keyring read failed: {e}"),
                });
            }
        };
        let bytes = B64URL
            .decode(raw.as_bytes())
            .map_err(|e| SecretStoreError::InvalidShape {
                key: key.to_string(),
                reason: format!("stored value is not valid base64: {e}"),
            })?;
        Ok(Some(bytes))
    }

    async fn put(&self, key: &str, value: &[u8]) -> Result<()> {
        let entry = self.entry(key)?;
        let encoded = B64URL.encode(value);
        entry
            .set_password(&encoded)
            .map_err(|e| SecretStoreError::Unreachable {
                backend: BACKEND_LABEL,
                reason: format!("keyring write failed: {e}"),
            })?;
        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<()> {
        let entry = self.entry(key)?;
        match entry.delete_credential() {
            Ok(()) => Ok(()),
            Err(keyring_core::Error::NoEntry) => Ok(()),
            Err(e) => Err(SecretStoreError::Unreachable {
                backend: BACKEND_LABEL,
                reason: format!("keyring delete failed: {e}"),
            }),
        }
    }

    /// Override the default put+get+delete roundtrip with a read-only
    /// probe. On macOS every distinct keyring-entry ACL can trigger a
    /// separate Keychain unlock prompt; the default probe creates an
    /// ephemeral sentinel entry that is visible only to this probe,
    /// adding a dialog the operator then has to manually "Always
    /// Allow" for an entry that never gets used again.
    ///
    /// Instead, we issue a `get()` against a fixed sentinel key. The
    /// keyring crate returns `NoEntry` immediately without prompting
    /// on all three platforms we target (macOS Keychain, Windows
    /// Credential Manager, Secret Service / libsecret) — that's a
    /// sufficient liveness check because any real "backend
    /// unreachable" failure (library unloadable, daemon down,
    /// keychain locked and not unlockable) would surface as an error
    /// from `get_password()` rather than `NoEntry`. A pre-existing
    /// entry under the sentinel name returning a real value is also
    /// fine — we only care that the call completed.
    ///
    /// The subsequent real writes (`put()` via `store_admin_credential`,
    /// etc.) catch ACL / permission misconfigurations at first use;
    /// the probe's job is narrower — "is the backend reachable at
    /// all?" — and a read-only probe answers that without leaving
    /// ephemeral state behind.
    async fn probe(&self) -> Result<()> {
        // Read-only probe with a fixed sentinel name — a keychain that
        // refuses to answer is the failure we want to catch; leaving no
        // residue keeps us out of the keychain's write ACL dialog on
        // macOS. Name lives in the shared `mediator_probe_*` namespace.
        let entry = self.entry("mediator_probe_keyring_sentinel")?;
        match entry.get_password() {
            Ok(_) | Err(keyring_core::Error::NoEntry) => Ok(()),
            Err(e) => Err(SecretStoreError::ProbeFailed {
                backend: BACKEND_LABEL,
                reason: format!("keyring read-probe failed: {e}"),
            }),
        }
    }
}

//! OS keyring backend.
//!
//! Maps every secret `key` to a keyring entry `(service, user)` where
//! `service` is whatever the operator chose via `keyring://<service>` and
//! `user` is the secret key itself (forward-slashes allowed — the `keyring`
//! crate passes them through verbatim on all platforms we target).
//!
//! Value encoding: base64url of the raw bytes, because `keyring::Entry`
//! stores UTF-8 strings and our stored bytes are binary envelopes.
//!
//! Feature-gated behind `secrets-keyring`; when the feature is off
//! [`open`] returns `BackendUnavailable` with a pointer at the required
//! cargo feature.

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

#[cfg(feature = "secrets-keyring")]
pub(crate) fn open(url: BackendUrl) -> Result<DynSecretStore> {
    let BackendUrl::Keyring { service } = url else {
        return Err(SecretStoreError::Other(
            "internal error: keyring backend received non-keyring URL".into(),
        ));
    };
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
    fn entry(&self, key: &str) -> Result<keyring::Entry> {
        keyring::Entry::new(&self.service, key).map_err(|e| SecretStoreError::Unreachable {
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
            Err(keyring::Error::NoEntry) => return Ok(None),
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
            Err(keyring::Error::NoEntry) => Ok(()),
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
            Ok(_) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(SecretStoreError::ProbeFailed {
                backend: BACKEND_LABEL,
                reason: format!("keyring read-probe failed: {e}"),
            }),
        }
    }
}

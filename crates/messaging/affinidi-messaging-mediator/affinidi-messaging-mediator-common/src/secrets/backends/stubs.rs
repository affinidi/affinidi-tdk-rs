//! Not-yet-implemented backends.
//!
//! HashiCorp Vault is part of the URL parser and the feature-flag
//! matrix so the mediator and wizard don't have to special-case "this
//! scheme isn't available yet" — the failure is surfaced uniformly
//! via [`SecretStoreError::BackendUnavailable`] when the backend is
//! opened.
//!
//! When the real Vault backend lands, move it into its own module and
//! drop the last match arm here. GCP (see [`super::gcp`]) and Azure
//! (see [`super::azure`]) have already landed.

use crate::secrets::error::{Result, SecretStoreError};
use crate::secrets::store::DynSecretStore;
use crate::secrets::url::BackendUrl;

pub(crate) mod vault {
    use super::*;
    pub(crate) fn open(_url: BackendUrl) -> Result<DynSecretStore> {
        Err(SecretStoreError::BackendUnavailable {
            backend: "vault",
            reason: "HashiCorp Vault backend is not yet implemented. \
                     Track this work in the 'secrets-vault' feature flag."
                .into(),
        })
    }
}

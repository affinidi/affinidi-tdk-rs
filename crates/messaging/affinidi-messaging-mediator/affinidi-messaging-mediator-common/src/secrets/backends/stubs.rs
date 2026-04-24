//! Not-yet-implemented backends.
//!
//! Azure Key Vault and HashiCorp Vault are part of the URL parser and
//! the feature-flag matrix so the mediator and wizard don't have to
//! special-case "this scheme isn't available yet" — the failure is
//! surfaced uniformly via [`SecretStoreError::BackendUnavailable`]
//! when the backend is opened.
//!
//! When the real backends land, move them into their own modules and drop
//! the corresponding match arm here. GCP has already landed in
//! [`super::gcp`].

use crate::secrets::error::{Result, SecretStoreError};
use crate::secrets::store::DynSecretStore;
use crate::secrets::url::BackendUrl;

pub(crate) mod azure {
    use super::*;
    pub(crate) fn open(_url: BackendUrl) -> Result<DynSecretStore> {
        Err(SecretStoreError::BackendUnavailable {
            backend: "azure_keyvault",
            reason: "Azure Key Vault backend is not yet implemented. \
                     Track this work in the 'secrets-azure' feature flag."
                .into(),
        })
    }
}

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

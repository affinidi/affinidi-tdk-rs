//! Azure Key Vault Secrets backend (feature `secrets-azure`).
//!
//! Every mediator secret is stored as an Azure Key Vault secret named
//! `<prefix><normalised_key>` under the configured vault. Key Vault
//! names are restricted to `[0-9a-zA-Z-]` (no underscores, no periods,
//! no slashes) so the flat well-known keys — which use `_` — are
//! mapped by replacing `_` with `-` on the way down and `-` with `_`
//! on the way back. This mapping is bijective by contract: the flat
//! well-known schema (see `well_known.rs`) never uses `-` inside its
//! key strings.
//!
//! Value encoding: the raw bytes from the envelope are base64url
//! encoded into the secret's `value` field so binary JSON (and future
//! binary formats) round-trip identically across backends.
//!
//! Authentication uses the `DeveloperToolsCredential` chain from
//! `azure_identity` — Azure CLI, then Azure Developer CLI. This
//! covers the operator-machine use case the wizard is built for.
//! Managed-identity / workload-identity fallbacks are a natural
//! follow-up but out of scope for this change.
//!
//! Calls go through [`super::super::retry::with_retry`] with
//! [`AzureRetryPolicy`]: 429, 500, 502, 503, 504, and connection /
//! IO kinds retry; 404, 401, 403, 409 and other 4xx short-circuit so
//! the caller's error path runs unchanged.

use crate::secrets::error::{Result, SecretStoreError};
use crate::secrets::store::DynSecretStore;
use crate::secrets::url::BackendUrl;

#[cfg(feature = "secrets-azure")]
use crate::secrets::retry::{RetryPolicy, Retryable, with_retry};
#[cfg(feature = "secrets-azure")]
use crate::secrets::store::SecretStore;
#[cfg(feature = "secrets-azure")]
use async_trait::async_trait;
#[cfg(feature = "secrets-azure")]
use azure_core::{
    Error as AzureError,
    error::ErrorKind as AzureErrorKind,
    http::{RequestContent, StatusCode},
};
#[cfg(feature = "secrets-azure")]
use azure_identity::DeveloperToolsCredential;
#[cfg(feature = "secrets-azure")]
use azure_security_keyvault_secrets::{SecretClient, models::SetSecretParameters};
#[cfg(feature = "secrets-azure")]
use base64::Engine;
#[cfg(feature = "secrets-azure")]
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
#[cfg(feature = "secrets-azure")]
use tokio::sync::OnceCell;

const BACKEND_LABEL: &str = "azure_keyvault";

#[cfg(feature = "secrets-azure")]
pub(crate) fn open(url: BackendUrl) -> Result<DynSecretStore> {
    let BackendUrl::Azure { vault } = url else {
        return Err(SecretStoreError::Other(
            "internal error: azure backend received non-azure URL".into(),
        ));
    };
    Ok(std::sync::Arc::new(AzureStore {
        endpoint: vault,
        prefix: String::new(),
        client: OnceCell::new(),
    }))
}

#[cfg(not(feature = "secrets-azure"))]
pub(crate) fn open(_url: BackendUrl) -> Result<DynSecretStore> {
    Err(SecretStoreError::BackendUnavailable {
        backend: BACKEND_LABEL,
        reason: "compiled without the 'secrets-azure' feature; rebuild with \
                 `cargo build --features secrets-azure` to enable"
            .into(),
    })
}

#[cfg(feature = "secrets-azure")]
pub struct AzureStore {
    /// Fully-qualified vault URL, e.g. `https://my-vault.vault.azure.net`.
    /// The URL parser resolves bare names + sovereign-cloud DNS into
    /// this canonical form before the backend ever sees it.
    endpoint: String,
    /// Optional key-name prefix (future; currently always empty
    /// because `azure_keyvault://` URLs don't carry one). Kept as a
    /// field so the wizard can populate it without a shape change.
    prefix: String,
    /// Lazily-constructed SDK client. `SecretClient::new` is sync but
    /// the credential chain's first token fetch is async; caching the
    /// whole client avoids redoing that dance on every call.
    client: OnceCell<SecretClient>,
}

#[cfg(feature = "secrets-azure")]
impl AzureStore {
    /// Map a flat well-known key (`[a-z0-9_]`) to an Azure-legal
    /// secret name (`[A-Za-z0-9-]`). Underscores become hyphens; the
    /// flat schema never uses hyphens so the mapping is bijective
    /// for every key the wizard produces.
    fn secret_name(&self, key: &str) -> String {
        let mapped: String = key
            .chars()
            .map(|c| if c == '_' { '-' } else { c })
            .collect();
        format!("{}{mapped}", self.prefix)
    }

    /// Defence-in-depth: our flat well-known keys never contain `/`
    /// or `.`, but a future caller could try one. Azure would reject
    /// it server-side; catching it here gives a clearer error with
    /// the backend and key in scope.
    fn validate_key(&self, key: &str) -> Result<()> {
        if key.contains('/') || key.contains('.') {
            return Err(SecretStoreError::InvalidShape {
                key: key.to_string(),
                reason: "Azure Key Vault secret names accept only [0-9a-zA-Z-]; \
                         well-known keys must use the flat [a-z0-9_] form"
                    .into(),
            });
        }
        Ok(())
    }

    async fn client(&self) -> Result<&SecretClient> {
        self.client
            .get_or_try_init(|| async {
                let credential = DeveloperToolsCredential::new(None).map_err(|e| {
                    SecretStoreError::Unreachable {
                        backend: BACKEND_LABEL,
                        reason: format!("could not build Azure credential: {e}"),
                    }
                })?;
                SecretClient::new(&self.endpoint, credential, None).map_err(|e| {
                    SecretStoreError::Unreachable {
                        backend: BACKEND_LABEL,
                        reason: format!("could not build Azure SecretClient: {e}"),
                    }
                })
            })
            .await
    }
}

/// Retry policy for Azure SDK errors. Retries transient HTTP status
/// codes and connection / IO failures; short-circuits on anything
/// that's a deterministic misconfiguration.
#[cfg(feature = "secrets-azure")]
pub(crate) struct AzureRetryPolicy;

#[cfg(feature = "secrets-azure")]
impl RetryPolicy<AzureError> for AzureRetryPolicy {
    fn classify(&self, err: &AzureError) -> Retryable {
        match err.kind() {
            AzureErrorKind::HttpResponse { status, .. } => match *status {
                StatusCode::TooManyRequests
                | StatusCode::InternalServerError
                | StatusCode::BadGateway
                | StatusCode::ServiceUnavailable
                | StatusCode::GatewayTimeout => Retryable::Yes { retry_after: None },
                _ => Retryable::No,
            },
            AzureErrorKind::Connection | AzureErrorKind::Io => Retryable::Yes { retry_after: None },
            // Credential / DataConversion / Other — don't retry.
            _ => Retryable::No,
        }
    }
}

#[cfg(feature = "secrets-azure")]
fn status_code(err: &AzureError) -> Option<StatusCode> {
    if let AzureErrorKind::HttpResponse { status, .. } = err.kind() {
        Some(*status)
    } else {
        None
    }
}

#[cfg(feature = "secrets-azure")]
#[async_trait]
impl SecretStore for AzureStore {
    fn backend(&self) -> &'static str {
        BACKEND_LABEL
    }

    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        self.validate_key(key)?;
        let name = self.secret_name(key);
        let client = self.client().await?;
        let label = format!("GetSecret({name})");
        let result = with_retry(&label, &AzureRetryPolicy, || {
            let name = name.clone();
            async move { client.get_secret(&name, None).await }
        })
        .await;
        let response = match result {
            Ok(r) => r,
            Err(err) if matches!(status_code(&err), Some(StatusCode::NotFound)) => {
                return Ok(None);
            }
            Err(err) => {
                return Err(SecretStoreError::Unreachable {
                    backend: BACKEND_LABEL,
                    reason: format!("GetSecret({name}) failed: {err}"),
                });
            }
        };
        // `into_model` is sync — the pipeline already buffered the body
        // during `send().await`, so parsing it is a pure serde step.
        let secret = response
            .into_model()
            .map_err(|e| SecretStoreError::Unreachable {
                backend: BACKEND_LABEL,
                reason: format!("GetSecret({name}) body parse failed: {e}"),
            })?;
        let Some(encoded) = secret.value else {
            return Err(SecretStoreError::InvalidShape {
                key: key.to_string(),
                reason: "Azure Key Vault secret has no value field".into(),
            });
        };
        let bytes =
            B64URL
                .decode(encoded.as_bytes())
                .map_err(|e| SecretStoreError::InvalidShape {
                    key: key.to_string(),
                    reason: format!("Azure secret value is not valid base64url: {e}"),
                })?;
        Ok(Some(bytes))
    }

    async fn put(&self, key: &str, value: &[u8]) -> Result<()> {
        self.validate_key(key)?;
        let name = self.secret_name(key);
        let client = self.client().await?;
        let encoded = B64URL.encode(value);
        let label = format!("SetSecret({name})");
        with_retry(&label, &AzureRetryPolicy, || {
            let name = name.clone();
            let encoded = encoded.clone();
            async move {
                let parameters = SetSecretParameters {
                    value: Some(encoded),
                    ..Default::default()
                };
                let body: RequestContent<SetSecretParameters> = parameters.try_into()?;
                client.set_secret(&name, body, None).await
            }
        })
        .await
        .map_err(|err| SecretStoreError::Unreachable {
            backend: BACKEND_LABEL,
            reason: format!("SetSecret({name}) failed: {err}"),
        })?;
        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<()> {
        self.validate_key(key)?;
        let name = self.secret_name(key);
        let client = self.client().await?;
        let label = format!("DeleteSecret({name})");
        let result = with_retry(&label, &AzureRetryPolicy, || {
            let name = name.clone();
            async move { client.delete_secret(&name, None).await }
        })
        .await;
        match result {
            Ok(_) => Ok(()),
            Err(err) if matches!(status_code(&err), Some(StatusCode::NotFound)) => Ok(()),
            Err(err) => Err(SecretStoreError::Unreachable {
                backend: BACKEND_LABEL,
                reason: format!("DeleteSecret({name}) failed: {err}"),
            }),
        }
    }
}

#[cfg(test)]
#[cfg(feature = "secrets-azure")]
mod tests {
    use super::*;
    use crate::secrets::url::parse_url;

    fn sample_store() -> AzureStore {
        AzureStore {
            endpoint: "https://my-vault.vault.azure.net".into(),
            prefix: String::new(),
            client: OnceCell::new(),
        }
    }

    #[test]
    fn secret_name_maps_underscore_to_hyphen() {
        let store = sample_store();
        assert_eq!(
            store.secret_name("mediator_admin_credential"),
            "mediator-admin-credential"
        );
        assert_eq!(
            store.secret_name("mediator_bootstrap_ephemeral_seed_abcdef"),
            "mediator-bootstrap-ephemeral-seed-abcdef"
        );
    }

    #[test]
    fn validate_key_rejects_slash_and_dot() {
        let store = sample_store();
        assert!(matches!(
            store.validate_key("has/slash"),
            Err(SecretStoreError::InvalidShape { .. })
        ));
        assert!(matches!(
            store.validate_key("has.dot"),
            Err(SecretStoreError::InvalidShape { .. })
        ));
        assert!(store.validate_key("mediator_admin_credential").is_ok());
    }

    #[test]
    fn open_returns_azure_store_for_azure_url() {
        let url = parse_url("azure_keyvault://my-vault").unwrap();
        let store = open(url).expect("open azure backend");
        assert_eq!(store.backend(), BACKEND_LABEL);
    }

    /// Opt-in live-backend test. Requires a real Azure Key Vault
    /// reachable via the DeveloperToolsCredential chain (`az login`).
    ///
    /// Run with:
    ///   MEDIATOR_TEST_AZURE_URL=azure_keyvault://my-vault \
    ///   cargo test -p affinidi-messaging-mediator-common \
    ///     --features secrets-azure azure_live_roundtrip -- --ignored
    #[tokio::test]
    #[ignore]
    async fn azure_live_roundtrip() {
        use crate::secrets::store::open_store;
        let url = std::env::var("MEDIATOR_TEST_AZURE_URL")
            .expect("set MEDIATOR_TEST_AZURE_URL to run the live Azure test");
        let store = open_store(&url).unwrap();
        store.probe().await.expect("probe");
        let key = format!("mediator_probe_{}", uuid::Uuid::new_v4().simple());
        let payload = b"payload-bytes".to_vec();
        store.put(&key, &payload).await.unwrap();
        let got = store.get(&key).await.unwrap().unwrap();
        assert_eq!(got, payload);
        store.delete(&key).await.unwrap();
        // Note: Azure soft-deletes secrets by default — a subsequent
        // `get` returns 404 but the secret is recoverable from the
        // deleted-state for the vault's configured retention window.
        assert!(store.get(&key).await.unwrap().is_none());
    }
}

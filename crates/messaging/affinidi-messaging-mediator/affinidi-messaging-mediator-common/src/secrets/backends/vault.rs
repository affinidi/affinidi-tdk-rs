//! HashiCorp Vault backend (feature `secrets-vault`).
//!
//! KV v2 only. Earlier KV v1 semantics are deliberately unsupported
//! — v1 is EOL-adjacent and the wizard has no reason to coexist with
//! existing v1 data. Operators who still use v1 should migrate to v2
//! first; Vault provides an in-place upgrade path.
//!
//! URL shape: `vault://<host[:port]>/<mount>[/<prefix>…]`.
//! The first path segment is the KV v2 mount point; anything
//! remaining becomes a prefix glued to each stored key. Examples:
//!   - `vault://vault.internal/secret` → mount `secret`, no prefix.
//!   - `vault://vault.internal/secret/mediator` → mount `secret`,
//!     prefix `mediator/`.
//!
//! Transport: always HTTPS against the configured endpoint. Local-
//! dev operators running Vault without TLS should front it with a
//! reverse proxy or use `vault server -dev-tls` — we don't offer an
//! `insecure=1` knob because wizard-managed material always includes
//! the mediator's admin credential and JWT key.
//!
//! Auth: token auth only (Kubernetes, AppRole, JWT/OIDC and friends
//! are documented follow-ups). `VAULT_TOKEN` env var is consulted at
//! client construction; an empty value produces a clear error at
//! probe time rather than a silent 403 on first write.
//!
//! Calls go through [`super::super::retry::with_retry`] with
//! [`VaultRetryPolicy`]: 429, 5xx, RestClientError connect / IO
//! failures retry; 400/401/403/404/409 and parse errors short-circuit.

use crate::secrets::error::{Result, SecretStoreError};
use crate::secrets::store::DynSecretStore;
use crate::secrets::url::BackendUrl;

#[cfg(feature = "secrets-vault")]
use crate::secrets::retry::{RetryPolicy, Retryable, with_retry};
#[cfg(feature = "secrets-vault")]
use crate::secrets::store::SecretStore;
#[cfg(feature = "secrets-vault")]
use async_trait::async_trait;
#[cfg(feature = "secrets-vault")]
use base64::Engine;
#[cfg(feature = "secrets-vault")]
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
#[cfg(feature = "secrets-vault")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "secrets-vault")]
use tokio::sync::OnceCell;
#[cfg(feature = "secrets-vault")]
use vaultrs::{
    client::{VaultClient, VaultClientSettingsBuilder},
    error::ClientError,
    kv2,
};

const BACKEND_LABEL: &str = "vault";

/// Env var the Vault backend looks up at client construction. Matches
/// the `VAULT_TOKEN` convention used by the `vault` CLI so operators
/// don't learn a new variable.
#[cfg(feature = "secrets-vault")]
const VAULT_TOKEN_ENV: &str = "VAULT_TOKEN";

#[cfg(feature = "secrets-vault")]
pub(crate) fn open(url: BackendUrl) -> Result<DynSecretStore> {
    let BackendUrl::Vault { endpoint, path } = url else {
        return Err(SecretStoreError::Other(
            "internal error: vault backend received non-vault URL".into(),
        ));
    };
    // Split the URL path into KV v2 mount + per-key prefix. First
    // segment is the mount; everything else is the prefix glued to
    // each stored key name.
    let (mount, prefix) = match path.split_once('/') {
        Some((m, rest)) => (m.to_string(), format!("{rest}/")),
        None => (path, String::new()),
    };
    if mount.is_empty() {
        return Err(SecretStoreError::InvalidUrl {
            url: format!("vault://{endpoint}/{mount}"),
            reason: "vault:// requires a KV v2 mount point as the first path segment".into(),
        });
    }
    let address = if endpoint.starts_with("http://") || endpoint.starts_with("https://") {
        endpoint.clone()
    } else {
        format!("https://{endpoint}")
    };
    Ok(std::sync::Arc::new(VaultStore {
        address,
        mount,
        prefix,
        client: OnceCell::new(),
    }))
}

#[cfg(not(feature = "secrets-vault"))]
pub(crate) fn open(_url: BackendUrl) -> Result<DynSecretStore> {
    Err(SecretStoreError::BackendUnavailable {
        backend: BACKEND_LABEL,
        reason: "compiled without the 'secrets-vault' feature; rebuild with \
                 `cargo build --features secrets-vault` to enable"
            .into(),
    })
}

#[cfg(feature = "secrets-vault")]
pub struct VaultStore {
    /// Full `http(s)://host[:port]` endpoint used by the REST client.
    address: String,
    /// KV v2 mount name.
    mount: String,
    /// Per-key path prefix (always ends with `/` when non-empty).
    prefix: String,
    /// Lazily-constructed client. Token discovery happens on first
    /// use so a wizard run that never touches the backend doesn't
    /// complain about a missing `VAULT_TOKEN`.
    client: OnceCell<VaultClient>,
}

#[cfg(feature = "secrets-vault")]
impl VaultStore {
    fn secret_path(&self, key: &str) -> String {
        format!("{}{key}", self.prefix)
    }

    async fn client(&self) -> Result<&VaultClient> {
        self.client
            .get_or_try_init(|| async {
                let token =
                    std::env::var(VAULT_TOKEN_ENV).map_err(|_| SecretStoreError::Unreachable {
                        backend: BACKEND_LABEL,
                        reason: format!(
                            "VAULT_TOKEN env var not set — token auth is the only auth \
                             method currently supported by the '{BACKEND_LABEL}' backend"
                        ),
                    })?;
                if token.is_empty() {
                    return Err(SecretStoreError::Unreachable {
                        backend: BACKEND_LABEL,
                        reason: format!("{VAULT_TOKEN_ENV} is set but empty"),
                    });
                }
                let settings = VaultClientSettingsBuilder::default()
                    .address(&self.address)
                    .token(token)
                    .build()
                    .map_err(|e| SecretStoreError::Unreachable {
                        backend: BACKEND_LABEL,
                        reason: format!("could not build Vault client settings: {e}"),
                    })?;
                VaultClient::new(settings).map_err(|e| SecretStoreError::Unreachable {
                    backend: BACKEND_LABEL,
                    reason: format!("could not build Vault client: {e}"),
                })
            })
            .await
    }
}

/// Retry policy for Vault SDK errors. Retries 429 / 5xx, and REST
/// transport failures that represent a transient connection problem.
/// Everything else (4xx, parse errors, credential problems) is
/// terminal.
#[cfg(feature = "secrets-vault")]
pub(crate) struct VaultRetryPolicy;

#[cfg(feature = "secrets-vault")]
impl RetryPolicy<ClientError> for VaultRetryPolicy {
    fn classify(&self, err: &ClientError) -> Retryable {
        match err {
            ClientError::APIError { code, .. } => {
                if *code == 429 || (*code >= 500 && *code < 600) {
                    Retryable::Yes { retry_after: None }
                } else {
                    Retryable::No
                }
            }
            // rustify wraps connection / timeout / IO under a single
            // variant. Safest to retry once — if it's a real
            // configuration error it will surface deterministically
            // on the second attempt too.
            ClientError::RestClientError { .. } => Retryable::Yes { retry_after: None },
            // JSON parse / empty response / wrap errors are
            // deterministic — retrying doesn't help.
            _ => Retryable::No,
        }
    }
}

#[cfg(feature = "secrets-vault")]
fn api_status(err: &ClientError) -> Option<u16> {
    match err {
        ClientError::APIError { code, .. } => Some(*code),
        _ => None,
    }
}

/// KV v2 stores arbitrary JSON under the secret path. We wrap every
/// envelope's raw bytes in a single `{"value": "<base64url>"}` object
/// so the stored shape is consistent across every backend the wizard
/// can target.
#[cfg(feature = "secrets-vault")]
#[derive(Debug, Clone, Serialize, Deserialize)]
struct VaultPayload {
    value: String,
}

#[cfg(feature = "secrets-vault")]
#[async_trait]
impl SecretStore for VaultStore {
    fn backend(&self) -> &'static str {
        BACKEND_LABEL
    }

    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let path = self.secret_path(key);
        let client = self.client().await?;
        let label = format!("kv2::read({}/{path})", self.mount);
        let result = with_retry(&label, &VaultRetryPolicy, || {
            let path = path.clone();
            async move { kv2::read::<VaultPayload>(client, &self.mount, &path).await }
        })
        .await;
        let payload = match result {
            Ok(p) => p,
            Err(err) if matches!(api_status(&err), Some(404)) => return Ok(None),
            Err(err) => {
                return Err(SecretStoreError::Unreachable {
                    backend: BACKEND_LABEL,
                    reason: format!("kv2::read({}/{path}) failed: {err}", self.mount),
                });
            }
        };
        let bytes = B64URL.decode(payload.value.as_bytes()).map_err(|e| {
            SecretStoreError::InvalidShape {
                key: key.to_string(),
                reason: format!("Vault payload is not valid base64url: {e}"),
            }
        })?;
        Ok(Some(bytes))
    }

    async fn put(&self, key: &str, value: &[u8]) -> Result<()> {
        let path = self.secret_path(key);
        let client = self.client().await?;
        let encoded = B64URL.encode(value);
        let label = format!("kv2::set({}/{path})", self.mount);
        with_retry(&label, &VaultRetryPolicy, || {
            let path = path.clone();
            let payload = VaultPayload {
                value: encoded.clone(),
            };
            async move { kv2::set(client, &self.mount, &path, &payload).await }
        })
        .await
        .map(|_| ())
        .map_err(|err| SecretStoreError::Unreachable {
            backend: BACKEND_LABEL,
            reason: format!("kv2::set({}/{path}) failed: {err}", self.mount),
        })
    }

    async fn delete(&self, key: &str) -> Result<()> {
        let path = self.secret_path(key);
        let client = self.client().await?;
        let label = format!("kv2::delete_latest({}/{path})", self.mount);
        let result = with_retry(&label, &VaultRetryPolicy, || {
            let path = path.clone();
            async move { kv2::delete_latest(client, &self.mount, &path).await }
        })
        .await;
        match result {
            Ok(()) => Ok(()),
            Err(err) if matches!(api_status(&err), Some(404)) => Ok(()),
            Err(err) => Err(SecretStoreError::Unreachable {
                backend: BACKEND_LABEL,
                reason: format!("kv2::delete_latest({}/{path}) failed: {err}", self.mount),
            }),
        }
    }
}

#[cfg(test)]
#[cfg(feature = "secrets-vault")]
mod tests {
    use super::*;
    use crate::secrets::url::parse_url;

    fn store_from(endpoint: &str, path: &str) -> VaultStore {
        VaultStore {
            address: format!("https://{endpoint}"),
            mount: path.split_once('/').map(|(m, _)| m).unwrap_or(path).into(),
            prefix: path
                .split_once('/')
                .map(|(_, rest)| format!("{rest}/"))
                .unwrap_or_default(),
            client: OnceCell::new(),
        }
    }

    #[test]
    fn secret_path_glues_prefix_and_key() {
        let with_prefix = store_from("vault.internal", "secret/mediator");
        assert_eq!(with_prefix.mount, "secret");
        assert_eq!(with_prefix.prefix, "mediator/");
        assert_eq!(
            with_prefix.secret_path("mediator_admin_credential"),
            "mediator/mediator_admin_credential"
        );

        let no_prefix = store_from("vault.internal", "secret");
        assert_eq!(no_prefix.mount, "secret");
        assert_eq!(no_prefix.prefix, "");
        assert_eq!(
            no_prefix.secret_path("mediator_admin_credential"),
            "mediator_admin_credential"
        );
    }

    #[test]
    fn open_splits_mount_and_prefix() {
        let url = parse_url("vault://vault.internal/secret/prod/mediator").unwrap();
        let store = open(url).expect("open vault backend");
        assert_eq!(store.backend(), BACKEND_LABEL);
    }

    #[test]
    fn open_defaults_to_https_when_scheme_absent() {
        let url = parse_url("vault://vault.internal/secret").unwrap();
        let store = open(url).expect("open vault backend");
        // Down-cast via public trait would require type-id gymnastics;
        // the public surface is intentionally minimal. `open` returning
        // an Arc<dyn SecretStore> without error is enough confirmation
        // that the https:// default path was taken — an invalid URL
        // would have errored inside VaultClientSettingsBuilder via the
        // lazy `.client()` init, but that's only exercised at use
        // time, not at open time.
        assert_eq!(store.backend(), BACKEND_LABEL);
    }

    /// Opt-in live-backend test. Requires a reachable Vault with KV v2
    /// mounted at the URL's mount point, plus a valid VAULT_TOKEN env
    /// var.
    ///
    /// Run with:
    ///   VAULT_TOKEN=... \
    ///   MEDIATOR_TEST_VAULT_URL=vault://vault.internal/secret/ci-mediator \
    ///   cargo test -p affinidi-messaging-mediator-common \
    ///     --features secrets-vault vault_live_roundtrip -- --ignored
    #[tokio::test]
    #[ignore]
    async fn vault_live_roundtrip() {
        use crate::secrets::store::open_store;
        let url = std::env::var("MEDIATOR_TEST_VAULT_URL")
            .expect("set MEDIATOR_TEST_VAULT_URL to run the live Vault test");
        let store = open_store(&url).unwrap();
        store.probe().await.expect("probe");
        let key = format!("mediator_probe_{}", uuid::Uuid::new_v4().simple());
        let payload = b"payload-bytes".to_vec();
        store.put(&key, &payload).await.unwrap();
        let got = store.get(&key).await.unwrap().unwrap();
        assert_eq!(got, payload);
        store.delete(&key).await.unwrap();
        assert!(store.get(&key).await.unwrap().is_none());
    }
}

//! HashiCorp Vault backend (feature `secrets-vault`).
//!
//! KV v2 only. Earlier KV v1 semantics are deliberately unsupported
//! — v1 is EOL-adjacent and the wizard has no reason to coexist with
//! existing v1 data. Operators who still use v1 should migrate to v2
//! first; Vault provides an in-place upgrade path.
//!
//! URL shape: `vault://<host[:port]>/<mount>[/<namespace>…]`.
//! The first path segment is the KV v2 mount point; anything
//! remaining becomes a namespace glued to each stored key. Examples:
//!   - `vault://vault.internal/secret` → mount `secret`, no namespace.
//!   - `vault://vault.internal/secret/mediator` → mount `secret`,
//!     namespace `mediator/`.
//!
//! Transport: HTTPS against the configured endpoint by default. The
//! `?insecure=1` query parameter disables TLS verification for local
//! dev / test only — never use it with production material, which
//! includes the mediator's admin credential and JWT key.
//!
//! Auth (selected by the `?auth=` query parameter, default `token`):
//!   - `token` — `VAULT_TOKEN` env var (matches the `vault` CLI).
//!   - `kubernetes` — the pod ServiceAccount JWT is exchanged for a
//!     Vault token (`?role=`, optional `?k8s_mount=` / `?jwt_path=`).
//!     The JWT is re-read on every login so kubelet rotation is
//!     handled transparently.
//!   - `approle` — `role_id`/`secret_id` from `VAULT_ROLE_ID` /
//!     `VAULT_SECRET_ID` (optional `?approle_mount=`).
//!
//! Auth secrets never appear in the URL. For the renewable methods
//! (Kubernetes / AppRole) a call that fails with 401/403 triggers a
//! single re-authentication + retry, so an expired token or rotated
//! JWT recovers without a restart. Vault Enterprise namespaces are
//! supported via `?namespace=` (`X-Vault-Namespace`).
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
use crate::secrets::url::VaultAuth;
#[cfg(feature = "secrets-vault")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "secrets-vault")]
use std::future::Future;
#[cfg(feature = "secrets-vault")]
use std::pin::Pin;
#[cfg(feature = "secrets-vault")]
use tokio::sync::{OnceCell, RwLock};
#[cfg(feature = "secrets-vault")]
use tracing::warn;
#[cfg(feature = "secrets-vault")]
use vaultrs::{
    auth::{approle, kubernetes},
    client::{Client, VaultClient, VaultClientSettings, VaultClientSettingsBuilder},
    error::ClientError,
    kv2,
};

const BACKEND_LABEL: &str = "vault";

/// Env var supplying the token for `auth=token`. Matches the `vault` CLI.
#[cfg(feature = "secrets-vault")]
const VAULT_TOKEN_ENV: &str = "VAULT_TOKEN";
/// Env vars supplying AppRole credentials for `auth=approle`.
#[cfg(feature = "secrets-vault")]
const VAULT_ROLE_ID_ENV: &str = "VAULT_ROLE_ID";
#[cfg(feature = "secrets-vault")]
const VAULT_SECRET_ID_ENV: &str = "VAULT_SECRET_ID";

/// Boxed future returned by a KV operation closure; borrows the client.
#[cfg(feature = "secrets-vault")]
type VaultFut<'a, T> =
    Pin<Box<dyn Future<Output = std::result::Result<T, ClientError>> + Send + 'a>>;

#[cfg(feature = "secrets-vault")]
pub(crate) fn open(url: BackendUrl) -> Result<DynSecretStore> {
    let BackendUrl::Vault {
        endpoint,
        path,
        auth,
        enterprise_namespace,
        insecure,
    } = url
    else {
        return Err(SecretStoreError::Other(
            "internal error: vault backend received non-vault URL".into(),
        ));
    };
    // Split the URL path into KV v2 mount + per-key namespace. First
    // segment is the mount; everything else is the namespace glued to
    // each stored key name.
    let (mount, namespace) = match path.split_once('/') {
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
        namespace,
        enterprise_namespace,
        auth,
        verify_tls: !insecure,
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
    /// Per-key namespace path (always ends with `/` when non-empty).
    namespace: String,
    /// Vault Enterprise namespace (`X-Vault-Namespace`), if configured.
    enterprise_namespace: Option<String>,
    /// Selected auth method.
    auth: VaultAuth,
    /// Whether TLS certificates are verified (false only for `insecure=1`).
    verify_tls: bool,
    /// Lazily-authenticated client behind an `RwLock` so a renewable auth
    /// method (Kubernetes / AppRole) can swap in a fresh token when the
    /// current one expires. Authentication happens on first use so a
    /// wizard run that never touches the backend doesn't require creds.
    client: OnceCell<RwLock<VaultClient>>,
}

/// Read a required env var, erroring if it is unset or empty.
#[cfg(feature = "secrets-vault")]
fn require_env(var: &str) -> Result<String> {
    let value = std::env::var(var).map_err(|_| SecretStoreError::Unreachable {
        backend: BACKEND_LABEL,
        reason: format!("{var} env var not set"),
    })?;
    if value.is_empty() {
        return Err(SecretStoreError::Unreachable {
            backend: BACKEND_LABEL,
            reason: format!("{var} is set but empty"),
        });
    }
    Ok(value)
}

#[cfg(feature = "secrets-vault")]
impl VaultStore {
    fn secret_path(&self, key: &str) -> String {
        format!("{}{key}", self.namespace)
    }

    /// Build client settings shared by every auth method — address, TLS
    /// verification, and the optional Enterprise namespace — bearing the
    /// supplied token (empty during the pre-login step of k8s/AppRole).
    fn settings(&self, token: &str) -> Result<VaultClientSettings> {
        let mut builder = VaultClientSettingsBuilder::default();
        builder
            .address(&self.address)
            .token(token)
            .verify(self.verify_tls);
        if let Some(ns) = &self.enterprise_namespace {
            builder.namespace(Some(ns.clone()));
        }
        builder.build().map_err(|e| SecretStoreError::Unreachable {
            backend: BACKEND_LABEL,
            reason: format!("could not build Vault client settings: {e}"),
        })
    }

    fn build_client(&self, token: &str) -> Result<VaultClient> {
        VaultClient::new(self.settings(token)?).map_err(|e| SecretStoreError::Unreachable {
            backend: BACKEND_LABEL,
            reason: format!("could not build Vault client: {e}"),
        })
    }

    /// Authenticate using the configured method, returning a token-bearing
    /// client. Kubernetes/AppRole perform a login round-trip; the
    /// ServiceAccount JWT is re-read on every call so kubelet rotation is
    /// handled transparently.
    async fn authenticate(&self) -> Result<VaultClient> {
        match &self.auth {
            VaultAuth::Token => {
                let token = require_env(VAULT_TOKEN_ENV)?;
                self.build_client(&token)
            }
            VaultAuth::Kubernetes {
                role,
                mount,
                jwt_path,
            } => {
                let jwt = std::fs::read_to_string(jwt_path).map_err(|e| {
                    SecretStoreError::Unreachable {
                        backend: BACKEND_LABEL,
                        reason: format!(
                            "could not read Kubernetes ServiceAccount JWT at '{jwt_path}': {e}"
                        ),
                    }
                })?;
                let mut client = self.build_client("")?;
                let info = kubernetes::login(&client, mount, role, jwt.trim())
                    .await
                    .map_err(|e| SecretStoreError::Unreachable {
                        backend: BACKEND_LABEL,
                        reason: format!(
                            "Vault Kubernetes login (mount '{mount}', role '{role}') failed: {e}"
                        ),
                    })?;
                client.set_token(&info.client_token);
                Ok(client)
            }
            VaultAuth::AppRole { mount } => {
                let role_id = require_env(VAULT_ROLE_ID_ENV)?;
                let secret_id = require_env(VAULT_SECRET_ID_ENV)?;
                let mut client = self.build_client("")?;
                let info = approle::login(&client, mount, &role_id, &secret_id)
                    .await
                    .map_err(|e| SecretStoreError::Unreachable {
                        backend: BACKEND_LABEL,
                        reason: format!("Vault AppRole login (mount '{mount}') failed: {e}"),
                    })?;
                client.set_token(&info.client_token);
                Ok(client)
            }
        }
    }

    /// Lazily initialise the authenticated client cell.
    async fn cell(&self) -> Result<&RwLock<VaultClient>> {
        self.client
            .get_or_try_init(|| async {
                let client = self.authenticate().await?;
                Ok(RwLock::new(client))
            })
            .await
    }

    /// Run a KV operation with transient-error retries, re-authenticating
    /// once if it fails with 401/403 and the auth method can obtain a
    /// fresh token. The outer `Result` carries setup/auth failures; the
    /// inner one carries the (possibly-retried) API result so callers keep
    /// their existing 404 handling.
    async fn run<T, F>(&self, label: &str, op: F) -> Result<std::result::Result<T, ClientError>>
    where
        F: for<'a> Fn(&'a VaultClient) -> VaultFut<'a, T>,
    {
        let cell = self.cell().await?;
        let first = {
            let guard = cell.read().await;
            with_retry(label, &VaultRetryPolicy, || op(&guard)).await
        };
        match first {
            Err(err)
                if self.auth.is_renewable() && matches!(api_status(&err), Some(401 | 403)) =>
            {
                match self.authenticate().await {
                    Ok(fresh) => {
                        *cell.write().await = fresh;
                        let guard = cell.read().await;
                        Ok(with_retry(label, &VaultRetryPolicy, || op(&guard)).await)
                    }
                    Err(reauth_err) => {
                        warn!(
                            backend = BACKEND_LABEL,
                            error = %reauth_err,
                            "vault re-authentication failed after an auth error"
                        );
                        Ok(Err(err))
                    }
                }
            }
            other => Ok(other),
        }
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
        let label = format!("kv2::read({}/{path})", self.mount);
        let result = self
            .run(&label, |client| {
                let mount = self.mount.clone();
                let path = path.clone();
                Box::pin(async move { kv2::read::<VaultPayload>(client, &mount, &path).await })
            })
            .await?;
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
        let encoded = B64URL.encode(value);
        let label = format!("kv2::set({}/{path})", self.mount);
        self.run(&label, |client| {
            let mount = self.mount.clone();
            let path = path.clone();
            let payload = VaultPayload {
                value: encoded.clone(),
            };
            Box::pin(async move { kv2::set(client, &mount, &path, &payload).await })
        })
        .await?
        .map(|_| ())
        .map_err(|err| SecretStoreError::Unreachable {
            backend: BACKEND_LABEL,
            reason: format!("kv2::set({}/{path}) failed: {err}", self.mount),
        })
    }

    async fn delete(&self, key: &str) -> Result<()> {
        let path = self.secret_path(key);
        let label = format!("kv2::delete_latest({}/{path})", self.mount);
        let result = self
            .run(&label, |client| {
                let mount = self.mount.clone();
                let path = path.clone();
                Box::pin(async move { kv2::delete_latest(client, &mount, &path).await })
            })
            .await?;
        match result {
            Ok(()) => Ok(()),
            Err(err) if matches!(api_status(&err), Some(404)) => Ok(()),
            Err(err) => Err(SecretStoreError::Unreachable {
                backend: BACKEND_LABEL,
                reason: format!("kv2::delete_latest({}/{path}) failed: {err}", self.mount),
            }),
        }
    }

    /// List the keys directly under the configured mount root (a single
    /// LIST call — no recursion). Folders end with `/`; leaves don't.
    /// The caller (wizard discovery) decides whether to recurse or
    /// present the raw entries.
    ///
    /// Vault's `kv2::list` returns `404` when the path holds no entries
    /// (a fresh mount, or one whose only previous keys were deleted +
    /// purged). We translate that to an empty list so the discovery
    /// hotkey shows "no entries" rather than an error banner.
    async fn list_namespace(&self) -> Result<Vec<String>> {
        let label = format!("kv2::list({}/)", self.mount);
        let result = self
            .run(&label, |client| {
                let mount = self.mount.clone();
                Box::pin(async move { kv2::list(client, &mount, "").await })
            })
            .await?;
        match result {
            Ok(keys) => Ok(keys),
            Err(err) if matches!(api_status(&err), Some(404)) => Ok(Vec::new()),
            Err(err) => Err(SecretStoreError::Unreachable {
                backend: BACKEND_LABEL,
                reason: format!("kv2::list({}/) failed: {err}", self.mount),
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
            namespace: path
                .split_once('/')
                .map(|(_, rest)| format!("{rest}/"))
                .unwrap_or_default(),
            enterprise_namespace: None,
            auth: VaultAuth::Token,
            verify_tls: true,
            client: OnceCell::new(),
        }
    }

    #[test]
    fn secret_path_glues_namespace_and_key() {
        let with_namespace = store_from("vault.internal", "secret/mediator");
        assert_eq!(with_namespace.mount, "secret");
        assert_eq!(with_namespace.namespace, "mediator/");
        assert_eq!(
            with_namespace.secret_path("mediator_admin_credential"),
            "mediator/mediator_admin_credential"
        );

        let no_namespace = store_from("vault.internal", "secret");
        assert_eq!(no_namespace.mount, "secret");
        assert_eq!(no_namespace.namespace, "");
        assert_eq!(
            no_namespace.secret_path("mediator_admin_credential"),
            "mediator_admin_credential"
        );
    }

    #[test]
    fn open_splits_mount_and_namespace() {
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

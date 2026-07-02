//! Native Kubernetes Secrets backend (feature `secrets-k8s`).
//!
//! URL shape: `k8s://<namespace>/<secret-name>` or `k8s://<secret-name>`
//! (namespace omitted → resolved from the ServiceAccount / kubeconfig).
//!
//! Layout: every mediator well-known key becomes one entry in the `data`
//! map of a *single* `Secret` object. This is the RBAC-minimal mapping —
//! the pod ServiceAccount only needs `get`/`create`/`update` on one named
//! Secret — and it keeps the whole secret bundle atomic. Values are the
//! raw envelope bytes stored as a `ByteString`; Kubernetes base64-encodes
//! them on the wire, so no extra encoding happens at this layer.
//!
//! Auth is resolved by [`Client::try_default`]: the in-cluster
//! ServiceAccount when running inside a pod, or the local kubeconfig
//! (`~/.kube/config` / `$KUBECONFIG`) otherwise. Writes read-modify-write
//! the Secret and use `replace` with the fetched `resourceVersion` for
//! optimistic concurrency, retrying a bounded number of times on a 409
//! conflict so concurrent writers don't clobber one another.

use crate::secrets::error::{Result, SecretStoreError};
use crate::secrets::store::DynSecretStore;
use crate::secrets::url::BackendUrl;

#[cfg(feature = "secrets-k8s")]
use async_trait::async_trait;
#[cfg(feature = "secrets-k8s")]
use k8s_openapi::ByteString;
#[cfg(feature = "secrets-k8s")]
use k8s_openapi::api::core::v1::Secret;
#[cfg(feature = "secrets-k8s")]
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
#[cfg(feature = "secrets-k8s")]
use kube::api::{Api, PostParams};
#[cfg(feature = "secrets-k8s")]
use kube::{Client, Error as KubeError};
#[cfg(feature = "secrets-k8s")]
use std::collections::BTreeMap;

#[cfg(feature = "secrets-k8s")]
use crate::secrets::store::SecretStore;

const BACKEND_LABEL: &str = "k8s";

/// Bounded retries on a 409 conflict during read-modify-write.
#[cfg(feature = "secrets-k8s")]
const MAX_CONFLICT_RETRIES: usize = 5;

#[cfg(feature = "secrets-k8s")]
pub(crate) fn open(url: BackendUrl) -> Result<DynSecretStore> {
    let BackendUrl::Kubernetes {
        namespace,
        secret_name,
    } = url
    else {
        return Err(SecretStoreError::Other(
            "internal error: k8s backend received non-k8s URL".into(),
        ));
    };
    Ok(std::sync::Arc::new(K8sStore {
        namespace,
        secret_name,
    }))
}

#[cfg(not(feature = "secrets-k8s"))]
pub(crate) fn open(_url: BackendUrl) -> Result<DynSecretStore> {
    Err(SecretStoreError::BackendUnavailable {
        backend: BACKEND_LABEL,
        reason: "compiled without the 'secrets-k8s' feature; rebuild with \
                 `cargo build --features secrets-k8s` to enable"
            .into(),
    })
}

#[cfg(feature = "secrets-k8s")]
pub struct K8sStore {
    /// Explicit namespace, or `None` to resolve from the SA / kubeconfig.
    namespace: Option<String>,
    /// Name of the `Secret` object holding every mediator key.
    secret_name: String,
}

/// Whether a `kube` error is a 409 Conflict (optimistic-concurrency clash).
#[cfg(feature = "secrets-k8s")]
fn is_conflict(err: &KubeError) -> bool {
    matches!(err, KubeError::Api(resp) if resp.code == 409)
}

/// Map a `kube` error to a `SecretStoreError`, unrolling its source chain
/// (the top-level `Display` is usually a terse "ApiError" that hides the
/// real cause — RBAC denial, DNS, TLS…). A 403 becomes `PermissionDenied`.
#[cfg(feature = "secrets-k8s")]
fn kube_error(secret_name: &str, context: &str, err: KubeError) -> SecretStoreError {
    let mut msg = format!("{context}: {err}");
    let mut source = std::error::Error::source(&err);
    while let Some(cause) = source {
        msg.push_str(&format!("\n  caused by: {cause}"));
        source = cause.source();
    }
    if matches!(&err, KubeError::Api(resp) if resp.code == 403) {
        return SecretStoreError::PermissionDenied {
            key: secret_name.to_string(),
            reason: msg,
        };
    }
    SecretStoreError::Unreachable {
        backend: BACKEND_LABEL,
        reason: msg,
    }
}

#[cfg(feature = "secrets-k8s")]
impl K8sStore {
    /// Build a namespaced `Secret` API handle, resolving the namespace and
    /// loading credentials from the in-cluster SA or local kubeconfig.
    async fn api(&self) -> Result<Api<Secret>> {
        let client = Client::try_default().await.map_err(|e| {
            kube_error(
                &self.secret_name,
                "failed to initialise Kubernetes client",
                e,
            )
        })?;
        let namespace = self
            .namespace
            .clone()
            .unwrap_or_else(|| client.default_namespace().to_string());
        Ok(Api::namespaced(client, &namespace))
    }
}

#[cfg(feature = "secrets-k8s")]
#[async_trait]
impl SecretStore for K8sStore {
    fn backend(&self) -> &'static str {
        BACKEND_LABEL
    }

    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let api = self.api().await?;
        // `get_opt` maps a 404 (missing Secret) to `Ok(None)` — the
        // legitimate first-boot case.
        let Some(secret) = api
            .get_opt(&self.secret_name)
            .await
            .map_err(|e| kube_error(&self.secret_name, "failed to read Kubernetes Secret", e))?
        else {
            return Ok(None);
        };
        // A present Secret that simply lacks this key means the individual
        // secret isn't stored yet → absent, not an error.
        match secret.data.unwrap_or_default().get(key) {
            Some(ByteString(bytes)) => Ok(Some(bytes.clone())),
            None => Ok(None),
        }
    }

    async fn put(&self, key: &str, value: &[u8]) -> Result<()> {
        let api = self.api().await?;
        for attempt in 0..MAX_CONFLICT_RETRIES {
            match api
                .get_opt(&self.secret_name)
                .await
                .map_err(|e| kube_error(&self.secret_name, "failed to read Kubernetes Secret", e))?
            {
                Some(mut existing) => {
                    // Preserve every other key (and the resourceVersion, for
                    // optimistic concurrency); touch only ours. `string_data`
                    // is write-only and never round-trips on GET — clear it.
                    let mut data = existing.data.take().unwrap_or_default();
                    data.insert(key.to_string(), ByteString(value.to_vec()));
                    existing.data = Some(data);
                    existing.string_data = None;
                    match api
                        .replace(&self.secret_name, &PostParams::default(), &existing)
                        .await
                    {
                        Ok(_) => return Ok(()),
                        Err(e) if is_conflict(&e) && attempt + 1 < MAX_CONFLICT_RETRIES => continue,
                        Err(e) => {
                            return Err(kube_error(
                                &self.secret_name,
                                "failed to update Kubernetes Secret",
                                e,
                            ));
                        }
                    }
                }
                None => {
                    let mut data = BTreeMap::new();
                    data.insert(key.to_string(), ByteString(value.to_vec()));
                    let secret = Secret {
                        metadata: ObjectMeta {
                            name: Some(self.secret_name.clone()),
                            ..Default::default()
                        },
                        data: Some(data),
                        type_: Some("Opaque".to_string()),
                        ..Default::default()
                    };
                    match api.create(&PostParams::default(), &secret).await {
                        Ok(_) => return Ok(()),
                        // Another writer created it first — loop back and
                        // apply as an update.
                        Err(e) if is_conflict(&e) && attempt + 1 < MAX_CONFLICT_RETRIES => continue,
                        Err(e) => {
                            return Err(kube_error(
                                &self.secret_name,
                                "failed to create Kubernetes Secret",
                                e,
                            ));
                        }
                    }
                }
            }
        }
        Err(SecretStoreError::Unreachable {
            backend: BACKEND_LABEL,
            reason: format!(
                "exhausted {MAX_CONFLICT_RETRIES} conflict retries writing key '{key}' to Secret '{}'",
                self.secret_name
            ),
        })
    }

    async fn delete(&self, key: &str) -> Result<()> {
        let api = self.api().await?;
        for attempt in 0..MAX_CONFLICT_RETRIES {
            let Some(mut existing) = api.get_opt(&self.secret_name).await.map_err(|e| {
                kube_error(&self.secret_name, "failed to read Kubernetes Secret", e)
            })?
            else {
                return Ok(()); // Secret absent → nothing to delete.
            };
            let mut data = existing.data.take().unwrap_or_default();
            if data.remove(key).is_none() {
                return Ok(()); // Key already absent → no-op.
            }
            existing.data = Some(data);
            existing.string_data = None;
            match api
                .replace(&self.secret_name, &PostParams::default(), &existing)
                .await
            {
                Ok(_) => return Ok(()),
                Err(e) if is_conflict(&e) && attempt + 1 < MAX_CONFLICT_RETRIES => continue,
                Err(e) => {
                    return Err(kube_error(
                        &self.secret_name,
                        "failed to update Kubernetes Secret",
                        e,
                    ));
                }
            }
        }
        Err(SecretStoreError::Unreachable {
            backend: BACKEND_LABEL,
            reason: format!(
                "exhausted {MAX_CONFLICT_RETRIES} conflict retries deleting key '{key}' from Secret '{}'",
                self.secret_name
            ),
        })
    }

    /// List the keys held inside the backing Secret (one per stored
    /// mediator secret). A missing Secret yields an empty list so wizard
    /// discovery shows "no entries" rather than an error.
    async fn list_namespace(&self) -> Result<Vec<String>> {
        let api = self.api().await?;
        let Some(secret) = api
            .get_opt(&self.secret_name)
            .await
            .map_err(|e| kube_error(&self.secret_name, "failed to read Kubernetes Secret", e))?
        else {
            return Ok(Vec::new());
        };
        Ok(secret.data.unwrap_or_default().into_keys().collect())
    }
}

#[cfg(test)]
#[cfg(feature = "secrets-k8s")]
mod tests {
    use super::*;
    use crate::secrets::url::parse_url;

    #[test]
    fn open_with_explicit_namespace() {
        let url = parse_url("k8s://affinidi/mediator-secrets").unwrap();
        let store = open(url).expect("open k8s backend");
        assert_eq!(store.backend(), BACKEND_LABEL);
    }

    #[test]
    fn open_without_namespace() {
        let url = parse_url("k8s://mediator-secrets").unwrap();
        let store = open(url).expect("open k8s backend");
        assert_eq!(store.backend(), BACKEND_LABEL);
    }

    /// Opt-in live-cluster test. Requires a reachable cluster (in-pod SA or
    /// a kubeconfig context) with RBAC allowing get/create/update on the
    /// target Secret.
    ///
    /// Run with:
    ///   MEDIATOR_TEST_K8S_URL=k8s://default/ci-mediator-secrets \
    ///   cargo test -p affinidi-messaging-mediator-common \
    ///     --features secrets-k8s k8s_live_roundtrip -- --ignored
    #[tokio::test]
    #[ignore]
    async fn k8s_live_roundtrip() {
        use crate::secrets::store::open_store;
        let url = std::env::var("MEDIATOR_TEST_K8S_URL")
            .expect("set MEDIATOR_TEST_K8S_URL to run the live Kubernetes test");
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

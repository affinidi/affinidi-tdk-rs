//! GCP Secret Manager backend (feature `secrets-gcp`).
//!
//! Every mediator secret is stored as a GCP Secret named
//! `<prefix><key>` under the configured project. The secret itself is
//! the persistent container; each [`SecretStore::put`] appends a new
//! `SecretVersion` and `get` reads the `latest` version. This matches
//! GCP's data-model (versions are additive, immutable, and the "live"
//! pointer follows the most recent).
//!
//! Secret naming fits the flat `[a-z0-9_]` well-known scheme verbatim
//! — GCP accepts `[A-Za-z0-9_-]+` so no encoding is required. The
//! setup wizard only ever writes flat keys; we still guard against
//! `/` sneaking in with a one-line sanity check so a future caller
//! can't accidentally hand GCP an invalid name.
//!
//! Calls go through [`super::super::retry::with_retry`] with
//! [`GcpRetryPolicy`]: Unavailable / DeadlineExceeded / ResourceExhausted /
//! Aborted / Internal retry; NotFound, AlreadyExists, PermissionDenied,
//! Unauthenticated, and InvalidArgument short-circuit so the caller's
//! error path runs unchanged.
//!
//! Auth is via Google's Application Default Credentials chain (the
//! `GOOGLE_APPLICATION_CREDENTIALS` env var, `gcloud auth
//! application-default login`, GKE workload identity, ...). The wizard
//! does not prompt for credentials — a misconfigured environment
//! surfaces at `probe` time with the upstream SDK's error message.

use crate::secrets::error::{Result, SecretStoreError};
use crate::secrets::store::DynSecretStore;
use crate::secrets::url::BackendUrl;

#[cfg(feature = "secrets-gcp")]
use crate::secrets::retry::{RetryPolicy, Retryable, with_retry};
#[cfg(feature = "secrets-gcp")]
use crate::secrets::store::SecretStore;
#[cfg(feature = "secrets-gcp")]
use async_trait::async_trait;
#[cfg(feature = "secrets-gcp")]
use google_cloud_secretmanager_v1::{
    Error as GcpError,
    client::SecretManagerService,
    model::{Replication, Secret, SecretPayload, replication::Automatic},
};
#[cfg(feature = "secrets-gcp")]
use tokio::sync::OnceCell;

const BACKEND_LABEL: &str = "gcp_secrets";

#[cfg(feature = "secrets-gcp")]
pub(crate) fn open(url: BackendUrl) -> Result<DynSecretStore> {
    let BackendUrl::Gcp { project, prefix } = url else {
        return Err(SecretStoreError::Other(
            "internal error: gcp backend received non-gcp URL".into(),
        ));
    };
    Ok(std::sync::Arc::new(GcpStore {
        project,
        prefix,
        client: OnceCell::new(),
    }))
}

#[cfg(not(feature = "secrets-gcp"))]
pub(crate) fn open(_url: BackendUrl) -> Result<DynSecretStore> {
    Err(SecretStoreError::BackendUnavailable {
        backend: BACKEND_LABEL,
        reason: "compiled without the 'secrets-gcp' feature; rebuild with \
                 `cargo build --features secrets-gcp` to enable"
            .into(),
    })
}

#[cfg(feature = "secrets-gcp")]
pub struct GcpStore {
    project: String,
    prefix: String,
    /// Lazily-constructed SDK client. GCP's `build()` is async and does
    /// credential discovery; caching avoids re-running the full ADC
    /// chain on every `get`/`put`/`delete`.
    client: OnceCell<SecretManagerService>,
}

#[cfg(feature = "secrets-gcp")]
impl GcpStore {
    /// Build the resource name used across all SDK calls. Shape:
    /// `projects/<project>/secrets/<prefix><key>`.
    fn secret_name(&self, key: &str) -> String {
        format!("projects/{}/secrets/{}{}", self.project, self.prefix, key)
    }

    /// Parent for `create_secret` / `list_secrets`:
    /// `projects/<project>`.
    fn parent(&self) -> String {
        format!("projects/{}", self.project)
    }

    /// Access path for the `latest` version of a secret.
    fn latest_version(&self, key: &str) -> String {
        format!("{}/versions/latest", self.secret_name(key))
    }

    /// Defence-in-depth: our flat well-known keys never contain `/`,
    /// but a future caller could try one. GCP would reject it
    /// server-side; catching it here gives a clearer error with the
    /// backend and key in scope.
    fn validate_key(&self, key: &str) -> Result<()> {
        if key.contains('/') {
            return Err(SecretStoreError::InvalidShape {
                key: key.to_string(),
                reason: "GCP secret names cannot contain '/' — well-known keys must use \
                         the flat [a-z0-9_] form"
                    .into(),
            });
        }
        Ok(())
    }

    async fn client(&self) -> Result<&SecretManagerService> {
        self.client
            .get_or_try_init(|| async {
                SecretManagerService::builder().build().await.map_err(|e| {
                    SecretStoreError::Unreachable {
                        backend: BACKEND_LABEL,
                        reason: format!("could not build GCP client: {e}"),
                    }
                })
            })
            .await
    }
}

/// Retry policy for GCP SDK errors. Retries transient RPC failures
/// and short-circuits on terminal status codes. Unknown / RPC-layer
/// errors (connection reset, dispatch failure) are treated as
/// transient on the same reasoning as AWS.
#[cfg(feature = "secrets-gcp")]
pub(crate) struct GcpRetryPolicy;

#[cfg(feature = "secrets-gcp")]
impl RetryPolicy<GcpError> for GcpRetryPolicy {
    fn classify(&self, err: &GcpError) -> Retryable {
        use google_cloud_gax::error::rpc::Code;

        if let Some(status) = err.status() {
            return match status.code {
                Code::NotFound
                | Code::AlreadyExists
                | Code::PermissionDenied
                | Code::Unauthenticated
                | Code::InvalidArgument
                | Code::FailedPrecondition
                | Code::OutOfRange => Retryable::No,
                Code::Unavailable
                | Code::DeadlineExceeded
                | Code::ResourceExhausted
                | Code::Aborted
                | Code::Internal => Retryable::Yes { retry_after: None },
                _ => Retryable::No,
            };
        }
        // No RPC status → connection-layer failure (DNS, TCP reset,
        // timeout before a response framed). Treat as transient, same
        // reasoning as the AWS backend.
        if err.is_timeout() {
            return Retryable::Yes { retry_after: None };
        }
        Retryable::Yes { retry_after: None }
    }
}

#[cfg(feature = "secrets-gcp")]
#[async_trait]
impl SecretStore for GcpStore {
    fn backend(&self) -> &'static str {
        BACKEND_LABEL
    }

    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        self.validate_key(key)?;
        let name = self.latest_version(key);
        let client = self.client().await?.clone();
        let label = format!("AccessSecretVersion({name})");
        let response = with_retry(&label, &GcpRetryPolicy, || {
            let client = client.clone();
            let name = name.clone();
            async move { client.access_secret_version().set_name(&name).send().await }
        })
        .await;
        let response = match response {
            Ok(r) => r,
            Err(err) => {
                if matches!(
                    err.status().map(|s| s.code),
                    Some(google_cloud_gax::error::rpc::Code::NotFound)
                ) {
                    return Ok(None);
                }
                return Err(SecretStoreError::Unreachable {
                    backend: BACKEND_LABEL,
                    reason: format!("AccessSecretVersion({name}) failed: {err}"),
                });
            }
        };
        let Some(payload) = response.payload else {
            return Err(SecretStoreError::InvalidShape {
                key: key.to_string(),
                reason: "GCP secret version has no payload".into(),
            });
        };
        Ok(Some(payload.data.to_vec()))
    }

    async fn put(&self, key: &str, value: &[u8]) -> Result<()> {
        self.validate_key(key)?;
        let secret_name = self.secret_name(key);
        let client = self.client().await?.clone();
        // Copy once up front; each retry attempt gets its own clone of
        // the Vec rather than relying on a shared `bytes::Bytes`
        // (avoids naming the transitive crate in our own code).
        let payload_bytes = value.to_vec();

        // Try AddSecretVersion first (the common case: secret already
        // exists). On NotFound, CreateSecret with automatic replication
        // and retry the AddSecretVersion exactly once — the create +
        // add pair isn't atomic on GCP's side either.
        let add_label = format!("AddSecretVersion({secret_name})");
        let add_result = with_retry(&add_label, &GcpRetryPolicy, || {
            let client = client.clone();
            let parent = secret_name.clone();
            let payload = SecretPayload::new().set_data(payload_bytes.clone());
            async move {
                client
                    .add_secret_version()
                    .set_parent(&parent)
                    .set_payload(payload)
                    .send()
                    .await
            }
        })
        .await;

        match add_result {
            Ok(_) => Ok(()),
            Err(err)
                if matches!(
                    err.status().map(|s| s.code),
                    Some(google_cloud_gax::error::rpc::Code::NotFound)
                ) =>
            {
                let parent = self.parent();
                let secret_id = format!("{}{}", self.prefix, key);
                let create_label = format!("CreateSecret({secret_name})");
                with_retry(&create_label, &GcpRetryPolicy, || {
                    let client = client.clone();
                    let parent = parent.clone();
                    let secret_id = secret_id.clone();
                    let secret = Secret::new()
                        .set_replication(Replication::new().set_automatic(Automatic::default()));
                    async move {
                        client
                            .create_secret()
                            .set_parent(&parent)
                            .set_secret_id(&secret_id)
                            .set_secret(secret)
                            .send()
                            .await
                    }
                })
                .await
                .map_err(|e| SecretStoreError::Unreachable {
                    backend: BACKEND_LABEL,
                    reason: format!("CreateSecret({secret_name}) failed: {e}"),
                })?;

                // Follow up with the AddSecretVersion that originally
                // missed. The exception case is symmetric with AWS's
                // PutSecretValue → CreateSecret fallback.
                with_retry(&add_label, &GcpRetryPolicy, || {
                    let client = client.clone();
                    let parent = secret_name.clone();
                    let payload = SecretPayload::new().set_data(payload_bytes.clone());
                    async move {
                        client
                            .add_secret_version()
                            .set_parent(&parent)
                            .set_payload(payload)
                            .send()
                            .await
                    }
                })
                .await
                .map_err(|e| SecretStoreError::Unreachable {
                    backend: BACKEND_LABEL,
                    reason: format!("AddSecretVersion({secret_name}) failed after create: {e}"),
                })?;
                Ok(())
            }
            Err(err) => Err(SecretStoreError::Unreachable {
                backend: BACKEND_LABEL,
                reason: format!("AddSecretVersion({secret_name}) failed: {err}"),
            }),
        }
    }

    async fn delete(&self, key: &str) -> Result<()> {
        self.validate_key(key)?;
        let name = self.secret_name(key);
        let client = self.client().await?.clone();
        let label = format!("DeleteSecret({name})");
        let result = with_retry(&label, &GcpRetryPolicy, || {
            let client = client.clone();
            let name = name.clone();
            async move { client.delete_secret().set_name(&name).send().await }
        })
        .await;
        match result {
            Ok(()) => Ok(()),
            Err(err)
                if matches!(
                    err.status().map(|s| s.code),
                    Some(google_cloud_gax::error::rpc::Code::NotFound)
                ) =>
            {
                Ok(())
            }
            Err(err) => Err(SecretStoreError::Unreachable {
                backend: BACKEND_LABEL,
                reason: format!("DeleteSecret({name}) failed: {err}"),
            }),
        }
    }

    /// Walks `ListSecrets` pages until exhausted and returns the resource
    /// names *with the `projects/<project>/secrets/` prefix stripped* —
    /// the `Secret.name` field uses the full resource path, but the
    /// caller's discovery flow wants to compare against the stored
    /// per-secret IDs. Each page is its own `with_retry` so a transient
    /// failure mid-walk doesn't lose the earlier batches.
    async fn list_namespace(&self) -> Result<Vec<String>> {
        let parent = self.parent();
        let client = self.client().await?.clone();
        let mut names: Vec<String> = Vec::new();
        let mut page_token: String = String::new();
        let resource_prefix = format!("{parent}/secrets/");
        loop {
            let token_for_label = if page_token.is_empty() {
                "first".into()
            } else {
                format!("...{}", &page_token[page_token.len().saturating_sub(8)..])
            };
            let label = format!("ListSecrets({token_for_label})");
            let response = with_retry(&label, &GcpRetryPolicy, || {
                let client = client.clone();
                let parent = parent.clone();
                let token = page_token.clone();
                async move {
                    client
                        .list_secrets()
                        .set_parent(&parent)
                        .set_page_token(token)
                        .send()
                        .await
                }
            })
            .await
            .map_err(|err| SecretStoreError::Unreachable {
                backend: BACKEND_LABEL,
                reason: format!("ListSecrets({parent}) failed: {err}"),
            })?;

            for secret in response.secrets {
                // `secret.name` is a fully-qualified resource path; strip
                // the parent so callers see just the per-secret id (the
                // shape they'd type if they were configuring a prefix).
                let id = secret
                    .name
                    .strip_prefix(&resource_prefix)
                    .unwrap_or(&secret.name)
                    .to_string();
                if !id.is_empty() {
                    names.push(id);
                }
            }
            if response.next_page_token.is_empty() {
                break;
            }
            page_token = response.next_page_token;
        }
        Ok(names)
    }
}

#[cfg(test)]
#[cfg(feature = "secrets-gcp")]
mod tests {
    use super::*;
    use crate::secrets::url::parse_url;

    fn sample_store() -> GcpStore {
        GcpStore {
            project: "my-proj".into(),
            prefix: "test_".into(),
            client: OnceCell::new(),
        }
    }

    #[test]
    fn secret_name_assembles_project_and_prefix() {
        let store = sample_store();
        assert_eq!(
            store.secret_name("mediator_admin_credential"),
            "projects/my-proj/secrets/test_mediator_admin_credential"
        );
    }

    #[test]
    fn latest_version_resource_shape() {
        let store = sample_store();
        assert_eq!(
            store.latest_version("mediator_jwt_secret"),
            "projects/my-proj/secrets/test_mediator_jwt_secret/versions/latest"
        );
    }

    #[test]
    fn parent_is_project_only() {
        assert_eq!(sample_store().parent(), "projects/my-proj");
    }

    #[test]
    fn validate_key_rejects_slash() {
        let store = sample_store();
        assert!(
            matches!(
                store.validate_key("has/slash"),
                Err(SecretStoreError::InvalidShape { .. })
            ),
            "keys containing '/' must be rejected before hitting GCP"
        );
        assert!(store.validate_key("mediator_admin_credential").is_ok());
    }

    #[test]
    fn open_returns_gcp_store_for_gcp_url() {
        let url = parse_url("gcp_secrets://my-proj/mediator_").unwrap();
        let store = open(url).expect("open gcp backend");
        assert_eq!(store.backend(), BACKEND_LABEL);
    }

    /// Opt-in live-backend test. Requires a real GCP project reachable
    /// via Application Default Credentials and a prefix under which
    /// throwaway secrets may be created + deleted.
    ///
    /// Run with:
    ///   MEDIATOR_TEST_GCP_URL=gcp_secrets://PROJECT/ci-mediator- \
    ///   cargo test -p affinidi-messaging-mediator-common \
    ///     --features secrets-gcp gcp_live_roundtrip -- --ignored
    #[tokio::test]
    #[ignore]
    async fn gcp_live_roundtrip() {
        use crate::secrets::store::open_store;
        let url = std::env::var("MEDIATOR_TEST_GCP_URL")
            .expect("set MEDIATOR_TEST_GCP_URL to run the live GCP test");
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

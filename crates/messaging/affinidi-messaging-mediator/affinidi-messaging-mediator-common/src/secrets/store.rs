//! The [`SecretStore`] trait and factory.
//!
//! Every backend implements this single trait. Callers construct a concrete
//! store via [`open_store`] from a URL (e.g. `keyring://affinidi-mediator`),
//! then use the trait's four methods — `get`, `put`, `delete`, `probe` — for
//! all further interaction.
//!
//! `put` semantics are overwrite (no atomic-compare-and-swap primitive in
//! the trait); the mediator is assumed single-writer per the HA decision.
//! `probe` writes → reads back → deletes a namespaced UUID sentinel, so
//! success means end-to-end round-trip works (not just "connection open").

use std::sync::Arc;

use async_trait::async_trait;
use uuid::Uuid;

use crate::secrets::backends;
use crate::secrets::error::{Result, SecretStoreError};
use crate::secrets::url::{BackendUrl, parse_url};
use crate::secrets::well_known::{PROBE_READONLY_KEY, PROBE_SENTINEL_PREFIX};

/// Convenience alias for a heap-allocated, trait-object-backed store.
pub type DynSecretStore = Arc<dyn SecretStore>;

/// Pluggable key-value store for mediator secrets.
///
/// Implementations must be thread-safe (`Send + Sync`) because a single
/// store is shared across the mediator's request-handling and background
/// tasks.
#[async_trait]
pub trait SecretStore: Send + Sync {
    /// Return the backend scheme (e.g. `"keyring"`, `"file"`). Used in
    /// log messages and error reports.
    fn backend(&self) -> &'static str;

    /// Fetch the bytes stored under `key`, or `Ok(None)` if no entry
    /// exists. Distinguishes "absent" from "unreachable": an unreachable
    /// backend returns `Err`.
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>>;

    /// Overwrite (or create) the entry under `key`.
    async fn put(&self, key: &str, value: &[u8]) -> Result<()>;

    /// Delete the entry under `key`. No-op if it doesn't exist — use
    /// [`SecretStore::get`] first if you need to distinguish.
    async fn delete(&self, key: &str) -> Result<()>;

    /// Enumerate every secret reachable in the backend's *namespace* — the
    /// region / project / vault / mount the URL points at, NOT just the
    /// keys under the configured per-deployment prefix. Setup tooling
    /// uses this to help operators discover existing prefixes (and pick
    /// an existing deployment) without having to remember exact names.
    ///
    /// Returns the FULL secret names as the backend stores them (with
    /// any prefix the backend appends). Implementations that lack an
    /// efficient list operation — keyring (per-OS), file (single blob) —
    /// return [`SecretStoreError::BackendUnavailable`] so callers can
    /// distinguish "this backend has no entries" from "this backend
    /// can't enumerate" and fall back to manual entry.
    ///
    /// Default impl returns `BackendUnavailable`; cloud backends override.
    async fn list_namespace(&self) -> Result<Vec<String>> {
        Err(SecretStoreError::BackendUnavailable {
            backend: self.backend(),
            reason: "this backend does not support enumeration".into(),
        })
    }

    /// End-to-end health check: write a sentinel under a namespaced UUID
    /// key, read it back, delete it. Returns `Err` if any step fails
    /// (unreachable backend, permission issue, read/write mismatch).
    async fn probe(&self) -> Result<()> {
        // UUID in simple form = 32 hex chars (no hyphens) which keeps
        // the sentinel within the flat [a-z0-9_] class all backends
        // accept verbatim.
        let key = format!("{PROBE_SENTINEL_PREFIX}{}", Uuid::new_v4().simple());
        let expected: Vec<u8> = b"probe".to_vec();
        self.put(&key, &expected).await?;
        let got = self.get(&key).await?;
        // Best-effort delete regardless — if the sentinel can't be removed
        // (permissions, etc.) we still surface that separately via the
        // subsequent delete call's result rather than leaving it in the
        // backend silently.
        let delete_result = self.delete(&key).await;

        let Some(got) = got else {
            return Err(SecretStoreError::ProbeFailed {
                backend: self.backend(),
                reason: "sentinel disappeared between write and read".into(),
            });
        };
        if got != expected {
            return Err(SecretStoreError::ProbeFailed {
                backend: self.backend(),
                reason: "sentinel roundtrip produced different bytes".into(),
            });
        }
        delete_result.map_err(|e| SecretStoreError::ProbeFailed {
            backend: self.backend(),
            reason: format!("sentinel read OK but delete failed: {e}"),
        })
    }

    /// Read-only reachability + credential check: proves the backend is
    /// reachable and the caller is authenticated **without mutating it**.
    ///
    /// Unlike [`SecretStore::probe`] (write → read → delete, requires write
    /// permissions), the default impl only reads the fixed [`PROBE_READONLY_KEY`]
    /// sentinel, so a read-only caller can use it. The sentinel is never
    /// written, so `Ok(None)` is the healthy case — it still proves the
    /// backend answered with valid credentials; only a transport/permission
    /// failure returns `Err` (propagated verbatim, so an unreachable backend
    /// surfaces as [`SecretStoreError::Unreachable`] identically to `get`).
    ///
    /// A read-only role must be granted the sentinel's **prefix**
    /// (`mediator_probe_*`), not just the well-known keys — e.g. on AWS,
    /// `Resource: arn:…:secret:mediator_probe_*` with `GetSecretValue`. A role
    /// scoped to an enumerated list of exact secret ARNs gets `AccessDenied`
    /// (→ `Unreachable`) and would report a healthy backend as down. Every
    /// call also emits a `ResourceNotFound`-shaped entry in the backend's
    /// audit log (CloudTrail / Cloud Audit Logs).
    ///
    /// The default reads through [`SecretStore::get`], so it is only a genuine
    /// health signal for backends whose `get` performs a live round-trip
    /// (cloud, `k8s`, `keyring`). The `file` / `file_encrypted` backends serve
    /// `get` from an in-memory cache after `open()`, so they override this to
    /// re-touch the disk.
    async fn probe_readonly(&self) -> Result<()> {
        // Fixed key (never written), so a healthy backend reads Ok(None).
        // Propagate the backend's error verbatim to match probe()'s read path.
        self.get(PROBE_READONLY_KEY).await.map(|_| ())
    }
}

/// Construct a store from a backend URL. Each supported scheme is
/// dispatched to its concrete implementation; the URL's query parameters
/// and path structure are interpreted by the backend itself.
pub fn open_store(url: &str) -> Result<DynSecretStore> {
    let parsed = parse_url(url)?;
    match &parsed {
        BackendUrl::Keyring { .. } => backends::keyring::open(parsed),
        BackendUrl::File {
            encrypted: true, ..
        } => backends::file_encrypted::open(parsed),
        BackendUrl::File { .. } => backends::file::open(parsed),
        BackendUrl::Aws { .. } => backends::aws::open(parsed),
        BackendUrl::Gcp { .. } => backends::gcp::open(parsed),
        BackendUrl::Azure { .. } => backends::azure::open(parsed),
        BackendUrl::Vault { .. } => backends::vault::open(parsed),
        BackendUrl::Kubernetes { .. } => backends::k8s::open(parsed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secrets::backends::memory::MemoryStore;

    #[tokio::test]
    async fn probe_succeeds_on_a_functioning_store() {
        let store: DynSecretStore = Arc::new(MemoryStore::new("memory"));
        store.probe().await.unwrap();
    }

    #[test]
    fn probe_readonly_key_lives_under_the_sentinel_prefix() {
        assert!(PROBE_READONLY_KEY.starts_with(PROBE_SENTINEL_PREFIX));
    }

    #[tokio::test]
    async fn probe_readonly_succeeds_on_empty_store() {
        // The sentinel key is absent, so this exercises the healthy
        // "authorized but empty" path: get returns Ok(None), probe passes.
        let store: DynSecretStore = Arc::new(MemoryStore::new("memory"));
        store.probe_readonly().await.unwrap();
    }

    #[tokio::test]
    async fn probe_readonly_does_not_mutate_the_store() {
        let store: DynSecretStore = Arc::new(MemoryStore::new("memory"));
        store.probe_readonly().await.unwrap();
        // A read-only probe must leave no sentinel behind.
        assert!(store.get(PROBE_READONLY_KEY).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn probe_readonly_surfaces_a_backend_error_verbatim() {
        // A backend whose get() is unreachable must surface as Unreachable
        // through probe_readonly() too — the same variant probe()'s read path
        // yields — not wrapped into a different error.
        struct UnreachableStore;
        #[async_trait]
        impl SecretStore for UnreachableStore {
            fn backend(&self) -> &'static str {
                "unreachable-test"
            }
            async fn get(&self, _key: &str) -> Result<Option<Vec<u8>>> {
                Err(SecretStoreError::Unreachable {
                    backend: "unreachable-test",
                    reason: "simulated transport failure".into(),
                })
            }
            async fn put(&self, _key: &str, _value: &[u8]) -> Result<()> {
                unreachable!("probe_readonly must not write")
            }
            async fn delete(&self, _key: &str) -> Result<()> {
                unreachable!("probe_readonly must not delete")
            }
        }

        let store: DynSecretStore = Arc::new(UnreachableStore);
        let err = store.probe_readonly().await.unwrap_err();
        assert!(
            matches!(err, SecretStoreError::Unreachable { backend, .. } if backend == "unreachable-test"),
            "expected Unreachable, got {err:?}"
        );
    }
}

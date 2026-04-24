//! `file://` backend.
//!
//! Stores all entries as a single JSON object keyed by secret name at a
//! path the operator controls. Each value is a base64url string (so binary
//! envelopes survive JSON round-tripping).
//!
//! **Safety:** plaintext on disk by default — only sane for local dev/test
//! or as a target for envelope encryption (see Phase H — `?encrypt=1`).
//! The parent directory is created if missing; the file itself is written
//! with mode 0600 on unix to limit exposure to the owner.
//!
//! Concurrent access: this backend assumes single-writer (per the HA
//! decision: mediator is single-writer; replicas should use a cloud
//! backend). Two processes racing on the same file risk lost writes — we
//! don't flock because file:// is dev/test territory anyway.

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;

use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use serde::{Deserialize, Serialize};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

use crate::secrets::error::{Result, SecretStoreError};
use crate::secrets::store::{DynSecretStore, SecretStore};
use crate::secrets::url::BackendUrl;

const BACKEND_LABEL: &str = "file";

pub(crate) fn open(url: BackendUrl) -> Result<DynSecretStore> {
    // Encrypted (`?encrypt=1`) URLs are routed by `store::open_store`
    // to `file_encrypted::open` *before* this function is called, so by
    // the time we get here `encrypted` must be false. We still match
    // exhaustively so the dispatcher contract is enforced — a future
    // mis-route would surface as a clear error rather than silently
    // bypassing encryption.
    let BackendUrl::File { path, encrypted } = url else {
        return Err(SecretStoreError::Other(
            "internal error: file backend received non-file URL".into(),
        ));
    };
    if encrypted {
        return Err(SecretStoreError::Other(
            "internal error: encrypted file URL reached the plaintext backend".into(),
        ));
    }
    Ok(std::sync::Arc::new(FileStore {
        path: PathBuf::from(path),
        state: Mutex::new(None),
    }))
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct StoreFile {
    /// Base64url-encoded entries, keyed by secret name.
    entries: BTreeMap<String, String>,
}

pub struct FileStore {
    path: PathBuf,
    /// Cached contents from the last read/write. Rebuilt lazily on first
    /// access; kept in-memory thereafter so repeated reads don't re-hit
    /// disk.
    state: Mutex<Option<StoreFile>>,
}

impl FileStore {
    fn load_locked(&self) -> Result<StoreFile> {
        match fs::read(&self.path) {
            Ok(bytes) if bytes.is_empty() => Ok(StoreFile::default()),
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(|e| SecretStoreError::Io {
                backend: BACKEND_LABEL,
                source: std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("failed to parse store file {}: {e}", self.path.display()),
                ),
            }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(StoreFile::default()),
            Err(e) => Err(SecretStoreError::Io {
                backend: BACKEND_LABEL,
                source: e,
            }),
        }
    }

    fn save_locked(&self, file: &StoreFile) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).map_err(|e| SecretStoreError::Io {
                    backend: BACKEND_LABEL,
                    source: e,
                })?;
            }
        }
        let body = serde_json::to_vec_pretty(file)?;
        let mut opts = fs::OpenOptions::new();
        opts.create(true).write(true).truncate(true);
        #[cfg(unix)]
        opts.mode(0o600);
        let mut handle = opts.open(&self.path).map_err(|e| SecretStoreError::Io {
            backend: BACKEND_LABEL,
            source: e,
        })?;
        handle.write_all(&body).map_err(|e| SecretStoreError::Io {
            backend: BACKEND_LABEL,
            source: e,
        })?;
        #[cfg(unix)]
        {
            let mut perm = fs::metadata(&self.path)
                .map_err(|e| SecretStoreError::Io {
                    backend: BACKEND_LABEL,
                    source: e,
                })?
                .permissions();
            perm.set_mode(0o600);
            let _ = fs::set_permissions(&self.path, perm);
        }
        Ok(())
    }
}

#[async_trait]
impl SecretStore for FileStore {
    fn backend(&self) -> &'static str {
        BACKEND_LABEL
    }

    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let mut guard = self
            .state
            .lock()
            .map_err(|e| SecretStoreError::other(format!("file store poisoned: {e}")))?;
        if guard.is_none() {
            *guard = Some(self.load_locked()?);
        }
        let state = guard.as_ref().expect("just initialised");
        Ok(state
            .entries
            .get(key)
            .map(|b64| B64URL.decode(b64))
            .transpose()
            .map_err(|e| SecretStoreError::Io {
                backend: BACKEND_LABEL,
                source: std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("entry '{key}' is not valid base64: {e}"),
                ),
            })?)
    }

    async fn put(&self, key: &str, value: &[u8]) -> Result<()> {
        let mut guard = self
            .state
            .lock()
            .map_err(|e| SecretStoreError::other(format!("file store poisoned: {e}")))?;
        let mut state = guard
            .take()
            .unwrap_or_else(|| self.load_locked().unwrap_or_default());
        state.entries.insert(key.to_string(), B64URL.encode(value));
        self.save_locked(&state)?;
        *guard = Some(state);
        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<()> {
        let mut guard = self
            .state
            .lock()
            .map_err(|e| SecretStoreError::other(format!("file store poisoned: {e}")))?;
        let mut state = guard
            .take()
            .unwrap_or_else(|| self.load_locked().unwrap_or_default());
        if state.entries.remove(key).is_some() {
            self.save_locked(&state)?;
        }
        *guard = Some(state);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn roundtrip_survives_process_lifetime() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("secrets.json");
        let url = BackendUrl::File {
            path: path.to_string_lossy().into(),
            encrypted: false,
        };

        let store = open(url).unwrap();
        store
            .put("mediator_admin_credential", b"hello")
            .await
            .unwrap();
        store.put("mediator_jwt_secret", b"world").await.unwrap();
        let got = store.get("mediator_admin_credential").await.unwrap();
        assert_eq!(got.as_deref(), Some(b"hello" as &[u8]));

        // Second open on the same path sees persisted data.
        let url2 = BackendUrl::File {
            path: path.to_string_lossy().into(),
            encrypted: false,
        };
        let store2 = open(url2).unwrap();
        let got = store2.get("mediator_jwt_secret").await.unwrap();
        assert_eq!(got.as_deref(), Some(b"world" as &[u8]));
    }

    #[tokio::test]
    async fn encrypted_url_misrouted_to_plaintext_backend_is_rejected() {
        // Sanity check on the dispatcher contract: if anything ever
        // routes an encrypted URL straight at this backend, it should
        // hard-fail rather than write plaintext to disk.
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("secrets.json");
        let url = BackendUrl::File {
            path: path.to_string_lossy().into(),
            encrypted: true,
        };
        match open(url) {
            Ok(_) => panic!("encrypted file:// must not open as plaintext"),
            Err(SecretStoreError::Other(msg)) => {
                assert!(msg.contains("encrypted file URL"), "wrong message: {msg}");
            }
            Err(other) => panic!("wrong error variant: {other}"),
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn written_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("secrets.json");
        let url = BackendUrl::File {
            path: path.to_string_lossy().into(),
            encrypted: false,
        };
        let store = open(url).unwrap();
        store.put("mediator_jwt_secret", b"x").await.unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "file:// must write owner-only");
    }

    #[tokio::test]
    async fn delete_of_missing_key_is_ok() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("secrets.json");
        let url = BackendUrl::File {
            path: path.to_string_lossy().into(),
            encrypted: false,
        };
        let store = open(url).unwrap();
        store.delete("does-not-exist").await.unwrap();
    }
}

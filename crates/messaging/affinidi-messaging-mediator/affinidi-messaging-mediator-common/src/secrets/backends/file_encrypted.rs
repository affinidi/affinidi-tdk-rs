//! `file://?encrypt=1` envelope-encryption backend.
//!
//! Same on-disk shape as the plaintext [`super::file::FileStore`] — a
//! single JSON file at an operator-chosen path, owner-only `0600` on
//! unix — but every value is sealed with AES-256-GCM under a key
//! derived from a deployment-wide passphrase via Argon2id.
//!
//! Format (JSON, pretty):
//!
//! ```json
//! {
//!   "version": 1,
//!   "kdf": {
//!     "algo": "argon2id",
//!     "salt_b64": "<22-byte base64url salt>",
//!     "memory_kib": 65536,
//!     "iterations": 3,
//!     "parallelism": 4
//!   },
//!   "verifier_b64": "<AES-GCM seal of a 32-byte zero block, used as a
//!                    fast wrong-passphrase check at open time>",
//!   "verifier_nonce_b64": "<12-byte nonce for the verifier>",
//!   "entries": {
//!     "<key>": {
//!       "nonce_b64": "<12-byte base64url nonce>",
//!       "ciphertext_b64": "<AES-GCM(value || tag)>"
//!     }
//!   }
//! }
//! ```
//!
//! Salt + KDF parameters are persisted in the file so the same
//! passphrase derives the same key on every open without round-trips.
//! Per-entry nonces are random per write — re-storing the same key
//! changes the ciphertext. The verifier lets the open path detect a
//! wrong passphrase up-front rather than on first `get` of a real
//! entry.
//!
//! The passphrase is fetched in [`load_passphrase`] from the
//! `MEDIATOR_FILE_BACKEND_PASSPHRASE` env var (preferred for
//! containers) or the file pointed to by
//! `MEDIATOR_FILE_BACKEND_PASSPHRASE_FILE` (preferred when secrets
//! ship via a tmpfs / k8s Secret mount). The wizard's interactive
//! flow sets the env var before opening the store.

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use rand::TryRng;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

use crate::secrets::error::{Result, SecretStoreError};
use crate::secrets::store::{DynSecretStore, SecretStore};
use crate::secrets::url::BackendUrl;

const BACKEND_LABEL: &str = "file-encrypted";

/// Env var the mediator reads at boot to pick up the passphrase.
/// Mirror of the wizard CLI's `--passphrase-file` rendered as an env
/// var for container deployments.
pub const PASSPHRASE_ENV: &str = "MEDIATOR_FILE_BACKEND_PASSPHRASE";

/// Optional indirection for env-shy deployments — the named file is
/// read once at backend open and trimmed of trailing whitespace. Read
/// errors are surfaced verbatim so misconfigured paths are obvious.
pub const PASSPHRASE_FILE_ENV: &str = "MEDIATOR_FILE_BACKEND_PASSPHRASE_FILE";

/// Argon2id parameters. Fixed (no auto-tuning) so an operator can
/// reproduce key derivation outside the mediator if they need to
/// recover entries by hand. Tweaking these in code is a breaking
/// change — bump `EncryptedStoreFile::version` if the parameters
/// change.
const KDF_MEMORY_KIB: u32 = 64 * 1024;
const KDF_ITERATIONS: u32 = 3;
const KDF_PARALLELISM: u32 = 4;
const KDF_KEY_BYTES: usize = 32;
const SALT_BYTES: usize = 16;
const NONCE_BYTES: usize = 12;
const KDF_ALGO_LABEL: &str = "argon2id";

/// Plaintext fed through the verifier seal. 32 zero bytes — small,
/// fixed, and known to anybody who needs to recover the file by hand.
const VERIFIER_PLAINTEXT: [u8; 32] = [0u8; 32];

pub(crate) fn open(url: BackendUrl) -> Result<DynSecretStore> {
    let BackendUrl::File { path, encrypted } = url else {
        return Err(SecretStoreError::Other(
            "internal error: encrypted file backend received non-file URL".into(),
        ));
    };
    if !encrypted {
        return Err(SecretStoreError::Other(
            "internal error: encrypted file backend received plaintext URL".into(),
        ));
    }
    let passphrase = load_passphrase()?;
    let store = EncryptedFileStore::open(PathBuf::from(path), passphrase)?;
    Ok(std::sync::Arc::new(store))
}

/// Read the passphrase from the standard env-var ladder. The order
/// matters: the file path wins so that a deployment can ship a
/// passphrase via tmpfs without leaking it into the process listing.
fn load_passphrase() -> Result<Zeroizing<String>> {
    if let Ok(path) = std::env::var(PASSPHRASE_FILE_ENV) {
        let raw = fs::read_to_string(&path).map_err(|e| SecretStoreError::Io {
            backend: BACKEND_LABEL,
            source: std::io::Error::new(
                e.kind(),
                format!("could not read passphrase from {path}: {e}"),
            ),
        })?;
        let trimmed = raw.trim().to_string();
        if trimmed.is_empty() {
            return Err(SecretStoreError::BackendUnavailable {
                backend: BACKEND_LABEL,
                reason: format!("{PASSPHRASE_FILE_ENV} pointed at {path}, but the file is empty"),
            });
        }
        return Ok(Zeroizing::new(trimmed));
    }
    if let Ok(raw) = std::env::var(PASSPHRASE_ENV) {
        let trimmed = raw.trim().to_string();
        if trimmed.is_empty() {
            return Err(SecretStoreError::BackendUnavailable {
                backend: BACKEND_LABEL,
                reason: format!("{PASSPHRASE_ENV} is set but empty"),
            });
        }
        return Ok(Zeroizing::new(trimmed));
    }
    Err(SecretStoreError::BackendUnavailable {
        backend: BACKEND_LABEL,
        reason: format!(
            "file://?encrypt=1 requires a passphrase. Set {PASSPHRASE_ENV} (raw) or \
             {PASSPHRASE_FILE_ENV} (path to a file containing the passphrase). The \
             mediator-setup wizard configures one for you when you choose the encrypted \
             file backend."
        ),
    })
}

/// Persistent on-disk representation. The version field gates future
/// migrations — bump it whenever the KDF params or AES variant changes
/// and write a migration shim that reads the old shape.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct EncryptedStoreFile {
    version: u32,
    kdf: KdfParams,
    verifier_nonce_b64: String,
    verifier_b64: String,
    #[serde(default)]
    entries: BTreeMap<String, SealedEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct KdfParams {
    algo: String,
    salt_b64: String,
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SealedEntry {
    nonce_b64: String,
    ciphertext_b64: String,
}

impl KdfParams {
    fn fresh() -> Result<(Self, [u8; SALT_BYTES])> {
        let mut salt = [0u8; SALT_BYTES];
        rand::rng()
            .try_fill_bytes(&mut salt)
            .map_err(|e| SecretStoreError::other(format!("salt generation failed: {e}")))?;
        Ok((
            Self {
                algo: KDF_ALGO_LABEL.into(),
                salt_b64: B64URL.encode(salt),
                memory_kib: KDF_MEMORY_KIB,
                iterations: KDF_ITERATIONS,
                parallelism: KDF_PARALLELISM,
            },
            salt,
        ))
    }

    fn salt(&self) -> Result<[u8; SALT_BYTES]> {
        if self.algo != KDF_ALGO_LABEL {
            return Err(SecretStoreError::BackendUnavailable {
                backend: BACKEND_LABEL,
                reason: format!(
                    "unsupported KDF algorithm '{}' on disk — only '{}' is implemented",
                    self.algo, KDF_ALGO_LABEL
                ),
            });
        }
        let raw = B64URL.decode(&self.salt_b64).map_err(|e| {
            SecretStoreError::other(format!("on-disk salt is not valid base64url: {e}"))
        })?;
        raw.try_into().map_err(|v: Vec<u8>| {
            SecretStoreError::other(format!(
                "on-disk salt is {} bytes; expected {}",
                v.len(),
                SALT_BYTES
            ))
        })
    }
}

fn derive_key(
    passphrase: &[u8],
    params: &KdfParams,
    salt: &[u8],
) -> Result<Zeroizing<[u8; KDF_KEY_BYTES]>> {
    let argon = Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(
            params.memory_kib,
            params.iterations,
            params.parallelism,
            Some(KDF_KEY_BYTES),
        )
        .map_err(|e| SecretStoreError::other(format!("invalid Argon2id params: {e}")))?,
    );
    let mut key = Zeroizing::new([0u8; KDF_KEY_BYTES]);
    argon
        .hash_password_into(passphrase, salt, key.as_mut_slice())
        .map_err(|e| SecretStoreError::other(format!("Argon2id derivation failed: {e}")))?;
    Ok(key)
}

fn random_nonce() -> Result<[u8; NONCE_BYTES]> {
    let mut n = [0u8; NONCE_BYTES];
    rand::rng()
        .try_fill_bytes(&mut n)
        .map_err(|e| SecretStoreError::other(format!("nonce generation failed: {e}")))?;
    Ok(n)
}

fn seal(
    key: &[u8; KDF_KEY_BYTES],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<(Vec<u8>, [u8; NONCE_BYTES])> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce_bytes = random_nonce()?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ct = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|e| SecretStoreError::other(format!("AES-GCM seal failed: {e}")))?;
    Ok((ct, nonce_bytes))
}

fn open_aead(
    key: &[u8; KDF_KEY_BYTES],
    nonce: &[u8; NONCE_BYTES],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|e| SecretStoreError::BackendUnavailable {
            backend: BACKEND_LABEL,
            reason: format!(
                "AES-GCM open failed: {e}. The on-disk file may have been written with a \
                 different passphrase, or the file has been tampered with."
            ),
        })
}

fn verifier_aad() -> &'static [u8] {
    b"mediator-file-encrypted-v1|verifier"
}

fn entry_aad(key: &str) -> Vec<u8> {
    let mut aad = Vec::with_capacity(64 + key.len());
    aad.extend_from_slice(b"mediator-file-encrypted-v1|entry|");
    aad.extend_from_slice(key.as_bytes());
    aad
}

pub struct EncryptedFileStore {
    path: PathBuf,
    /// Cached derived key; never written to disk.
    key: Zeroizing<[u8; KDF_KEY_BYTES]>,
    /// Cached on-disk state (without re-decrypting on every read).
    state: Mutex<EncryptedStoreFile>,
}

impl EncryptedFileStore {
    fn open(path: PathBuf, passphrase: Zeroizing<String>) -> Result<Self> {
        let state = match fs::read(&path) {
            Ok(bytes) if bytes.is_empty() => init_new(&path, &passphrase)?,
            Ok(bytes) => {
                let parsed: EncryptedStoreFile =
                    serde_json::from_slice(&bytes).map_err(|e| SecretStoreError::Io {
                        backend: BACKEND_LABEL,
                        source: std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            format!("failed to parse encrypted store {}: {e}", path.display()),
                        ),
                    })?;
                if parsed.version != 1 {
                    return Err(SecretStoreError::BackendUnavailable {
                        backend: BACKEND_LABEL,
                        reason: format!(
                            "encrypted store at {} uses unsupported version {}; this build only \
                             reads v1",
                            path.display(),
                            parsed.version
                        ),
                    });
                }
                parsed
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => init_new(&path, &passphrase)?,
            Err(e) => {
                return Err(SecretStoreError::Io {
                    backend: BACKEND_LABEL,
                    source: e,
                });
            }
        };

        // Derive once from the on-disk salt + parameters.
        let salt = state.kdf.salt()?;
        let key = derive_key(passphrase.as_bytes(), &state.kdf, &salt)?;

        // Verifier check: a wrong passphrase derives a different key,
        // which makes the AEAD seal-of-zeros fail to open. Catch it
        // here rather than on first `get`.
        let verifier_nonce_raw = B64URL.decode(&state.verifier_nonce_b64).map_err(|e| {
            SecretStoreError::other(format!("verifier nonce is not base64url: {e}"))
        })?;
        let verifier_ct = B64URL
            .decode(&state.verifier_b64)
            .map_err(|e| SecretStoreError::other(format!("verifier blob is not base64url: {e}")))?;
        let nonce_bytes: [u8; NONCE_BYTES] =
            verifier_nonce_raw.try_into().map_err(|v: Vec<u8>| {
                SecretStoreError::other(format!(
                    "verifier nonce is {} bytes; expected {}",
                    v.len(),
                    NONCE_BYTES
                ))
            })?;
        let opened = open_aead(&key, &nonce_bytes, &verifier_ct, verifier_aad())?;
        if opened != VERIFIER_PLAINTEXT {
            return Err(SecretStoreError::BackendUnavailable {
                backend: BACKEND_LABEL,
                reason: "verifier opened but its payload was unexpected — the on-disk file looks \
                         corrupt"
                    .into(),
            });
        }

        Ok(Self {
            path,
            key,
            state: Mutex::new(state),
        })
    }

    fn save_locked(&self, file: &EncryptedStoreFile) -> Result<()> {
        if let Some(parent) = self.path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent).map_err(|e| SecretStoreError::Io {
                backend: BACKEND_LABEL,
                source: e,
            })?;
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

fn init_new(path: &PathBuf, passphrase: &Zeroizing<String>) -> Result<EncryptedStoreFile> {
    let (kdf, salt) = KdfParams::fresh()?;
    let key = derive_key(passphrase.as_bytes(), &kdf, &salt)?;
    let (verifier_ct, verifier_nonce) = seal(&key, &VERIFIER_PLAINTEXT, verifier_aad())?;
    let state = EncryptedStoreFile {
        version: 1,
        kdf,
        verifier_nonce_b64: B64URL.encode(verifier_nonce),
        verifier_b64: B64URL.encode(verifier_ct),
        entries: BTreeMap::new(),
    };
    // Persist immediately so subsequent opens find the same salt.
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent).map_err(|e| SecretStoreError::Io {
            backend: BACKEND_LABEL,
            source: e,
        })?;
    }
    let body = serde_json::to_vec_pretty(&state)?;
    let mut opts = fs::OpenOptions::new();
    opts.create(true).write(true).truncate(true);
    #[cfg(unix)]
    opts.mode(0o600);
    let mut handle = opts.open(path).map_err(|e| SecretStoreError::Io {
        backend: BACKEND_LABEL,
        source: e,
    })?;
    handle.write_all(&body).map_err(|e| SecretStoreError::Io {
        backend: BACKEND_LABEL,
        source: e,
    })?;
    Ok(state)
}

#[async_trait]
impl SecretStore for EncryptedFileStore {
    fn backend(&self) -> &'static str {
        BACKEND_LABEL
    }

    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let guard = self
            .state
            .lock()
            .map_err(|e| SecretStoreError::other(format!("encrypted file store poisoned: {e}")))?;
        let Some(sealed) = guard.entries.get(key) else {
            return Ok(None);
        };
        let nonce_raw = B64URL
            .decode(&sealed.nonce_b64)
            .map_err(|e| SecretStoreError::other(format!("entry '{key}' nonce is not b64: {e}")))?;
        let nonce: [u8; NONCE_BYTES] = nonce_raw.try_into().map_err(|v: Vec<u8>| {
            SecretStoreError::other(format!(
                "entry '{key}' nonce is {} bytes; expected {}",
                v.len(),
                NONCE_BYTES
            ))
        })?;
        let ct = B64URL.decode(&sealed.ciphertext_b64).map_err(|e| {
            SecretStoreError::other(format!("entry '{key}' ciphertext is not b64: {e}"))
        })?;
        let pt = open_aead(&self.key, &nonce, &ct, &entry_aad(key))?;
        Ok(Some(pt))
    }

    async fn put(&self, key: &str, value: &[u8]) -> Result<()> {
        let mut guard = self
            .state
            .lock()
            .map_err(|e| SecretStoreError::other(format!("encrypted file store poisoned: {e}")))?;
        let (ct, nonce) = seal(&self.key, value, &entry_aad(key))?;
        guard.entries.insert(
            key.to_string(),
            SealedEntry {
                nonce_b64: B64URL.encode(nonce),
                ciphertext_b64: B64URL.encode(ct),
            },
        );
        let snapshot = guard.clone();
        // Hold the lock across the write to keep the in-memory state
        // consistent with the on-disk file.
        self.save_locked(&snapshot)?;
        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<()> {
        let mut guard = self
            .state
            .lock()
            .map_err(|e| SecretStoreError::other(format!("encrypted file store poisoned: {e}")))?;
        if guard.entries.remove(key).is_some() {
            let snapshot = guard.clone();
            self.save_locked(&snapshot)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, MutexGuard};
    use tempfile::TempDir;

    /// Serialise env-var manipulation across the test suite. Tokio's
    /// runtime would nest if we tried to combine `#[tokio::test]` with
    /// `block_on`, so all tests are plain `#[test]` and we own a
    /// per-call current-thread runtime for the async work.
    fn env_lock() -> MutexGuard<'static, ()> {
        static LOCK: Mutex<()> = Mutex::new(());
        LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn url_for(path: &std::path::Path) -> BackendUrl {
        BackendUrl::File {
            path: path.to_string_lossy().into(),
            encrypted: true,
        }
    }

    fn block_on<F: std::future::Future>(fut: F) -> F::Output {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(fut)
    }

    #[test]
    fn open_without_passphrase_errors_clearly() {
        let _g = env_lock();
        unsafe {
            std::env::remove_var(PASSPHRASE_ENV);
            std::env::remove_var(PASSPHRASE_FILE_ENV);
        }
        let tmp = TempDir::new().unwrap();
        match open(url_for(&tmp.path().join("s.json"))) {
            Ok(_) => panic!("missing passphrase must error"),
            Err(SecretStoreError::BackendUnavailable { reason, .. }) => {
                assert!(
                    reason.contains("passphrase"),
                    "expected message to mention passphrase, got: {reason}"
                );
            }
            Err(other) => panic!("wrong error variant: {other}"),
        }
    }

    #[test]
    fn roundtrip_encrypts_and_persists() {
        let _g = env_lock();
        unsafe {
            std::env::set_var(PASSPHRASE_ENV, "correct horse battery staple");
            std::env::remove_var(PASSPHRASE_FILE_ENV);
        }
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("s.json");
        let store = open(url_for(&path)).unwrap();
        block_on(async {
            store
                .put("mediator_admin_credential", b"secret-bytes")
                .await
                .unwrap();
            let got = store.get("mediator_admin_credential").await.unwrap();
            assert_eq!(got.as_deref(), Some(&b"secret-bytes"[..]));
        });

        // Re-open with the same passphrase: data survives.
        let store2 = open(url_for(&path)).unwrap();
        block_on(async {
            let got = store2.get("mediator_admin_credential").await.unwrap();
            assert_eq!(got.as_deref(), Some(&b"secret-bytes"[..]));
        });

        // The on-disk bytes must not contain the plaintext.
        let raw = fs::read_to_string(&path).unwrap();
        assert!(
            !raw.contains("secret-bytes"),
            "plaintext leaked into the store file"
        );

        unsafe {
            std::env::remove_var(PASSPHRASE_ENV);
        }
    }

    #[test]
    fn wrong_passphrase_is_rejected_at_open_time() {
        let _g = env_lock();
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("s.json");

        unsafe {
            std::env::set_var(PASSPHRASE_ENV, "right-one");
            std::env::remove_var(PASSPHRASE_FILE_ENV);
        }
        let store = open(url_for(&path)).unwrap();
        block_on(async { store.put("k", b"v").await.unwrap() });

        unsafe {
            std::env::set_var(PASSPHRASE_ENV, "WRONG-one");
        }
        match open(url_for(&path)) {
            Ok(_) => panic!("wrong passphrase must be rejected"),
            Err(SecretStoreError::BackendUnavailable { reason, .. }) => {
                assert!(
                    reason.contains("AES-GCM open failed"),
                    "expected AEAD failure, got: {reason}"
                );
            }
            Err(other) => panic!("wrong error variant: {other}"),
        }

        unsafe {
            std::env::remove_var(PASSPHRASE_ENV);
        }
    }

    #[test]
    fn each_put_uses_a_fresh_nonce() {
        let _g = env_lock();
        unsafe {
            std::env::set_var(PASSPHRASE_ENV, "nonce-test");
            std::env::remove_var(PASSPHRASE_FILE_ENV);
        }
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("s.json");
        let store = open(url_for(&path)).unwrap();
        block_on(async {
            store.put("k", b"same-value").await.unwrap();
            let raw1 = fs::read_to_string(&path).unwrap();
            store.put("k", b"same-value").await.unwrap();
            let raw2 = fs::read_to_string(&path).unwrap();
            assert_ne!(
                raw1, raw2,
                "rewriting the same key with the same plaintext must change the on-disk \
                 ciphertext (nonce reuse would be a critical AES-GCM bug)"
            );
        });
        unsafe {
            std::env::remove_var(PASSPHRASE_ENV);
        }
    }
}

//! Well-known secret keys + typed accessors.
//!
//! The mediator and its setup wizard read secrets by *name*, not by URL.
//! The names are fixed constants here; the [`MediatorSecrets`] helper
//! handles envelope wrapping, shape validation, and VTA cache integrity /
//! freshness.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use hmac::{Hmac, Mac};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tracing::{info, warn};

use crate::secrets::envelope::Envelope;
use crate::secrets::error::{Result, SecretStoreError};
use crate::secrets::store::{DynSecretStore, open_store};

type HmacSha256 = Hmac<Sha256>;

// All well-known key names use flat `[a-z0-9_]` identifiers. This is
// the common subset every backend accepts verbatim (GCP rejects `/`
// and `.`, Azure rejects `_` unless we substitute, and Vault KV v2
// paths happen to round-trip either). Sticking to the flat form means
// no per-backend encoding and no hidden invariants about which
// separators are safe — add new keys by following the same shape.

/// Credential the mediator uses to authenticate to its VTA.
pub const ADMIN_CREDENTIAL: &str = "mediator_admin_credential";
/// HMAC secret used by the mediator admin-API JWT.
pub const JWT_SECRET: &str = "mediator_jwt_secret";
/// Operating keys for the mediator's own DID — stored as a JSON array of
/// `affinidi_secrets_resolver::secrets::Secret` values. Populated in
/// self-hosted mode; VTA-managed deployments leave this absent and pull
/// keys from the VTA at startup.
pub const OPERATING_SECRETS: &str = "mediator_operating_secrets";
/// Reserved for a future per-key typed storage scheme. Not currently
/// written or read — `OPERATING_SECRETS` holds the full bundle today.
pub const OPERATING_SIGNING: &str = "mediator_operating_signing";
/// Reserved — see [`OPERATING_SIGNING`].
pub const OPERATING_KEY_AGREEMENT: &str = "mediator_operating_key_agreement";
/// Optional cached copy of the mediator's DID document (self-hosted mode).
pub const OPERATING_DID_DOCUMENT: &str = "mediator_operating_did_document";
/// Last successful `DidSecretsBundle` fetch from the VTA. Used as a
/// fall-back at boot when the VTA is unreachable.
pub const VTA_LAST_KNOWN_BUNDLE: &str = "mediator_vta_last_known_bundle";

/// Prefix for in-flight sealed-handoff HPKE recipient seeds written by
/// the non-interactive wizard in phase 1 and consumed in phase 2. The
/// full key is `<prefix><bundle_id_hex>`; bundle ids are lowercase hex
/// (16 bytes / 32 chars) so the result stays within the flat
/// `[a-z0-9_]` class every backend accepts.
pub const BOOTSTRAP_EPHEMERAL_SEED_PREFIX: &str = "mediator_bootstrap_ephemeral_seed_";

/// Index of in-flight bootstrap seeds with their creation timestamps.
/// Written on every `store_bootstrap_seed`, pruned on every
/// `delete_bootstrap_seed`, swept by `sweep_bootstrap_seeds`. Exists
/// because `SecretStore` has no `list_keys(prefix)` method — the index
/// is the enumeration substrate.
pub const BOOTSTRAP_SEED_INDEX: &str = "mediator_bootstrap_seed_index";

/// Prefix for `SecretStore::probe` sentinel keys. A UUID (simple form
/// — 32 hex chars, no hyphens) is appended to produce a per-probe
/// unique name that fits the flat character class.
pub const PROBE_SENTINEL_PREFIX: &str = "mediator_probe_";

/// HKDF salt for deriving the cache-HMAC key from the admin credential's
/// private key. Versioned so we can rotate the derivation in the future
/// without invalidating admin credentials.
const CACHE_HMAC_SALT: &[u8] = b"mediator-vta-cache-hmac-v1";

// ── Admin credential ────────────────────────────────────────────────────

const KIND_ADMIN_CREDENTIAL: &str = "admin-credential";

/// What the mediator needs to authenticate to its VTA on every startup.
///
/// `context` is the VTA context this mediator lives in (defaults to
/// `"mediator"` if missing). Holding it alongside the credential means
/// `mediator.toml` needs only a pointer at the secret backend — no
/// separate `[vta]` block to keep in sync.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminCredential {
    pub did: String,
    pub private_key_multibase: String,
    pub vta_did: String,
    pub vta_url: Option<String>,
    #[serde(default = "default_context")]
    pub context: String,
}

fn default_context() -> String {
    "mediator".into()
}

impl AdminCredential {
    fn validate(&self, key: &str) -> Result<()> {
        if !self.did.starts_with("did:") {
            return Err(SecretStoreError::InvalidShape {
                key: key.to_string(),
                reason: format!("admin credential DID '{}' is not a DID URI", self.did),
            });
        }
        if self.private_key_multibase.is_empty() {
            return Err(SecretStoreError::InvalidShape {
                key: key.to_string(),
                reason: "admin credential has empty private_key_multibase".into(),
            });
        }
        if !self.vta_did.starts_with("did:") {
            return Err(SecretStoreError::InvalidShape {
                key: key.to_string(),
                reason: format!(
                    "admin credential VTA DID '{}' is not a DID URI",
                    self.vta_did
                ),
            });
        }
        Ok(())
    }

    /// Derive the 32-byte HMAC key used to sign the VTA cache. Derivation
    /// is HKDF-SHA256 with a versioned salt; the admin private key
    /// multibase string is used as IKM.
    fn derive_cache_hmac_key(&self) -> [u8; 32] {
        let hkdf =
            hkdf::Hkdf::<Sha256>::new(Some(CACHE_HMAC_SALT), self.private_key_multibase.as_bytes());
        let mut okm = [0u8; 32];
        hkdf.expand(b"cache-hmac", &mut okm)
            .expect("HKDF expand into 32 bytes always succeeds");
        okm
    }
}

// ── VTA cache wrapper ──────────────────────────────────────────────────

const KIND_VTA_BUNDLE: &str = "vta-cached-bundle";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VtaCachedBundle {
    pub fetched_at: u64,
    pub ttl_secs: u64,
    /// HMAC-SHA256 of the canonical cache form (fetched_at || ttl_secs ||
    /// canonical(bundle)) keyed from the admin credential's private key.
    /// Hex-encoded.
    #[serde(default)]
    pub hmac: String,
    /// The bundle itself — opaque JSON to avoid coupling this crate to
    /// `vta_sdk::did_secrets::DidSecretsBundle` (which lives downstream).
    /// Consumers parse it with `serde_json::from_value`.
    pub bundle: serde_json::Value,
}

impl VtaCachedBundle {
    /// Canonical byte string that feeds the HMAC. Stable order + explicit
    /// field separators make it robust to JSON whitespace/key-order
    /// differences across backends.
    fn hmac_input(fetched_at: u64, ttl_secs: u64, bundle: &serde_json::Value) -> Vec<u8> {
        let mut out = Vec::with_capacity(64);
        out.extend_from_slice(b"mediator-vta-cache-v1|");
        out.extend_from_slice(&fetched_at.to_be_bytes());
        out.extend_from_slice(b"|");
        out.extend_from_slice(&ttl_secs.to_be_bytes());
        out.extend_from_slice(b"|");
        let canonical = serde_json::to_vec(bundle).unwrap_or_default();
        out.extend_from_slice(&canonical);
        out
    }

    fn compute_hmac(&self, key: &[u8; 32]) -> String {
        let mut mac =
            <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC-SHA256 accepts any 32-byte key");
        mac.update(&Self::hmac_input(
            self.fetched_at,
            self.ttl_secs,
            &self.bundle,
        ));
        hex::encode(mac.finalize().into_bytes())
    }

    fn verify_hmac(&self, key: &[u8; 32]) -> bool {
        let expected = self.compute_hmac(key);
        // hmac crate's `Mac::verify_slice` would be constant-time, but we
        // already have the hex — fall back to a simple constant-time
        // comparison of equal-length strings.
        constant_time_eq(self.hmac.as_bytes(), expected.as_bytes())
    }

    fn is_expired(&self, now_secs: u64) -> bool {
        self.ttl_secs > 0 && now_secs.saturating_sub(self.fetched_at) > self.ttl_secs
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut acc = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        acc |= x ^ y;
    }
    acc == 0
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ── Helper: typed wrapper over a DynSecretStore ─────────────────────────

/// Thin typed wrapper over a [`DynSecretStore`]. All mediator components
/// take one of these rather than reaching into a raw store, so shape
/// validation and envelope handling live in one place.
#[derive(Clone)]
pub struct MediatorSecrets {
    store: DynSecretStore,
}

impl MediatorSecrets {
    pub fn new(store: DynSecretStore) -> Self {
        Self { store }
    }

    /// Convenience: open a store from a URL and wrap it in one call.
    pub fn from_url(url: &str) -> Result<Self> {
        Ok(Self::new(open_store(url)?))
    }

    pub fn store(&self) -> &DynSecretStore {
        &self.store
    }

    pub fn store_arc(&self) -> Arc<dyn crate::secrets::store::SecretStore> {
        Arc::clone(&self.store)
    }

    pub async fn probe(&self) -> Result<()> {
        self.store.probe().await
    }

    // ── Generic envelope accessors ───────────────────────────────────
    //
    // Escape hatch for well-known keys that don't have a typed accessor
    // here yet (operating keys, DID docs, etc.). Callers still get schema
    // versioning + kind checking; they just supply the concrete type.

    pub async fn load_entry<T: DeserializeOwned>(
        &self,
        key: &str,
        kind: &'static str,
    ) -> Result<Option<T>> {
        let Some(bytes) = self.store.get(key).await? else {
            return Ok(None);
        };
        Envelope::<T>::open(&bytes, key, kind).map(Some)
    }

    pub async fn store_entry<T: Serialize>(
        &self,
        key: &str,
        kind: impl Into<String>,
        value: &T,
    ) -> Result<()> {
        let bytes = Envelope::new(kind, value).seal()?;
        self.store.put(key, &bytes).await
    }

    pub async fn delete_entry(&self, key: &str) -> Result<()> {
        self.store.delete(key).await
    }

    // ── Admin credential ─────────────────────────────────────────────

    pub async fn load_admin_credential(&self) -> Result<Option<AdminCredential>> {
        let Some(bytes) = self.store.get(ADMIN_CREDENTIAL).await? else {
            return Ok(None);
        };
        let cred: AdminCredential =
            Envelope::open(&bytes, ADMIN_CREDENTIAL, KIND_ADMIN_CREDENTIAL)?;
        cred.validate(ADMIN_CREDENTIAL)?;
        Ok(Some(cred))
    }

    pub async fn store_admin_credential(&self, cred: &AdminCredential) -> Result<()> {
        cred.validate(ADMIN_CREDENTIAL)?;
        let bytes = Envelope::new(KIND_ADMIN_CREDENTIAL, cred.clone()).seal()?;
        self.store.put(ADMIN_CREDENTIAL, &bytes).await
    }

    pub async fn delete_admin_credential(&self) -> Result<()> {
        self.store.delete(ADMIN_CREDENTIAL).await
    }

    // ── JWT secret ───────────────────────────────────────────────────

    pub async fn load_jwt_secret(&self) -> Result<Option<Vec<u8>>> {
        let Some(bytes) = self.store.get(JWT_SECRET).await? else {
            return Ok(None);
        };
        let raw: Vec<u8> = Envelope::open(&bytes, JWT_SECRET, "jwt-secret")?;
        if raw.is_empty() {
            return Err(SecretStoreError::InvalidShape {
                key: JWT_SECRET.into(),
                reason: "JWT secret is empty".into(),
            });
        }
        Ok(Some(raw))
    }

    pub async fn store_jwt_secret(&self, raw: &[u8]) -> Result<()> {
        if raw.is_empty() {
            return Err(SecretStoreError::InvalidShape {
                key: JWT_SECRET.into(),
                reason: "JWT secret must be non-empty".into(),
            });
        }
        let bytes = Envelope::new("jwt-secret", raw.to_vec()).seal()?;
        self.store.put(JWT_SECRET, &bytes).await
    }

    // ── VTA cache ────────────────────────────────────────────────────

    /// Load the most recent cached VTA bundle. Returns `None` when the
    /// cache is absent, expired, or its HMAC fails to verify — callers
    /// should treat all three as "no cache available". An HMAC failure
    /// or expiry is logged at `warn`.
    pub async fn load_vta_cached_bundle(&self) -> Result<Option<VtaCachedBundle>> {
        let Some(bytes) = self.store.get(VTA_LAST_KNOWN_BUNDLE).await? else {
            return Ok(None);
        };
        let cached: VtaCachedBundle =
            Envelope::open(&bytes, VTA_LAST_KNOWN_BUNDLE, KIND_VTA_BUNDLE)?;

        if cached.is_expired(now_unix()) {
            warn!(
                fetched_at = cached.fetched_at,
                ttl_secs = cached.ttl_secs,
                "VTA cache has exceeded its TTL; treating as absent",
            );
            return Ok(None);
        }

        // HMAC requires the admin credential; if it's missing we can't
        // verify, so we refuse to trust the cache. In practice the
        // mediator loads the admin credential first at boot anyway.
        let Some(admin) = self.load_admin_credential().await? else {
            warn!(
                "VTA cache present but no admin credential available to verify \
                 its HMAC; treating as absent"
            );
            return Ok(None);
        };
        let key = admin.derive_cache_hmac_key();
        if !cached.verify_hmac(&key) {
            warn!(
                "VTA cache HMAC verification failed — the entry was written by \
                 a different admin credential or has been tampered with; \
                 treating as absent"
            );
            return Ok(None);
        }
        Ok(Some(cached))
    }

    /// Write a fresh VTA bundle snapshot. The HMAC is computed against
    /// the current admin credential; if no admin credential is present,
    /// returns a clear error rather than storing an unverifiable cache.
    pub async fn store_vta_cached_bundle(
        &self,
        bundle: serde_json::Value,
        ttl_secs: u64,
    ) -> Result<()> {
        let admin = self.load_admin_credential().await?.ok_or_else(|| {
            SecretStoreError::Other(
                "cannot write VTA cache: no admin credential present (cache HMAC \
                 requires the admin key)"
                    .into(),
            )
        })?;
        let key = admin.derive_cache_hmac_key();
        let fetched_at = now_unix();
        let mut cached = VtaCachedBundle {
            fetched_at,
            ttl_secs,
            hmac: String::new(),
            bundle,
        };
        cached.hmac = cached.compute_hmac(&key);
        let bytes = Envelope::new(KIND_VTA_BUNDLE, cached).seal()?;
        self.store.put(VTA_LAST_KNOWN_BUNDLE, &bytes).await
    }

    // ── Bootstrap ephemeral seeds ────────────────────────────────────
    //
    // The non-interactive sealed-handoff flow mints an Ed25519 seed in
    // phase 1 (request emission) and uses it in phase 2 (bundle open).
    // The two phases run as separate process invocations, so the seed
    // must outlive phase 1 — it is written here (into the configured
    // backend) rather than to disk.
    //
    // Each seed carries an index entry under `BOOTSTRAP_SEED_INDEX`
    // recording `{bundle_id_hex, created_at}`. The index is the listing
    // substrate for `sweep_bootstrap_seeds`; without it we would need a
    // trait-level `list_keys(prefix)` method that not every backend can
    // cheaply provide.

    /// Persist a 32-byte Ed25519 seed keyed by `bundle_id_hex` and
    /// record the entry in the bootstrap sweep index. Subsequent
    /// invocations overwrite both the seed and its index entry,
    /// refreshing the timestamp.
    pub async fn store_bootstrap_seed(&self, bundle_id_hex: &str, seed: &[u8; 32]) -> Result<()> {
        validate_bundle_id_hex(bundle_id_hex)?;
        let key = bootstrap_seed_key(bundle_id_hex);
        let payload = EphemeralSeedPayload {
            seed_b64: B64URL.encode(seed),
        };
        let bytes = Envelope::new(KIND_EPHEMERAL_SEED, payload).seal()?;
        self.store.put(&key, &bytes).await?;
        self.upsert_seed_index(bundle_id_hex, now_unix()).await?;
        Ok(())
    }

    /// Fetch the 32-byte seed stored under `bundle_id_hex`. Returns
    /// `Ok(None)` when no seed is present (expected for the common
    /// "wrong bundle id" case).
    pub async fn load_bootstrap_seed(&self, bundle_id_hex: &str) -> Result<Option<[u8; 32]>> {
        validate_bundle_id_hex(bundle_id_hex)?;
        let key = bootstrap_seed_key(bundle_id_hex);
        let Some(bytes) = self.store.get(&key).await? else {
            return Ok(None);
        };
        let payload: EphemeralSeedPayload = Envelope::open(&bytes, &key, KIND_EPHEMERAL_SEED)?;
        let raw = B64URL.decode(payload.seed_b64.as_bytes()).map_err(|e| {
            SecretStoreError::InvalidShape {
                key: key.clone(),
                reason: format!("ephemeral seed is not valid base64url: {e}"),
            }
        })?;
        let seed: [u8; 32] =
            raw.try_into()
                .map_err(|v: Vec<u8>| SecretStoreError::InvalidShape {
                    key: key.clone(),
                    reason: format!(
                        "ephemeral seed must decode to exactly 32 bytes (got {})",
                        v.len()
                    ),
                })?;
        Ok(Some(seed))
    }

    /// Remove the seed for `bundle_id_hex` from both the backend and
    /// the sweep index. No-op if the seed isn't present; the index
    /// entry is removed regardless so a partial earlier write cannot
    /// leave it orphaned forever.
    pub async fn delete_bootstrap_seed(&self, bundle_id_hex: &str) -> Result<()> {
        validate_bundle_id_hex(bundle_id_hex)?;
        let key = bootstrap_seed_key(bundle_id_hex);
        self.store.delete(&key).await?;
        self.remove_from_seed_index(bundle_id_hex).await?;
        Ok(())
    }

    /// Snapshot of currently-tracked bootstrap seeds. Consumed by the
    /// wizard's "don't clobber an in-flight bundle" check in phase 1
    /// and by tooling that wants to surface pending bundle ids to the
    /// operator. Returns an empty index rather than `None` when the
    /// index entry is absent — simpler at call sites.
    pub async fn bootstrap_seed_index(&self) -> Result<BootstrapSeedIndex> {
        self.load_seed_index().await
    }

    /// Delete any bootstrap-seed entries older than `max_age`. Returns
    /// the bundle ids that were removed. Best-effort: if a per-entry
    /// delete fails the index entry stays (so a later sweep retries)
    /// but the overall call still returns `Ok` with whatever succeeded.
    pub async fn sweep_bootstrap_seeds(&self, max_age: Duration) -> Result<Vec<String>> {
        let index = self.load_seed_index().await?;
        if index.entries.is_empty() {
            return Ok(Vec::new());
        }
        let cutoff = now_unix().saturating_sub(max_age.as_secs());
        let mut swept = Vec::new();
        let mut surviving = Vec::with_capacity(index.entries.len());
        for entry in index.entries {
            if entry.created_at > cutoff {
                surviving.push(entry);
                continue;
            }
            let key = bootstrap_seed_key(&entry.bundle_id_hex);
            match self.store.delete(&key).await {
                Ok(()) => {
                    info!(
                        bundle_id = %entry.bundle_id_hex,
                        age_s = now_unix().saturating_sub(entry.created_at),
                        "swept stale bootstrap seed",
                    );
                    swept.push(entry.bundle_id_hex);
                }
                Err(e) => {
                    warn!(
                        bundle_id = %entry.bundle_id_hex,
                        error = %e,
                        "failed to delete stale bootstrap seed; will retry next sweep",
                    );
                    surviving.push(entry);
                }
            }
        }
        self.write_seed_index(&BootstrapSeedIndex { entries: surviving })
            .await?;
        Ok(swept)
    }

    async fn load_seed_index(&self) -> Result<BootstrapSeedIndex> {
        let Some(bytes) = self.store.get(BOOTSTRAP_SEED_INDEX).await? else {
            return Ok(BootstrapSeedIndex::default());
        };
        Envelope::open(&bytes, BOOTSTRAP_SEED_INDEX, KIND_SEED_INDEX)
    }

    async fn write_seed_index(&self, index: &BootstrapSeedIndex) -> Result<()> {
        if index.entries.is_empty() {
            // Don't leave an empty index lying around — delete it so
            // `load_seed_index` on the next call cheaply returns the
            // default without a round-trip.
            return self.store.delete(BOOTSTRAP_SEED_INDEX).await;
        }
        let bytes = Envelope::new(KIND_SEED_INDEX, index.clone()).seal()?;
        self.store.put(BOOTSTRAP_SEED_INDEX, &bytes).await
    }

    async fn upsert_seed_index(&self, bundle_id_hex: &str, created_at: u64) -> Result<()> {
        let mut index = self.load_seed_index().await?;
        if let Some(existing) = index
            .entries
            .iter_mut()
            .find(|e| e.bundle_id_hex == bundle_id_hex)
        {
            existing.created_at = created_at;
        } else {
            index.entries.push(BootstrapSeedIndexEntry {
                bundle_id_hex: bundle_id_hex.to_string(),
                created_at,
            });
        }
        self.write_seed_index(&index).await
    }

    async fn remove_from_seed_index(&self, bundle_id_hex: &str) -> Result<()> {
        let mut index = self.load_seed_index().await?;
        let before = index.entries.len();
        index.entries.retain(|e| e.bundle_id_hex != bundle_id_hex);
        if index.entries.len() == before {
            // Nothing to rewrite — save a round trip.
            return Ok(());
        }
        self.write_seed_index(&index).await
    }
}

// ── Bootstrap seed envelope + index types ───────────────────────────

const KIND_EPHEMERAL_SEED: &str = "ephemeral-seed";
const KIND_SEED_INDEX: &str = "bootstrap-seed-index";

/// Envelope-inner payload for a bootstrap seed. `seed_b64` carries the
/// raw 32-byte Ed25519 seed encoded as URL-safe base64 (no padding).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct EphemeralSeedPayload {
    seed_b64: String,
}

/// One entry in the bootstrap sweep index.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BootstrapSeedIndexEntry {
    pub bundle_id_hex: String,
    /// Unix seconds (UTC) when the entry was first written.
    pub created_at: u64,
}

/// Serialised form of the sweep index — a JSON array under
/// [`BOOTSTRAP_SEED_INDEX`].
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BootstrapSeedIndex {
    pub entries: Vec<BootstrapSeedIndexEntry>,
}

fn bootstrap_seed_key(bundle_id_hex: &str) -> String {
    format!("{BOOTSTRAP_EPHEMERAL_SEED_PREFIX}{bundle_id_hex}")
}

/// Defence-in-depth: bundle ids originate from the wizard's own
/// `hex_lower(&nonce)` so should always be 32 lowercase-hex chars, but
/// a typo in a future caller would otherwise produce a key that's
/// accepted by some backends and rejected by others. Reject eagerly
/// here so the failure mode is uniform.
fn validate_bundle_id_hex(bundle_id_hex: &str) -> Result<()> {
    if bundle_id_hex.len() != 32
        || !bundle_id_hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(SecretStoreError::InvalidShape {
            key: bootstrap_seed_key(bundle_id_hex),
            reason: "bundle id must be exactly 32 lowercase-hex characters".into(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secrets::backends::MemoryStore;

    fn helper() -> MediatorSecrets {
        let store: DynSecretStore = Arc::new(MemoryStore::new("memory"));
        MediatorSecrets::new(store)
    }

    fn sample_admin() -> AdminCredential {
        AdminCredential {
            did: "did:key:z6MkSAMPLE".into(),
            private_key_multibase: "z3u2SAMPLE".into(),
            vta_did: "did:webvh:vta.example.com".into(),
            vta_url: Some("https://vta.example.com".into()),
            context: "mediator".into(),
        }
    }

    #[tokio::test]
    async fn admin_credential_roundtrip() {
        let secrets = helper();
        assert!(secrets.load_admin_credential().await.unwrap().is_none());
        let cred = sample_admin();
        secrets.store_admin_credential(&cred).await.unwrap();
        let got = secrets.load_admin_credential().await.unwrap().unwrap();
        assert_eq!(got.did, cred.did);
    }

    #[tokio::test]
    async fn admin_credential_shape_validation_rejects_bogus_dids() {
        let secrets = helper();
        let bad = AdminCredential {
            did: "not-a-did".into(),
            private_key_multibase: "z...".into(),
            vta_did: "did:webvh:ok".into(),
            vta_url: None,
            context: "mediator".into(),
        };
        assert!(matches!(
            secrets.store_admin_credential(&bad).await,
            Err(SecretStoreError::InvalidShape { .. })
        ));
    }

    #[tokio::test]
    async fn jwt_secret_rejects_empty() {
        let secrets = helper();
        assert!(matches!(
            secrets.store_jwt_secret(&[]).await,
            Err(SecretStoreError::InvalidShape { .. })
        ));
    }

    #[tokio::test]
    async fn jwt_secret_roundtrip() {
        let secrets = helper();
        secrets.store_jwt_secret(&[1u8; 32]).await.unwrap();
        assert_eq!(
            secrets.load_jwt_secret().await.unwrap().unwrap(),
            vec![1u8; 32]
        );
    }

    #[tokio::test]
    async fn vta_cache_requires_admin_credential_to_write() {
        let secrets = helper();
        let bundle = serde_json::json!({"did": "did:x", "secrets": []});
        assert!(matches!(
            secrets.store_vta_cached_bundle(bundle, 3600).await,
            Err(SecretStoreError::Other(_))
        ));
    }

    #[tokio::test]
    async fn vta_cache_roundtrip_verifies_hmac() {
        let secrets = helper();
        secrets
            .store_admin_credential(&sample_admin())
            .await
            .unwrap();
        let bundle = serde_json::json!({"did": "did:webvh:x", "secrets": [1, 2, 3]});
        secrets
            .store_vta_cached_bundle(bundle.clone(), 3600)
            .await
            .unwrap();
        let got = secrets.load_vta_cached_bundle().await.unwrap().unwrap();
        assert_eq!(got.bundle, bundle);
        assert_eq!(got.ttl_secs, 3600);
        assert!(!got.hmac.is_empty());
    }

    #[tokio::test]
    async fn vta_cache_with_wrong_admin_key_is_treated_as_absent() {
        let secrets = helper();
        secrets
            .store_admin_credential(&sample_admin())
            .await
            .unwrap();
        secrets
            .store_vta_cached_bundle(serde_json::json!({"x": 1}), 3600)
            .await
            .unwrap();

        // Rotate to a different admin credential — the HMAC no longer
        // matches, so load should treat the cache as absent.
        let rotated = AdminCredential {
            private_key_multibase: "z-different-key".into(),
            ..sample_admin()
        };
        secrets.store_admin_credential(&rotated).await.unwrap();
        assert!(secrets.load_vta_cached_bundle().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn vta_cache_respects_ttl() {
        let secrets = helper();
        secrets
            .store_admin_credential(&sample_admin())
            .await
            .unwrap();
        let bundle = serde_json::json!({"x": 1});
        // Manually craft an expired entry: fetched_at in the distant
        // past, ttl one second.
        let admin = secrets.load_admin_credential().await.unwrap().unwrap();
        let key = admin.derive_cache_hmac_key();
        let mut cached = VtaCachedBundle {
            fetched_at: 1,
            ttl_secs: 1,
            hmac: String::new(),
            bundle,
        };
        cached.hmac = cached.compute_hmac(&key);
        let bytes = Envelope::new(KIND_VTA_BUNDLE, cached).seal().unwrap();
        secrets
            .store
            .put(VTA_LAST_KNOWN_BUNDLE, &bytes)
            .await
            .unwrap();
        assert!(secrets.load_vta_cached_bundle().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn vta_cache_tampered_hmac_is_rejected() {
        let secrets = helper();
        secrets
            .store_admin_credential(&sample_admin())
            .await
            .unwrap();
        secrets
            .store_vta_cached_bundle(serde_json::json!({"x": 1}), 3600)
            .await
            .unwrap();

        // Read the raw envelope, corrupt the `bundle` field, write back.
        let raw = secrets
            .store
            .get(VTA_LAST_KNOWN_BUNDLE)
            .await
            .unwrap()
            .unwrap();
        let mut env: Envelope<VtaCachedBundle> = serde_json::from_slice(&raw).unwrap();
        env.data.bundle = serde_json::json!({"x": 2});
        let tampered = serde_json::to_vec(&env).unwrap();
        secrets
            .store
            .put(VTA_LAST_KNOWN_BUNDLE, &tampered)
            .await
            .unwrap();

        // Load treats the cache as absent because HMAC no longer verifies.
        assert!(secrets.load_vta_cached_bundle().await.unwrap().is_none());
    }

    // ── Bootstrap seed helpers ───────────────────────────────────────

    fn valid_bundle_id() -> &'static str {
        // 32 lowercase hex chars — matches the wizard's
        // hex_lower(&nonce) output for a 16-byte bundle id.
        "0123456789abcdef0123456789abcdef"
    }

    #[tokio::test]
    async fn bootstrap_seed_roundtrip_returns_same_bytes() {
        let secrets = helper();
        let seed = [7u8; 32];
        secrets
            .store_bootstrap_seed(valid_bundle_id(), &seed)
            .await
            .unwrap();
        let got = secrets
            .load_bootstrap_seed(valid_bundle_id())
            .await
            .unwrap()
            .expect("seed must be present after store");
        assert_eq!(got, seed);
    }

    #[tokio::test]
    async fn bootstrap_seed_delete_then_load_returns_none() {
        let secrets = helper();
        let seed = [9u8; 32];
        secrets
            .store_bootstrap_seed(valid_bundle_id(), &seed)
            .await
            .unwrap();
        secrets
            .delete_bootstrap_seed(valid_bundle_id())
            .await
            .unwrap();
        let got = secrets
            .load_bootstrap_seed(valid_bundle_id())
            .await
            .unwrap();
        assert!(got.is_none());
    }

    #[tokio::test]
    async fn bootstrap_seed_rejects_invalid_bundle_id() {
        let secrets = helper();
        assert!(matches!(
            secrets.store_bootstrap_seed("too-short", &[0u8; 32]).await,
            Err(SecretStoreError::InvalidShape { .. })
        ));
        assert!(matches!(
            secrets
                .store_bootstrap_seed("UPPERCASEISNOTOKHEXXHEXXHEXXHEXXH", &[0u8; 32])
                .await,
            Err(SecretStoreError::InvalidShape { .. })
        ));
    }

    #[tokio::test]
    async fn sweep_removes_aged_entries_and_keeps_fresh_ones() {
        let secrets = helper();
        let aged_id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let fresh_id = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

        secrets
            .store_bootstrap_seed(aged_id, &[1u8; 32])
            .await
            .unwrap();
        secrets
            .store_bootstrap_seed(fresh_id, &[2u8; 32])
            .await
            .unwrap();

        // Manually backdate the aged entry's index timestamp — the
        // seed itself stays put; we are only backdating the sweep's
        // source of truth.
        let mut index = secrets.load_seed_index().await.unwrap();
        let now = now_unix();
        for entry in index.entries.iter_mut() {
            if entry.bundle_id_hex == aged_id {
                entry.created_at = now.saturating_sub(48 * 3600);
            } else if entry.bundle_id_hex == fresh_id {
                entry.created_at = now.saturating_sub(3600);
            }
        }
        secrets.write_seed_index(&index).await.unwrap();

        let swept = secrets
            .sweep_bootstrap_seeds(Duration::from_secs(24 * 3600))
            .await
            .unwrap();
        assert_eq!(swept, vec![aged_id.to_string()]);

        // Aged seed gone from both the backend and the index.
        assert!(
            secrets
                .load_bootstrap_seed(aged_id)
                .await
                .unwrap()
                .is_none()
        );
        let after = secrets.load_seed_index().await.unwrap();
        assert_eq!(after.entries.len(), 1);
        assert_eq!(after.entries[0].bundle_id_hex, fresh_id);

        // Fresh seed survives.
        assert_eq!(
            secrets.load_bootstrap_seed(fresh_id).await.unwrap(),
            Some([2u8; 32])
        );
    }

    #[tokio::test]
    async fn sweep_keeps_index_entry_when_backend_delete_fails() {
        use crate::secrets::store::SecretStore;
        use async_trait::async_trait;

        struct FailingDelete {
            inner: DynSecretStore,
            failing_key: String,
        }

        #[async_trait]
        impl SecretStore for FailingDelete {
            fn backend(&self) -> &'static str {
                "test-failing-delete"
            }
            async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
                self.inner.get(key).await
            }
            async fn put(&self, key: &str, value: &[u8]) -> Result<()> {
                self.inner.put(key, value).await
            }
            async fn delete(&self, key: &str) -> Result<()> {
                if key == self.failing_key {
                    return Err(SecretStoreError::Other("simulated delete failure".into()));
                }
                self.inner.delete(key).await
            }
        }

        let mem: DynSecretStore = Arc::new(MemoryStore::new("memory"));
        let aged_id = "cccccccccccccccccccccccccccccccc";
        let aged_key = bootstrap_seed_key(aged_id);
        // Seed through the plain memory store so state exists before
        // the failing wrapper takes over — easier to reason about.
        let plain = MediatorSecrets::new(mem.clone());
        plain
            .store_bootstrap_seed(aged_id, &[3u8; 32])
            .await
            .unwrap();
        let mut idx = plain.load_seed_index().await.unwrap();
        for entry in idx.entries.iter_mut() {
            entry.created_at = now_unix().saturating_sub(48 * 3600);
        }
        plain.write_seed_index(&idx).await.unwrap();

        let wrapping = Arc::new(FailingDelete {
            inner: mem,
            failing_key: aged_key.clone(),
        });
        let secrets = MediatorSecrets::new(wrapping);

        let swept = secrets
            .sweep_bootstrap_seeds(Duration::from_secs(24 * 3600))
            .await
            .unwrap();
        assert!(
            swept.is_empty(),
            "nothing should be reported as swept when the backend delete fails"
        );
        let retained = secrets.load_seed_index().await.unwrap();
        assert_eq!(
            retained.entries.len(),
            1,
            "failed sweep must leave the index entry for the next run"
        );
        assert_eq!(retained.entries[0].bundle_id_hex, aged_id);
    }

    #[tokio::test]
    async fn sweep_on_empty_index_is_noop() {
        let secrets = helper();
        let swept = secrets
            .sweep_bootstrap_seeds(Duration::from_secs(60))
            .await
            .unwrap();
        assert!(swept.is_empty());
    }

    #[tokio::test]
    async fn probe_still_succeeds_with_new_sentinel_prefix() {
        let store: DynSecretStore = Arc::new(MemoryStore::new("memory"));
        // The trait-default probe writes a key under `PROBE_SENTINEL_PREFIX`
        // and reads it back. A failing MemoryStore would fail here; a
        // passing round-trip confirms the new key shape still works.
        store.probe().await.unwrap();
    }

    #[tokio::test]
    async fn generic_entry_accessor_roundtrip() {
        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        struct Sample {
            value: u32,
        }

        let secrets = helper();
        let key = "mediator_test_sample";
        assert!(
            secrets
                .load_entry::<Sample>(key, "sample")
                .await
                .unwrap()
                .is_none()
        );

        secrets
            .store_entry(key, "sample", &Sample { value: 42 })
            .await
            .unwrap();
        let got = secrets
            .load_entry::<Sample>(key, "sample")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got, Sample { value: 42 });

        // Wrong kind → error.
        assert!(matches!(
            secrets.load_entry::<Sample>(key, "wrong-kind").await,
            Err(SecretStoreError::EnvelopeKindMismatch { .. })
        ));
    }
}

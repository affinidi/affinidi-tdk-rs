//! Well-known secret keys + typed accessors.
//!
//! The mediator and its setup wizard read secrets by *name*, not by URL.
//! The names are fixed constants here; the [`MediatorSecrets`] helper
//! handles envelope wrapping, shape validation, and VTA cache integrity /
//! freshness.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tracing::warn;

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

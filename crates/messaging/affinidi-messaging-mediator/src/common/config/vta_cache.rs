//! VTA secrets cache — thin adapter over [`MediatorSecrets`].
//!
//! The cache is a well-known entry in the unified secret backend
//! (`mediator/vta/last_known_bundle`), HMAC-signed with a key derived from
//! the admin credential, with a configurable TTL. All persistence logic
//! lives in `mediator-common`; this file just bridges the vta-sdk
//! [`SecretCache`] trait to `MediatorSecrets::{load,store}_vta_cached_bundle`.

use affinidi_messaging_mediator_common::MediatorSecrets;
use tracing::{debug, warn};
use vta_sdk::did_secrets::DidSecretsBundle;
use vta_sdk::integration::SecretCache;

/// The mediator's implementation of vta-sdk's [`SecretCache`] trait.
///
/// Constructed in `config/mod.rs` with the same `MediatorSecrets` used
/// elsewhere — VTA cache operations go through the same backend as every
/// other secret, with the same HMAC + TTL guarantees.
pub struct MediatorSecretCache {
    secrets: MediatorSecrets,
    ttl_secs: u64,
}

impl MediatorSecretCache {
    /// Construct the cache adapter. `ttl_secs` is parsed from
    /// `[secrets].cache_ttl` (humantime) — `0` means no expiry.
    pub fn new(secrets: MediatorSecrets, ttl_secs: u64) -> Self {
        Self { secrets, ttl_secs }
    }
}

impl SecretCache for MediatorSecretCache {
    async fn load(
        &self,
    ) -> Result<Option<DidSecretsBundle>, Box<dyn std::error::Error + Send + Sync>> {
        match self.secrets.load_vta_cached_bundle().await {
            Ok(Some(cached)) => match serde_json::from_value::<DidSecretsBundle>(cached.bundle) {
                Ok(bundle) => {
                    debug!(
                        fetched_at = cached.fetched_at,
                        ttl_secs = cached.ttl_secs,
                        "Loaded VTA bundle from cache"
                    );
                    Ok(Some(bundle))
                }
                Err(e) => {
                    warn!("Could not deserialise cached VTA bundle: {e}");
                    Ok(None)
                }
            },
            Ok(None) => {
                debug!("No cached VTA bundle present");
                Ok(None)
            }
            Err(e) => {
                warn!("Could not read VTA cache: {e}");
                Ok(None)
            }
        }
    }

    async fn store(
        &self,
        bundle: &DidSecretsBundle,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let value = serde_json::to_value(bundle)?;
        self.secrets
            .store_vta_cached_bundle(value, self.ttl_secs)
            .await
            .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })?;
        debug!("Cached fresh VTA bundle");
        Ok(())
    }
}

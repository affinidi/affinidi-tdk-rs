//! VTA boot-time integration with circular-dependency awareness.
//!
//! When the mediator's VTA configuration points at a VTA whose own
//! `DIDCommMessaging` service routes through this very mediator, the
//! default `integration::startup` flow can deadlock: the SDK auto-
//! resolves the VTA's mediator DID, attempts DIDComm to it, and waits
//! for *us* to start listening — which only happens after VTA bootstrap
//! completes. The eventual REST fallback works, but only after a
//! lengthy DIDComm timeout.
//!
//! This module wraps `integration::startup` with a pre-probe that
//! detects the circular topology and short-circuits to the cached
//! bundle (when available) or forces REST-only transport (when not).
//! Probe failures degrade silently to the default `Auto` behaviour —
//! a probe must never be the reason the mediator can't start.
//!
//! Companion: [`vta_refresh`](crate::tasks::vta_refresh) runs a periodic
//! background refresh post-listener so a circular bootstrap converges
//! to a fresh cache once the mediator is live.

use crate::common::config::vta_cache::MediatorSecretCache;
use affinidi_messaging_mediator_common::MediatorSecrets;
use tracing::{debug, info, warn};
use vta_sdk::did_secrets::DidSecretsBundle;
use vta_sdk::integration::{
    self, SecretCache, SecretSource, StartupResult, TransportPreference, VtaIntegrationError,
    VtaServiceConfig,
};

/// Outcome of a circular-dependency probe.
pub(crate) enum CircularProbe {
    /// The VTA's mediator DID matches our cached mediator DID — DIDComm
    /// to the VTA would route through us, deadlocking the boot.
    Circular { mediator_did: String },
    /// Confirmed not circular: VTA resolved to a different mediator (or
    /// no DIDComm mediator at all).
    NotCircular,
    /// Couldn't tell. No cached DID to compare, or VTA DID resolution
    /// failed. Caller should use the default boot path.
    Unknown,
}

/// Probe the configured VTA for a circular dependency on this mediator.
///
/// Reads the cached mediator DID (written on every successful boot)
/// and compares to the DID found in the VTA's `DIDCommMessaging`
/// service entries. The probe is best-effort — any failure returns
/// `Unknown` so the caller falls back to the default `Auto` flow.
pub(crate) async fn probe_circular_dependency(
    vta_did: &str,
    secrets: &MediatorSecrets,
) -> CircularProbe {
    let cached_did = match secrets.load_vta_cached_bundle().await {
        Ok(Some(cached)) => cached
            .bundle
            .get("did")
            .and_then(|v| v.as_str())
            .map(str::to_owned),
        Ok(None) => {
            debug!("Circular probe: no cached bundle, can't compare");
            return CircularProbe::Unknown;
        }
        Err(e) => {
            debug!("Circular probe: cache read failed: {e}");
            return CircularProbe::Unknown;
        }
    };

    let Some(cached_did) = cached_did else {
        debug!("Circular probe: cached bundle has no DID field");
        return CircularProbe::Unknown;
    };

    match vta_sdk::session::resolve_mediator_did(vta_did).await {
        Ok(Some(vta_mediator_did)) => {
            if vta_mediator_did == cached_did {
                CircularProbe::Circular {
                    mediator_did: cached_did,
                }
            } else {
                debug!(
                    cached_mediator = %cached_did,
                    vta_mediator = %vta_mediator_did,
                    "Circular probe: VTA's mediator differs from ours"
                );
                CircularProbe::NotCircular
            }
        }
        Ok(None) => {
            debug!("Circular probe: VTA DID has no DIDCommMessaging mediator entry");
            CircularProbe::NotCircular
        }
        Err(e) => {
            debug!("Circular probe: VTA DID resolution failed: {e}");
            CircularProbe::Unknown
        }
    }
}

/// Run VTA boot integration, transparently handling circular
/// topology.
///
/// Behavioural matrix:
///
/// | Probe result   | Cache         | Action                                                  |
/// |----------------|---------------|---------------------------------------------------------|
/// | Circular       | Fresh         | Skip live fetch — boot from cache, log circular notice  |
/// | Circular       | Stale/missing | Force `PreferRest`, run normal startup                  |
/// | NotCircular    | (any)         | Default `Auto` startup (current behaviour)              |
/// | Unknown        | (any)         | Default `Auto` startup (probe must never block boot)    |
pub(crate) async fn bootstrap_vta(
    service_config: &VtaServiceConfig,
    cache: &MediatorSecretCache,
    secrets: &MediatorSecrets,
) -> Result<StartupResult, VtaIntegrationError> {
    let vta_did = &service_config.auth.credential.vta_did;
    let probe = probe_circular_dependency(vta_did, secrets).await;

    match probe {
        CircularProbe::Circular { mediator_did } => {
            // Try the cached bundle first — when fresh, skip the VTA
            // round-trip entirely. The post-listener refresh task will
            // re-fetch once DIDComm to ourselves is reachable.
            match cache.load().await {
                Ok(Some(bundle)) => {
                    info!(
                        mediator_did = %mediator_did,
                        vta_did = %vta_did,
                        secrets = bundle.secrets.len(),
                        "VTA self-mediated: routing via this mediator. \
                         Skipping initial VTA contact and booting from cache. \
                         The periodic refresh task will reach the VTA over DIDComm \
                         once the listener is up."
                    );
                    return Ok(StartupResult {
                        did: bundle.did.clone(),
                        bundle,
                        source: SecretSource::Cache,
                        client: None,
                    });
                }
                Ok(None) => {
                    warn!(
                        mediator_did = %mediator_did,
                        "VTA self-mediated and no fresh cache available. \
                         Forcing REST transport for this boot — DIDComm to ourselves \
                         would deadlock. The periodic refresh task will warm the \
                         cache once the listener is up."
                    );
                }
                Err(e) => {
                    warn!(
                        mediator_did = %mediator_did,
                        error = %e,
                        "VTA self-mediated; cache read failed. Forcing REST transport."
                    );
                }
            }

            // No fresh cache — REST is the only escape. Force PreferRest
            // so the SDK skips the (futile) DIDComm tier entirely.
            let mut cfg = service_config.clone();
            cfg.context.transport_preference = TransportPreference::PreferRest;
            integration::startup(&cfg, cache).await
        }
        CircularProbe::NotCircular | CircularProbe::Unknown => {
            integration::startup(service_config, cache).await
        }
    }
}

/// Re-run [`bootstrap_vta`]'s live fetch path. Used by the periodic
/// refresh task. Always uses `Auto` transport — by the time this runs
/// the listener is up, so the circular case (DIDComm to ourselves)
/// resolves cleanly. Returns the refreshed bundle (or the unchanged
/// cached one) on success.
#[allow(dead_code)]
pub(crate) async fn refresh_vta(
    service_config: &VtaServiceConfig,
    cache: &MediatorSecretCache,
) -> Result<DidSecretsBundle, VtaIntegrationError> {
    let result = integration::startup(service_config, cache).await?;
    Ok(result.bundle)
}

//! Periodic VTA secrets refresh.
//!
//! Long-lived background task that re-runs the VTA boot flow on a
//! configurable cadence. Two roles:
//!
//! 1. **Cache freshness** — without this task, the cache is written
//!    once at boot and never refreshed; after one TTL window the next
//!    reboot has to round-trip the VTA to get fresh secrets. With it,
//!    the cache stays within TTL as long as the VTA is reachable, so
//!    a reboot during a temporary VTA outage still has a usable cache.
//!
//! 2. **Circular-bootstrap convergence** — when [`vta_bootstrap`]
//!    detected a VTA self-mediation loop and booted from cache without
//!    contacting the VTA, this task is the path that re-fetches once
//!    the listener is up (DIDComm to ourselves now resolves cleanly).
//!
//! Behaviour:
//! - Fire-and-forget: the mediator keeps serving even when refresh
//!   fails. The cache is the durable state; runtime keys persist
//!   across failures.
//! - Interval: `clamp(cache_ttl / 4, 5min, 1h)`. When `cache_ttl == 0`
//!   (no expiry), defaults to 6 hours.
//! - On failure: log a warning, wait the next interval. No exponential
//!   backoff — the cadence is already conservative.
//!
//! [`vta_bootstrap`]: crate::common::config::vta_bootstrap

use crate::common::config::vta_cache::MediatorSecretCache;
use crate::common::metrics::names;
use affinidi_messaging_mediator_common::MediatorSecrets;
use affinidi_secrets_resolver::{SecretsResolver, ThreadedSecretsResolver, secrets::Secret};
use std::{
    borrow::Cow,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};
use vta_sdk::integration::{
    self, FallbackReason, SecretSource, TransportPreference, VtaServiceConfig,
};

/// Default refresh interval when `cache_ttl == 0` (no-expiry policy).
/// Picks a sensible cadence so the cache still tracks the latest VTA
/// state without being aggressive.
const DEFAULT_INTERVAL_SECS: u64 = 6 * 3600;

/// Lower bound on refresh cadence — running more often than every 5
/// minutes is unnecessary churn for any reasonable TTL.
const MIN_INTERVAL_SECS: u64 = 5 * 60;

/// Upper bound — even with a multi-day TTL, we want to refresh at
/// least hourly so the cache never drifts more than an hour from the
/// VTA's current view.
const MAX_INTERVAL_SECS: u64 = 3600;

/// Compute the refresh interval from the configured cache TTL.
/// `cache_ttl_secs == 0` means no expiry; use [`DEFAULT_INTERVAL_SECS`].
pub(crate) fn interval_for_ttl(cache_ttl_secs: u64) -> Duration {
    if cache_ttl_secs == 0 {
        return Duration::from_secs(DEFAULT_INTERVAL_SECS);
    }
    let raw = cache_ttl_secs / 4;
    Duration::from_secs(raw.clamp(MIN_INTERVAL_SECS, MAX_INTERVAL_SECS))
}

/// Inputs the refresh task needs. Built at config-load time and held
/// in `Config` until [`server::serve_internal`] spawns the task.
/// Cloneable so [`Config`] can stay `Clone` (every inner field is
/// cheap to clone — the secrets resolver is `Arc`, the credential is
/// reference-counted strings, etc.).
#[derive(Clone)]
pub struct VtaRefresher {
    pub service_config: VtaServiceConfig,
    pub secrets: MediatorSecrets,
    pub cache_ttl_secs: u64,
    pub secrets_resolver: Arc<ThreadedSecretsResolver>,
    pub interval: Duration,
    /// This mediator's own DID. Compared against the VTA's advertised DIDComm
    /// mediator each tick to detect the self-mediated topology — see
    /// [`Self::tick_config`].
    pub mediator_did: String,
}

impl VtaRefresher {
    pub fn new(
        service_config: VtaServiceConfig,
        secrets: MediatorSecrets,
        cache_ttl_secs: u64,
        secrets_resolver: Arc<ThreadedSecretsResolver>,
    ) -> Self {
        let interval = interval_for_ttl(cache_ttl_secs);
        Self {
            service_config,
            secrets,
            cache_ttl_secs,
            secrets_resolver,
            interval,
            // Empty = "unknown", which disables the self-mediation probe and
            // leaves the configured transport untouched. Set it with
            // [`Self::with_mediator_did`]; `new` keeps its original signature so
            // this stays a non-breaking addition.
            mediator_did: String::new(),
        }
    }

    /// Tell the refresher this mediator's own DID, enabling the self-mediation
    /// check in [`Self::tick_config`]. Without it, refresh ticks use the
    /// configured transport preference unchanged.
    pub fn with_mediator_did(mut self, mediator_did: String) -> Self {
        self.mediator_did = mediator_did;
        self
    }

    /// Pick the transport for one refresh tick.
    ///
    /// [`bootstrap_vta`] detects the self-mediated topology at boot, but the
    /// refresh path used to re-run with `Auto` every time on the assumption that
    /// "by the time this runs the listener is up, so DIDComm to ourselves
    /// resolves cleanly". It does connect — and that is the problem. Each tick
    /// then opens a *client* websocket, authenticated as the mediator's admin
    /// DID, back into this same mediator. The mediator allows one socket per
    /// DID, so every such session competes for the admin DID's slot with any
    /// other session that outlived its owner; the result is an eviction duel
    /// that saturates the server with connect/close churn.
    ///
    /// So: when the VTA routes through us, refresh over REST. Nothing is lost —
    /// REST is the same authenticated fetch — and the mediator never dials
    /// itself. Probe failures fall back to the configured preference; a probe
    /// must never be the reason a refresh doesn't happen.
    ///
    /// [`bootstrap_vta`]: crate::common::config::vta_bootstrap::bootstrap_vta
    async fn tick_config(&self) -> Cow<'_, VtaServiceConfig> {
        if self.mediator_did.is_empty() {
            return Cow::Borrowed(&self.service_config);
        }

        let vta_did = &self.service_config.auth.credential.vta_did;
        match vta_sdk::session::resolve_mediator_did(vta_did).await {
            Ok(Some(vta_mediator)) if vta_mediator == self.mediator_did => {
                debug!(
                    mediator_did = %self.mediator_did,
                    "VTA is self-mediated; refreshing over REST to avoid dialling ourselves"
                );
                let mut config = self.service_config.clone();
                config.context.transport_preference = TransportPreference::PreferRest;
                Cow::Owned(config)
            }
            Ok(_) => Cow::Borrowed(&self.service_config),
            Err(e) => {
                debug!("Self-mediation probe failed ({e}); using the configured transport");
                Cow::Borrowed(&self.service_config)
            }
        }
    }

    /// Run the refresh loop until `shutdown_token` is cancelled.
    pub async fn run(self, shutdown_token: CancellationToken) {
        info!(
            interval_secs = self.interval.as_secs(),
            cache_ttl_secs = self.cache_ttl_secs,
            context = %self.service_config.context.id,
            "VTA refresh task started"
        );

        let cache = MediatorSecretCache::new(self.secrets.clone(), self.cache_ttl_secs);

        loop {
            tokio::select! {
                _ = shutdown_token.cancelled() => {
                    info!("VTA refresh task shutting down");
                    return;
                }
                _ = tokio::time::sleep(self.interval) => {}
            }

            let started = Instant::now();
            let tick_config = self.tick_config().await;
            let outcome = integration::startup_with_reason(&tick_config, &cache).await;
            metrics::histogram!(names::VTA_REFRESH_DURATION_SECONDS)
                .record(started.elapsed().as_secs_f64());

            match outcome {
                Ok((result, fallback)) => match result.source {
                    SecretSource::Vta => {
                        metrics::counter!(names::VTA_REFRESH_TOTAL, "result" => "vta").increment(1);
                        if let Ok(since_epoch) = SystemTime::now().duration_since(UNIX_EPOCH) {
                            metrics::gauge!(names::VTA_LAST_SUCCESS_TIMESTAMP_SECONDS)
                                .set(since_epoch.as_secs_f64());
                        }
                        debug!(
                            secrets = result.bundle.secrets.len(),
                            "VTA refresh OK — refreshed cache and runtime secrets"
                        );
                        if let Err(err) =
                            install_secrets(&result.bundle.secrets, &self.secrets_resolver).await
                        {
                            warn!("VTA refresh: failed to install secrets: {err}");
                        }
                    }
                    SecretSource::Cache => {
                        // Refresh fell back to cache. The cache write didn't
                        // re-fetch fresh material; runtime secrets are
                        // unchanged either way. But *why* it fell back
                        // decides the severity: an authorization denial is
                        // an operator problem that won't self-heal, whereas
                        // transient unreachability clears on the next tick.
                        match fallback {
                            Some(FallbackReason::AuthDenied) => {
                                metrics::counter!(names::VTA_REFRESH_TOTAL, "result" => "forbidden")
                                    .increment(1);
                                // Not "unreachable" — the VTA answered and
                                // *rejected* us. A fresh re-auth happens every
                                // cycle, so this is a standing authorization
                                // problem (e.g. an expired ACL entry for the
                                // mediator's operating DID), not a stale token.
                                warn!(
                                    context = %self.service_config.context.id,
                                    "VTA refused the mediator's credential (401/403); \
                                     running on cached secrets. Runtime keys are unchanged, \
                                     but this will keep failing until the mediator's \
                                     authorization is restored on the VTA (check the ACL / \
                                     access policy for its operating DID)."
                                );
                            }
                            _ => {
                                metrics::counter!(names::VTA_REFRESH_TOTAL, "result" => "cache")
                                    .increment(1);
                                // Unreachable / timeout — log at debug; operators
                                // only care if it persists, in which case the
                                // boot-time degraded-mode warning suffices.
                                debug!("VTA refresh: VTA unreachable, runtime secrets unchanged");
                            }
                        }
                    }
                },
                Err(err) => {
                    metrics::counter!(names::VTA_REFRESH_TOTAL, "result" => "error").increment(1);
                    warn!(
                        context = %self.service_config.context.id,
                        error = %err,
                        "VTA refresh failed; will retry on next interval"
                    );
                }
            }
        }
    }
}

/// Convert vta-sdk's secret records into resolver-shaped [`Secret`]s
/// and install them into the runtime resolver. Mirrors the boot path
/// in `common::config::security::SecurityConfigRaw::convert`.
async fn install_secrets(
    entries: &[vta_sdk::did_secrets::SecretEntry],
    secrets_resolver: &Arc<ThreadedSecretsResolver>,
) -> Result<(), String> {
    let mut converted = Vec::with_capacity(entries.len());
    for entry in entries {
        match Secret::from_multibase(&entry.private_key_multibase, Some(&entry.key_id)) {
            Ok(secret) => converted.push(secret),
            Err(e) => {
                return Err(format!(
                    "could not decode VTA operating secret '{}': {e}",
                    entry.key_id
                ));
            }
        }
    }
    secrets_resolver.insert_vec(&converted).await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interval_clamping() {
        // 30 days / 4 = 7.5 days → clamped to MAX (1h)
        assert_eq!(
            interval_for_ttl(30 * 86_400),
            Duration::from_secs(MAX_INTERVAL_SECS)
        );
        // 1 hour / 4 = 15 min — between bounds
        assert_eq!(interval_for_ttl(3600), Duration::from_secs(15 * 60));
        // 1 minute / 4 = 15s → clamped to MIN (5min)
        assert_eq!(interval_for_ttl(60), Duration::from_secs(MIN_INTERVAL_SECS));
        // 0 → DEFAULT
        assert_eq!(
            interval_for_ttl(0),
            Duration::from_secs(DEFAULT_INTERVAL_SECS)
        );
    }
}

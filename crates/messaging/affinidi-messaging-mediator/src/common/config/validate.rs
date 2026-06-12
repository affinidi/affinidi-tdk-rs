//! Boot-time configuration invariant validation.
//!
//! The individual checks (DID syntax, JWT expiry ordering, TLS file presence,
//! and the legal-but-suspicious-combo warnings) live in
//! [`affinidi_messaging_mediator_config::validate`] as pure, reusable helpers.
//! This module wires them against the resolved [`Config`]: it maps hard
//! failures to [`MediatorError::ConfigError`] (aborting startup) and logs the
//! warnings.

use affinidi_messaging_mediator_common::errors::MediatorError;
use affinidi_messaging_mediator_config::validate::{
    check_did_syntax, check_jwt_expiry, check_tls, warn_admin_is_mediator, warn_implicit_relay,
    warn_permissive_default_with_denylist_mode, warn_remote_admin_allowed,
};
use tracing::warn;

use super::Config;
use crate::common::error_codes;

/// Run all config invariants. Hard conflicts return an error (aborting
/// startup); suspicious-but-legal combinations are logged at WARN.
pub fn validate_config(config: &Config) -> Result<(), MediatorError> {
    let cfg_err =
        |msg: String| MediatorError::ConfigError(error_codes::CONFIG_ERROR, "NA".into(), msg);

    // ── Hard errors ──────────────────────────────────────────────────
    check_did_syntax("mediator_did", &config.mediator_did).map_err(cfg_err)?;
    check_did_syntax("admin_did", &config.admin_did).map_err(cfg_err)?;
    check_jwt_expiry(
        config.security.jwt_access_expiry,
        config.security.jwt_refresh_expiry,
    )
    .map_err(cfg_err)?;
    check_tls(
        config.security.use_ssl,
        config.security.ssl_certificate_file.as_deref(),
        config.security.ssl_key_file.as_deref(),
    )
    .map_err(cfg_err)?;

    // ── Warnings (legal, but usually a mistake) ──────────────────────
    if let Some(msg) = warn_admin_is_mediator(&config.admin_did, &config.mediator_did) {
        warn!("{msg}");
    }
    if let Some(msg) = warn_permissive_default_with_denylist_mode(
        &config.security.mediator_acl_mode,
        &config.security.global_acl_default,
    ) {
        warn!("{msg}");
    }
    if let Some(msg) = warn_remote_admin_allowed(config.security.block_remote_admin_msgs) {
        warn!("{msg}");
    }
    if let Some(msg) = warn_implicit_relay(
        config.security.enable_inter_mediator_relay,
        &config.security.global_acl_default,
    ) {
        warn!("{msg}");
    }

    Ok(())
}

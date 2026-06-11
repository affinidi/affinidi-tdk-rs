//! Boot-time configuration invariant validation.
//!
//! A single pass, run once when the file-based config is loaded, that
//! rejects hard misconfigurations early (with an actionable message)
//! and warns on legal-but-suspicious combinations. The goal is to fail
//! at startup rather than at the first request — or, for the warnings,
//! to flag a footgun the operator probably didn't intend.
//!
//! Each check is a small pure helper so it can be unit-tested in
//! isolation without building a full [`Config`]; [`validate_config`]
//! wires them together, mapping hard failures to
//! [`MediatorError::ConfigError`] and logging warnings.

use affinidi_messaging_mediator_common::errors::MediatorError;
use affinidi_messaging_mediator_common::types::acls::{AccessListModeType, MediatorACLSet};
use tracing::warn;

use super::Config;
use crate::common::authz::{Capability, grants};
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

/// Warn when this mediator relays inter-mediator forwards *implicitly* — i.e.
/// `global_acl_default` grants `SEND_FORWARDED` (so anonymous `/inbound`
/// forwards are accepted) but the operator hasn't set the explicit
/// `security.enable_inter_mediator_relay` flag.
///
/// This is the deprecation half of the explicit-relay rollout: today the
/// implicit configuration still works, but a future release will require the
/// flag, so we surface it loudly now. Setting the flag (or removing
/// `SEND_FORWARDED` from the global default) silences the warning.
pub(crate) fn warn_implicit_relay(
    enable_relay_flag: bool,
    global_acl_default: &MediatorACLSet,
) -> Option<String> {
    if !enable_relay_flag && grants(global_acl_default, Capability::SendForwarded) {
        return Some(
            "inter-mediator relay is enabled implicitly: global_acl_default grants SEND_FORWARDED \
             but security.enable_inter_mediator_relay is not set. This still works today, but a \
             future release will require the explicit flag — set \
             security.enable_inter_mediator_relay = \"true\" to opt in (or drop SEND_FORWARDED from \
             the global default if this mediator should not relay)."
                .to_string(),
        );
    }
    None
}

/// Warn when `admin_did` equals `mediator_did`: sharing one identity lets
/// the mediator's operating key authenticate as admin (privilege confusion)
/// and conflates two distinct trust roles.
///
/// This is a *warning*, not a hard error: the shipped example config (and
/// possibly real deployments) use a single DID for both, so rejecting it at
/// boot would break a currently-valid deployment — which the validation
/// contract forbids. The footgun is still surfaced loudly.
pub(crate) fn warn_admin_is_mediator(admin_did: &str, mediator_did: &str) -> Option<String> {
    if admin_did == mediator_did {
        return Some(format!(
            "admin_did equals mediator_did ('{admin_did}') — the admin role shares the mediator's \
             operating DID/key (privilege confusion). Use a separate DID for admin unless this is \
             intentional."
        ));
    }
    None
}

/// Minimal DID syntax check: `did:<method>:<method-specific-id>`, with a
/// non-empty lowercase-alphanumeric method and a non-empty id. Not a full
/// DID-spec parser — just enough to catch a fat-fingered or empty value
/// before it fails opaquely at resolve time.
pub(crate) fn check_did_syntax(field: &str, did: &str) -> Result<(), String> {
    let invalid = |why: &str| {
        Err(format!(
            "{field} is not a valid DID ('{did}'): {why}. Expected 'did:<method>:<id>'"
        ))
    };
    let Some(rest) = did.strip_prefix("did:") else {
        return invalid("must start with 'did:'");
    };
    let Some((method, id)) = rest.split_once(':') else {
        return invalid("missing the method or method-specific id");
    };
    if method.is_empty()
        || !method
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
    {
        return invalid("method must be non-empty lowercase alphanumeric");
    }
    if id.is_empty() {
        return invalid("method-specific id is empty");
    }
    Ok(())
}

/// JWT access tokens must expire before refresh tokens, otherwise refresh
/// is pointless and the access token outlives its refresh window.
pub(crate) fn check_jwt_expiry(access: u64, refresh: u64) -> Result<(), String> {
    if access >= refresh {
        return Err(format!(
            "jwt_access_expiry ({access}s) must be less than jwt_refresh_expiry ({refresh}s)"
        ));
    }
    Ok(())
}

/// When `use_ssl` is set, both the certificate and key must be configured
/// and readable. Catches the misconfiguration at load time rather than at
/// the TLS handshake. A no-op when `use_ssl` is false.
pub(crate) fn check_tls(
    use_ssl: bool,
    cert: Option<&str>,
    key: Option<&str>,
) -> Result<(), String> {
    if !use_ssl {
        return Ok(());
    }
    // Check both are configured before touching the filesystem, so a missing
    // path is reported as "not set" rather than masked by a readability error
    // on the other file.
    let cert = require_path("ssl_certificate_file", cert)?;
    let key = require_path("ssl_key_file", key)?;
    for (label, path) in [("ssl_certificate_file", cert), ("ssl_key_file", key)] {
        std::fs::File::open(path)
            .map_err(|e| format!("use_ssl is true but {label} ('{path}') is not readable: {e}"))?;
    }
    Ok(())
}

/// A configured TLS path must be present and non-empty.
fn require_path<'a>(label: &str, path: Option<&'a str>) -> Result<&'a str, String> {
    match path {
        None => Err(format!("use_ssl is true but {label} is not set")),
        Some("") => Err(format!("use_ssl is true but {label} is empty")),
        Some(p) => Ok(p),
    }
}

/// Warn when the mediator runs a permissive denylist mode
/// (`ExplicitDeny`) *and* hands new DIDs an `ALLOW_ALL` default — together
/// these mean every new account accepts everything from everyone, which is
/// rarely intended for a deployment that bothered to set a mode.
pub(crate) fn warn_permissive_default_with_denylist_mode(
    mode: &AccessListModeType,
    global_acl_default: &MediatorACLSet,
) -> Option<String> {
    let allow_all = MediatorACLSet::from_string_ruleset("ALLOW_ALL").ok()?;
    if *mode == AccessListModeType::ExplicitDeny
        && global_acl_default.to_u64() == allow_all.to_u64()
    {
        return Some(
            "mediator_acl_mode is ExplicitDeny (denylist) and global_acl_default grants ALLOW_ALL \
             — every new DID will accept messages from anyone. Confirm this is intended."
                .to_string(),
        );
    }
    None
}

/// Warn when remote (non-local) DIDs may send admin-protocol messages.
/// The secure posture restricts admin messaging to locally-registered
/// DIDs; disabling that widens the admin attack surface.
pub(crate) fn warn_remote_admin_allowed(block_remote_admin_msgs: bool) -> Option<String> {
    if !block_remote_admin_msgs {
        return Some(
            "block_remote_admin_msgs is false — remote DIDs may send admin-protocol messages. \
             This widens the admin attack surface; enable it unless you specifically need remote \
             administration."
                .to_string(),
        );
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn warns_only_when_admin_equals_mediator() {
        assert!(warn_admin_is_mediator("did:key:zAdmin", "did:peer:2.zMediator").is_none());
        let msg = warn_admin_is_mediator("did:peer:2.same", "did:peer:2.same")
            .expect("identical DIDs should warn");
        assert!(msg.contains("privilege confusion"), "msg was: {msg}");
    }

    #[test]
    fn implicit_relay_warning_fires_only_for_acl_without_flag() {
        let relay = MediatorACLSet::from_string_ruleset("ALLOW_ALL").unwrap();
        let no_relay =
            MediatorACLSet::from_string_ruleset("DENY_ALL,LOCAL,SEND_MESSAGES,RECEIVE_MESSAGES")
                .unwrap();

        // ACL grants SEND_FORWARDED but flag off → deprecation warning.
        let msg = warn_implicit_relay(false, &relay).expect("implicit relay should warn");
        assert!(
            msg.contains("enable_inter_mediator_relay"),
            "msg was: {msg}"
        );

        // Flag explicitly set → no warning (operator opted in).
        assert!(warn_implicit_relay(true, &relay).is_none());
        // ACL doesn't grant SEND_FORWARDED → not relaying, no warning.
        assert!(warn_implicit_relay(false, &no_relay).is_none());
        assert!(warn_implicit_relay(true, &no_relay).is_none());
    }

    #[test]
    fn did_syntax_accepts_real_methods() {
        for did in [
            "did:key:z6MkABC",
            "did:peer:2.Vz6Mk.Ez6LS.SeyJ",
            "did:web:mediator.example.com",
            "did:webvh:scid:mediator.example.com:path",
        ] {
            assert!(
                check_did_syntax("mediator_did", did).is_ok(),
                "{did} should be valid"
            );
        }
    }

    #[test]
    fn did_syntax_rejects_garbage() {
        for bad in [
            "",
            "notadid",
            "did:",
            "did:key",
            "did::id",
            "did:KEY:z6",
            "did:key:",
        ] {
            assert!(
                check_did_syntax("admin_did", bad).is_err(),
                "{bad:?} should be rejected"
            );
        }
    }

    #[test]
    fn jwt_expiry_ordering() {
        assert!(check_jwt_expiry(900, 86_400).is_ok());
        assert!(check_jwt_expiry(86_400, 86_400).is_err(), "equal must fail");
        assert!(
            check_jwt_expiry(90_000, 86_400).is_err(),
            "access > refresh must fail"
        );
    }

    #[test]
    fn tls_noop_when_disabled() {
        assert!(check_tls(false, None, None).is_ok());
    }

    #[test]
    fn tls_requires_both_files_when_enabled() {
        assert!(
            check_tls(true, None, Some("/x/key.pem"))
                .unwrap_err()
                .contains("ssl_certificate_file")
        );
        assert!(
            check_tls(true, Some("/x/cert.pem"), None)
                .unwrap_err()
                .contains("ssl_key_file")
        );
        assert!(
            check_tls(true, Some(""), Some("/x/key.pem"))
                .unwrap_err()
                .contains("empty")
        );
    }

    #[test]
    fn tls_checks_readability_when_enabled() {
        let cert = tempfile::NamedTempFile::new().expect("cert temp");
        let key = tempfile::NamedTempFile::new().expect("key temp");
        // Both present + readable → ok.
        assert!(
            check_tls(
                true,
                Some(cert.path().to_str().unwrap()),
                Some(key.path().to_str().unwrap()),
            )
            .is_ok()
        );
        // A non-existent path → unreadable error.
        let err = check_tls(
            true,
            Some(cert.path().to_str().unwrap()),
            Some("/definitely/not/here/key.pem"),
        )
        .unwrap_err();
        assert!(err.contains("not readable"), "msg was: {err}");
    }

    #[test]
    fn warns_only_on_denylist_mode_plus_allow_all_default() {
        let allow_all = MediatorACLSet::from_string_ruleset("ALLOW_ALL").unwrap();
        let default = MediatorACLSet::default();

        // The flagged combination.
        assert!(
            warn_permissive_default_with_denylist_mode(
                &AccessListModeType::ExplicitDeny,
                &allow_all
            )
            .is_some()
        );
        // Allowlist mode with ALLOW_ALL default → not flagged.
        assert!(
            warn_permissive_default_with_denylist_mode(
                &AccessListModeType::ExplicitAllow,
                &allow_all
            )
            .is_none()
        );
        // Denylist mode but restrictive default → not flagged.
        assert!(
            warn_permissive_default_with_denylist_mode(&AccessListModeType::ExplicitDeny, &default)
                .is_none()
        );
    }

    #[test]
    fn warns_only_when_remote_admin_unblocked() {
        assert!(warn_remote_admin_allowed(false).is_some());
        assert!(warn_remote_admin_allowed(true).is_none());
    }
}

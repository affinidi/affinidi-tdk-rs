//! The gate in front of the legacy admin surface — see
//! [`LegacyAdminProtocols`](crate::common::config::security::LegacyAdminProtocols).

use affinidi_messaging_mediator_common::errors::MediatorError;
use affinidi_messaging_mediator_common::types::problem_report::{
    ProblemReportScope, ProblemReportSorter,
};
use http::StatusCode;
use tracing::warn;

use crate::SharedData;
use crate::common::config::security::LegacyAdminProtocols;
use crate::common::session::Session;

/// Metric: uses of the legacy admin surface, by `surface`.
pub(crate) const LEGACY_ADMIN_REQUESTS_TOTAL: &str = "legacy_admin_requests_total";

/// Let a request to the legacy admin surface `surface` through, or refuse it,
/// per `security.legacy_admin_protocols`. `replacement` names what to use
/// instead; it goes in the log line and in the refusal.
pub(crate) fn admit(
    state: &SharedData,
    session: &Session,
    surface: &'static str,
    replacement: &'static str,
) -> Result<(), MediatorError> {
    let mode = state.config.security.legacy_admin_protocols;
    if mode != LegacyAdminProtocols::On {
        metrics::counter!(LEGACY_ADMIN_REQUESTS_TOTAL, "surface" => surface).increment(1);
    }
    match mode {
        LegacyAdminProtocols::On => Ok(()),
        LegacyAdminProtocols::Warn => {
            warn!(
                surface,
                did_hash = %session.did_hash,
                "legacy admin protocol used; it is deprecated and will be switched off: use {replacement}"
            );
            Ok(())
        }
        LegacyAdminProtocols::Off => Err(MediatorError::problem(
            12,
            &session.session_id,
            None,
            ProblemReportSorter::Error,
            ProblemReportScope::Protocol,
            "legacy_admin.disabled",
            "This mediator no longer serves {1}; use {2}",
            vec![surface.to_string(), replacement.to_string()],
            StatusCode::GONE,
        )),
    }
}

/// The DIDComm protocols that belong to the legacy admin surface.
pub(crate) const LEGACY_PROTOCOLS: &[&str] = &[
    "https://didcomm.org/mediator/1.0/admin-management",
    "https://didcomm.org/mediator/1.0/account-management",
    "https://didcomm.org/mediator/1.0/acl-management",
];

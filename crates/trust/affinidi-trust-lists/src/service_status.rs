/*!
 * Trust Service status values per ETSI TS 119 612.
 */

use serde::{Deserialize, Serialize};
use std::fmt;

/// The status of a trust service.
///
/// Determines whether the service is currently active and trusted.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ServiceStatus {
    /// Active, qualified, under supervision. This is the "trusted" state.
    Granted,
    /// No longer valid or trusted.
    Withdrawn,
    /// Recognised at national level (non-qualified services).
    RecognisedAtNationalLevel,
    /// Deprecated at national level.
    DeprecatedAtNationalLevel,
    /// Service is winding down (temporary state).
    SupervisionInCessation,
    /// Supervision has ceased.
    SupervisionCeased,
    /// Supervision was actively revoked.
    SupervisionRevoked,
    /// Legacy: accredited (pre-eIDAS).
    Accredited,
    /// Set by national law.
    SetByNationalLaw,
    /// Unknown status (stores the raw URI).
    Other(String),
}

impl ServiceStatus {
    /// The ETSI URI for this status.
    pub fn uri(&self) -> &str {
        match self {
            Self::Granted => "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted",
            Self::Withdrawn => "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/withdrawn",
            Self::RecognisedAtNationalLevel => {
                "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/recognisedatnationallevel"
            }
            Self::DeprecatedAtNationalLevel => {
                "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/deprecatedatnationallevel"
            }
            Self::SupervisionInCessation => {
                "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/supervisionincessation"
            }
            Self::SupervisionCeased => {
                "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/supervisionceased"
            }
            Self::SupervisionRevoked => {
                "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/supervisionrevoked"
            }
            Self::Accredited => "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/accredited",
            Self::SetByNationalLaw => {
                "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/setbynationallaw"
            }
            Self::Other(uri) => uri,
        }
    }

    /// Parse a status from its ETSI URI.
    pub fn from_uri(uri: &str) -> Self {
        // Normalize: trim trailing slash, lowercase compare
        let normalized = uri.trim_end_matches('/');
        match normalized {
            s if s.ends_with("/granted") => Self::Granted,
            s if s.ends_with("/withdrawn") => Self::Withdrawn,
            s if s.ends_with("/recognisedatnationallevel") => Self::RecognisedAtNationalLevel,
            s if s.ends_with("/deprecatedatnationallevel") => Self::DeprecatedAtNationalLevel,
            s if s.ends_with("/supervisionincessation") => Self::SupervisionInCessation,
            s if s.ends_with("/supervisionceased") => Self::SupervisionCeased,
            s if s.ends_with("/supervisionrevoked") => Self::SupervisionRevoked,
            s if s.ends_with("/accredited") => Self::Accredited,
            s if s.ends_with("/setbynationallaw") => Self::SetByNationalLaw,
            other => Self::Other(other.to_string()),
        }
    }

    /// Whether this status means the service is currently active and trusted.
    pub fn is_active(&self) -> bool {
        matches!(
            self,
            Self::Granted | Self::RecognisedAtNationalLevel | Self::Accredited
        )
    }

    /// Whether this status means the service has been terminated or revoked.
    pub fn is_terminated(&self) -> bool {
        matches!(
            self,
            Self::Withdrawn | Self::SupervisionCeased | Self::SupervisionRevoked
        )
    }
}

impl fmt::Display for ServiceStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Granted => write!(f, "Granted"),
            Self::Withdrawn => write!(f, "Withdrawn"),
            Self::RecognisedAtNationalLevel => write!(f, "Recognised at National Level"),
            Self::DeprecatedAtNationalLevel => write!(f, "Deprecated at National Level"),
            Self::SupervisionInCessation => write!(f, "Supervision in Cessation"),
            Self::SupervisionCeased => write!(f, "Supervision Ceased"),
            Self::SupervisionRevoked => write!(f, "Supervision Revoked"),
            Self::Accredited => write!(f, "Accredited"),
            Self::SetByNationalLaw => write!(f, "Set by National Law"),
            Self::Other(uri) => write!(f, "Other({uri})"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_uri_known() {
        assert_eq!(
            ServiceStatus::from_uri("http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted"),
            ServiceStatus::Granted
        );
        assert_eq!(
            ServiceStatus::from_uri("http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/withdrawn"),
            ServiceStatus::Withdrawn
        );
    }

    #[test]
    fn from_uri_unknown() {
        let s = ServiceStatus::from_uri("http://example.com/custom");
        assert_eq!(s, ServiceStatus::Other("http://example.com/custom".into()));
    }

    #[test]
    fn active_classification() {
        assert!(ServiceStatus::Granted.is_active());
        assert!(ServiceStatus::RecognisedAtNationalLevel.is_active());
        assert!(!ServiceStatus::Withdrawn.is_active());
        assert!(!ServiceStatus::SupervisionRevoked.is_active());
    }

    #[test]
    fn terminated_classification() {
        assert!(ServiceStatus::Withdrawn.is_terminated());
        assert!(ServiceStatus::SupervisionRevoked.is_terminated());
        assert!(!ServiceStatus::Granted.is_terminated());
    }

    #[test]
    fn display_formatting() {
        assert_eq!(ServiceStatus::Granted.to_string(), "Granted");
        assert_eq!(ServiceStatus::Withdrawn.to_string(), "Withdrawn");
    }
}

/*!
 * Trust Service type identifiers per ETSI TS 119 612.
 *
 * Covers all service types from eIDAS 1.0 and 2.0, including the
 * new entity types required by the Architecture Reference Framework.
 */

use serde::{Deserialize, Serialize};
use std::fmt;

/// Trust service type identifier per ETSI TS 119 612.
///
/// Each variant corresponds to a URI from the ETSI registry.
/// The eIDAS 2.0 types (PID, QEAA, etc.) are at the end.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ServiceType {
    // ── eIDAS 1.0 types ──
    /// Qualified certificate issuing CA.
    CaQc,
    /// Non-qualified certificate authority.
    CaPkc,
    /// Qualified OCSP responder.
    OcspQc,
    /// Non-qualified OCSP responder.
    Ocsp,
    /// Qualified CRL issuer.
    CrlQc,
    /// Non-qualified CRL issuer.
    Crl,
    /// Qualified timestamp authority.
    TsaQtst,
    /// Non-qualified timestamp service.
    Tsa,
    /// Qualified electronic delivery service.
    EdsQ,
    /// Qualified registered e-delivery service.
    EdsRemQ,
    /// Qualified preservation service.
    PsesQ,
    /// Qualified validation service for qualified electronic signatures/seals.
    QesValidationQ,
    /// National root CA for qualified certificates.
    NationalRootCaQc,
    /// Registration authority.
    Ra,
    /// Trusted List issuer.
    TlIssuer,

    // ── eIDAS 2.0 types ──
    /// Person Identification Data (PID) Provider.
    Pid,
    /// Legal Person PID Provider.
    LegalPid,
    /// Qualified Electronic Attestation of Attributes (QEAA) Provider.
    QEaa,
    /// Non-qualified EAA Provider.
    Eaa,
    /// Public Body EAA Provider.
    PubEaa,
    /// Natural Person Wallet Provider.
    WalletProvider,
    /// Legal Person Wallet Provider.
    LegalWalletProvider,
    /// Qualified Electronic Signature/Seal Remote Creation (QESRC) Provider.
    Qesrc,
    /// Access Certificate Authority.
    AccessCa,
    /// Registration Certificate Provider.
    RegistrationCa,

    /// Unknown or future service type (stores the raw URI).
    Other(String),
}

impl ServiceType {
    /// The ETSI URI for this service type.
    pub fn uri(&self) -> &str {
        match self {
            Self::CaQc => "http://uri.etsi.org/TrstSvc/Svctype/CA/QC",
            Self::CaPkc => "http://uri.etsi.org/TrstSvc/Svctype/CA/PKC",
            Self::OcspQc => "http://uri.etsi.org/TrstSvc/Svctype/Certstatus/OCSP/QC",
            Self::Ocsp => "http://uri.etsi.org/TrstSvc/Svctype/Certstatus/OCSP",
            Self::CrlQc => "http://uri.etsi.org/TrstSvc/Svctype/Certstatus/CRL/QC",
            Self::Crl => "http://uri.etsi.org/TrstSvc/Svctype/Certstatus/CRL",
            Self::TsaQtst => "http://uri.etsi.org/TrstSvc/Svctype/TSA/QTST",
            Self::Tsa => "http://uri.etsi.org/TrstSvc/Svctype/TSA",
            Self::EdsQ => "http://uri.etsi.org/TrstSvc/Svctype/EDS/Q",
            Self::EdsRemQ => "http://uri.etsi.org/TrstSvc/Svctype/EDS/REM/Q",
            Self::PsesQ => "http://uri.etsi.org/TrstSvc/Svctype/PSES/Q",
            Self::QesValidationQ => "http://uri.etsi.org/TrstSvc/Svctype/QESValidation/Q",
            Self::NationalRootCaQc => "http://uri.etsi.org/TrstSvc/Svctype/NationalRootCA-QC",
            Self::Ra => "http://uri.etsi.org/TrstSvc/Svctype/RA",
            Self::TlIssuer => "http://uri.etsi.org/TrstSvc/Svctype/TLIssuer",
            Self::Pid => "http://uri.etsi.org/TrstSvc/Svctype/PID",
            Self::LegalPid => "http://uri.etsi.org/TrstSvc/Svctype/LPID",
            Self::QEaa => "http://uri.etsi.org/TrstSvc/Svctype/EAA/Q",
            Self::Eaa => "http://uri.etsi.org/TrstSvc/Svctype/EAA",
            Self::PubEaa => "http://uri.etsi.org/TrstSvc/Svctype/EAA/Pub-EAA",
            Self::WalletProvider => "http://uri.etsi.org/TrstSvc/Svctype/WalletProvider",
            Self::LegalWalletProvider => "http://uri.etsi.org/TrstSvc/Svctype/LegalWalletProvider",
            Self::Qesrc => "http://uri.etsi.org/TrstSvc/Svctype/QESRC",
            Self::AccessCa => "http://uri.etsi.org/TrstSvc/Svctype/AccessCA",
            Self::RegistrationCa => "http://uri.etsi.org/TrstSvc/Svctype/RegistrationCA",
            Self::Other(uri) => uri,
        }
    }

    /// Parse a service type from its ETSI URI.
    pub fn from_uri(uri: &str) -> Self {
        match uri {
            "http://uri.etsi.org/TrstSvc/Svctype/CA/QC" => Self::CaQc,
            "http://uri.etsi.org/TrstSvc/Svctype/CA/PKC" => Self::CaPkc,
            "http://uri.etsi.org/TrstSvc/Svctype/Certstatus/OCSP/QC" => Self::OcspQc,
            "http://uri.etsi.org/TrstSvc/Svctype/Certstatus/OCSP" => Self::Ocsp,
            "http://uri.etsi.org/TrstSvc/Svctype/Certstatus/CRL/QC" => Self::CrlQc,
            "http://uri.etsi.org/TrstSvc/Svctype/Certstatus/CRL" => Self::Crl,
            "http://uri.etsi.org/TrstSvc/Svctype/TSA/QTST" => Self::TsaQtst,
            "http://uri.etsi.org/TrstSvc/Svctype/TSA" => Self::Tsa,
            "http://uri.etsi.org/TrstSvc/Svctype/EDS/Q" => Self::EdsQ,
            "http://uri.etsi.org/TrstSvc/Svctype/EDS/REM/Q" => Self::EdsRemQ,
            "http://uri.etsi.org/TrstSvc/Svctype/PSES/Q" => Self::PsesQ,
            "http://uri.etsi.org/TrstSvc/Svctype/QESValidation/Q" => Self::QesValidationQ,
            "http://uri.etsi.org/TrstSvc/Svctype/NationalRootCA-QC" => Self::NationalRootCaQc,
            "http://uri.etsi.org/TrstSvc/Svctype/RA" => Self::Ra,
            "http://uri.etsi.org/TrstSvc/Svctype/TLIssuer" => Self::TlIssuer,
            "http://uri.etsi.org/TrstSvc/Svctype/PID" => Self::Pid,
            "http://uri.etsi.org/TrstSvc/Svctype/LPID" => Self::LegalPid,
            "http://uri.etsi.org/TrstSvc/Svctype/EAA/Q" => Self::QEaa,
            "http://uri.etsi.org/TrstSvc/Svctype/EAA" => Self::Eaa,
            "http://uri.etsi.org/TrstSvc/Svctype/EAA/Pub-EAA" => Self::PubEaa,
            "http://uri.etsi.org/TrstSvc/Svctype/WalletProvider" => Self::WalletProvider,
            "http://uri.etsi.org/TrstSvc/Svctype/LegalWalletProvider" => Self::LegalWalletProvider,
            "http://uri.etsi.org/TrstSvc/Svctype/QESRC" => Self::Qesrc,
            "http://uri.etsi.org/TrstSvc/Svctype/AccessCA" => Self::AccessCa,
            "http://uri.etsi.org/TrstSvc/Svctype/RegistrationCA" => Self::RegistrationCa,
            other => Self::Other(other.to_string()),
        }
    }

    /// Whether this is an eIDAS 2.0 entity type.
    pub fn is_eidas2(&self) -> bool {
        matches!(
            self,
            Self::Pid
                | Self::LegalPid
                | Self::QEaa
                | Self::Eaa
                | Self::PubEaa
                | Self::WalletProvider
                | Self::LegalWalletProvider
                | Self::Qesrc
                | Self::AccessCa
                | Self::RegistrationCa
        )
    }

    /// Whether this service type represents a qualified trust service.
    pub fn is_qualified(&self) -> bool {
        matches!(
            self,
            Self::CaQc
                | Self::OcspQc
                | Self::CrlQc
                | Self::TsaQtst
                | Self::EdsQ
                | Self::EdsRemQ
                | Self::PsesQ
                | Self::QesValidationQ
                | Self::QEaa
                | Self::Qesrc
        )
    }
}

impl fmt::Display for ServiceType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.uri())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_uri_known_types() {
        assert_eq!(
            ServiceType::from_uri("http://uri.etsi.org/TrstSvc/Svctype/CA/QC"),
            ServiceType::CaQc
        );
        assert_eq!(
            ServiceType::from_uri("http://uri.etsi.org/TrstSvc/Svctype/PID"),
            ServiceType::Pid
        );
        assert_eq!(
            ServiceType::from_uri("http://uri.etsi.org/TrstSvc/Svctype/EAA/Q"),
            ServiceType::QEaa
        );
    }

    #[test]
    fn from_uri_unknown() {
        let st = ServiceType::from_uri("http://example.com/custom");
        assert_eq!(st, ServiceType::Other("http://example.com/custom".into()));
    }

    #[test]
    fn uri_roundtrip() {
        let types = vec![
            ServiceType::CaQc,
            ServiceType::Pid,
            ServiceType::QEaa,
            ServiceType::WalletProvider,
            ServiceType::AccessCa,
        ];
        for t in types {
            assert_eq!(ServiceType::from_uri(t.uri()), t);
        }
    }

    #[test]
    fn eidas2_classification() {
        assert!(ServiceType::Pid.is_eidas2());
        assert!(ServiceType::QEaa.is_eidas2());
        assert!(ServiceType::WalletProvider.is_eidas2());
        assert!(!ServiceType::CaQc.is_eidas2());
        assert!(!ServiceType::TsaQtst.is_eidas2());
    }

    #[test]
    fn qualified_classification() {
        assert!(ServiceType::CaQc.is_qualified());
        assert!(ServiceType::QEaa.is_qualified());
        assert!(!ServiceType::Eaa.is_qualified());
        assert!(!ServiceType::Pid.is_qualified());
    }
}

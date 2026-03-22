/*!
 * Core Trust List data types per ETSI TS 119 612.
 *
 * These types represent the parsed structure of an EU Trusted List,
 * independent of the serialization format (XML or JSON).
 */

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::service_status::ServiceStatus;
use crate::service_type::ServiceType;

/// The root Trust Service Status List structure.
///
/// Represents a parsed EU Trusted List (either the LoTL or a national TL).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustServiceStatusList {
    /// Metadata about the trust list.
    pub scheme_information: SchemeInformation,
    /// Trust Service Providers listed in this TL (empty for LoTL).
    pub trust_service_providers: Vec<TrustServiceProvider>,
}

/// The type of trust list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TslType {
    /// The EU List of Trusted Lists (maintained by the European Commission).
    ListOfTrustedLists,
    /// A national Trusted List (maintained by a Member State).
    EuGeneric,
    /// Unknown type.
    Other(String),
}

impl TslType {
    /// Parse from the ETSI URI.
    pub fn from_uri(uri: &str) -> Self {
        if uri.contains("EUlistofthelists") {
            Self::ListOfTrustedLists
        } else if uri.contains("EUgeneric") {
            Self::EuGeneric
        } else {
            Self::Other(uri.to_string())
        }
    }
}

/// Metadata about the trust list (SchemeInformation in ETSI TS 119 612).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchemeInformation {
    /// TSL version (currently 5).
    pub tsl_version: u32,
    /// Sequence number (incremented on each update).
    pub tsl_sequence_number: u32,
    /// Type of this trust list (LoTL or national).
    pub tsl_type: TslType,
    /// Name of the scheme operator (multi-language).
    pub scheme_operator_name: String,
    /// Territory/country code (e.g., "EU", "DE", "AT").
    pub scheme_territory: String,
    /// When this version was issued.
    pub list_issue_date_time: DateTime<Utc>,
    /// When the next update is expected.
    pub next_update: Option<DateTime<Utc>>,
    /// Pointers to other trust lists (used by LoTL to point to national TLs).
    pub pointers_to_other_tsl: Vec<OtherTslPointer>,
}

/// A pointer from the LoTL to a national Trusted List.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OtherTslPointer {
    /// URL of the target trust list.
    pub tsl_location: String,
    /// Territory of the target trust list (e.g., "AT", "DE").
    pub scheme_territory: String,
    /// Signing certificates for the target TL (DER-encoded X.509).
    pub signing_certificates: Vec<Vec<u8>>,
    /// Operator name for the target TL.
    pub scheme_operator_name: Option<String>,
}

/// A Trust Service Provider (organization providing trust services).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustServiceProvider {
    /// Name of the TSP (primary language).
    pub name: String,
    /// Trade name (optional).
    pub trade_name: Option<String>,
    /// Country/territory where the TSP operates.
    pub territory: String,
    /// Information URI(s) for the TSP.
    pub information_uris: Vec<String>,
    /// Individual trust services offered by this TSP.
    pub services: Vec<ServiceInformation>,
}

/// Information about an individual trust service (the trust anchor).
///
/// This is the core entry that maps a digital identity (certificate/key)
/// to a service type and status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceInformation {
    /// The type of trust service (CA/QC, PID, QEAA, etc.).
    pub service_type: ServiceType,
    /// Human-readable service name.
    pub service_name: String,
    /// The digital identity of the service (certificate, key, or DID).
    pub digital_identity: ServiceDigitalIdentity,
    /// Current status of the service.
    pub service_status: ServiceStatus,
    /// When the current status took effect.
    pub status_starting_time: DateTime<Utc>,
    /// Historical status transitions.
    pub history: Vec<ServiceHistoryEntry>,
}

/// The digital identity (trust anchor) of a trust service.
///
/// A service can be identified by multiple forms; in practice,
/// X.509 certificates are the most common.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ServiceDigitalIdentity {
    /// An X.509 certificate (DER-encoded bytes).
    X509Certificate(Vec<u8>),
    /// An X.509 Subject Key Identifier.
    X509Ski(Vec<u8>),
    /// An X.509 subject distinguished name.
    X509SubjectName(String),
    /// A raw public key (algorithm-specific encoding).
    PublicKey(Vec<u8>),
    /// A DID URI (for EBSI/DLT-based trust anchors).
    Did(String),
}

impl ServiceDigitalIdentity {
    /// Compute the SHA-256 fingerprint of the identity for indexing.
    pub fn fingerprint(&self) -> Vec<u8> {
        use sha2::{Digest, Sha256};
        match self {
            Self::X509Certificate(cert) => Sha256::digest(cert).to_vec(),
            Self::X509Ski(ski) => Sha256::digest(ski).to_vec(),
            Self::X509SubjectName(name) => Sha256::digest(name.as_bytes()).to_vec(),
            Self::PublicKey(key) => Sha256::digest(key).to_vec(),
            Self::Did(did) => Sha256::digest(did.as_bytes()).to_vec(),
        }
    }
}

/// A historical status transition for a service.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceHistoryEntry {
    /// The service type at this point in history.
    pub service_type: ServiceType,
    /// The status at this point.
    pub service_status: ServiceStatus,
    /// When this status took effect.
    pub status_starting_time: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tsl_type_from_uri() {
        assert_eq!(
            TslType::from_uri("http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUlistofthelists"),
            TslType::ListOfTrustedLists
        );
        assert_eq!(
            TslType::from_uri("http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUgeneric"),
            TslType::EuGeneric
        );
    }

    #[test]
    fn digital_identity_fingerprint() {
        let id1 = ServiceDigitalIdentity::X509Certificate(vec![1, 2, 3]);
        let id2 = ServiceDigitalIdentity::X509Certificate(vec![1, 2, 3]);
        let id3 = ServiceDigitalIdentity::X509Certificate(vec![4, 5, 6]);

        assert_eq!(id1.fingerprint(), id2.fingerprint());
        assert_ne!(id1.fingerprint(), id3.fingerprint());
    }

    #[test]
    fn did_identity_fingerprint() {
        let id = ServiceDigitalIdentity::Did("did:ebsi:abc123".into());
        assert_eq!(id.fingerprint().len(), 32); // SHA-256
    }
}

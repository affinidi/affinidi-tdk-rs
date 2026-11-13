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

impl TrustServiceStatusList {
    /// Whether the list is current at `now`: issued no later than `now` and
    /// with a `NextUpdate` that has not passed. A list without `NextUpdate`
    /// is a closed list (ETSI TS 119 612 clause 5.3.15) and is never current.
    pub fn is_current_at(&self, now: DateTime<Utc>) -> bool {
        let info = &self.scheme_information;
        info.list_issue_date_time <= now && info.next_update.is_some_and(|next| now <= next)
    }
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
    /// When this version was issued (`ListIssueDateTime`).
    pub list_issue_date_time: DateTime<Utc>,
    /// When the next update is due (`NextUpdate`); the list is stale after
    /// it. `None` for a closed list, whose `NextUpdate` is empty.
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
    /// The digital identities of the service (certificates, SKIs, subject
    /// names, keys, or DIDs). A service may list several, e.g. a renewed
    /// certificate beside the one it replaces; each is indexed.
    pub digital_identities: Vec<ServiceDigitalIdentity>,
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
    /// Whether the identity carries no value (zero bytes or an empty
    /// string). An empty identity identifies nothing: the registry does not
    /// index it and a lookup with one finds nothing.
    pub fn is_empty(&self) -> bool {
        match self {
            Self::X509Certificate(bytes) | Self::X509Ski(bytes) | Self::PublicKey(bytes) => {
                bytes.is_empty()
            }
            Self::X509SubjectName(text) | Self::Did(text) => text.is_empty(),
        }
    }

    /// Compute the SHA-256 fingerprint of the identity for indexing.
    ///
    /// The identity kind is hashed ahead of its value, so equal bytes or
    /// strings of different kinds (a subject name and a DID, an SKI and a
    /// public key) have different fingerprints.
    pub fn fingerprint(&self) -> Vec<u8> {
        use sha2::{Digest, Sha256};
        let (kind, value): (&[u8], &[u8]) = match self {
            Self::X509Certificate(cert) => (b"x509-certificate", cert),
            Self::X509Ski(ski) => (b"x509-ski", ski),
            Self::X509SubjectName(name) => (b"x509-subject-name", name.as_bytes()),
            Self::PublicKey(key) => (b"public-key", key),
            Self::Did(did) => (b"did", did.as_bytes()),
        };
        let mut hasher = Sha256::new();
        hasher.update(kind);
        hasher.update([0u8]);
        hasher.update(value);
        hasher.finalize().to_vec()
    }
}

impl ServiceInformation {
    /// The service's status at `now`: the current status once its
    /// `status_starting_time` has passed, otherwise the latest history entry
    /// that had started by `now`. `None` when no recorded status covers `now`.
    pub fn status_at(&self, now: DateTime<Utc>) -> Option<&ServiceStatus> {
        if self.status_starting_time <= now {
            return Some(&self.service_status);
        }
        self.history
            .iter()
            .filter(|entry| entry.status_starting_time <= now)
            .max_by_key(|entry| entry.status_starting_time)
            .map(|entry| &entry.service_status)
    }
}

/// A historical status transition for a service (`ServiceHistoryInstance`).
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
    fn fingerprints_are_separated_by_identity_kind() {
        let name = ServiceDigitalIdentity::X509SubjectName("CN=Issuer, C=DE".into());
        let did = ServiceDigitalIdentity::Did("CN=Issuer, C=DE".into());
        assert_ne!(name.fingerprint(), did.fingerprint());

        let ski = ServiceDigitalIdentity::X509Ski(vec![1, 2, 3]);
        let key = ServiceDigitalIdentity::PublicKey(vec![1, 2, 3]);
        let cert = ServiceDigitalIdentity::X509Certificate(vec![1, 2, 3]);
        assert_ne!(ski.fingerprint(), key.fingerprint());
        assert_ne!(ski.fingerprint(), cert.fingerprint());
        assert_ne!(key.fingerprint(), cert.fingerprint());
    }

    #[test]
    fn status_at_uses_history_before_the_current_status_started() {
        let at = |text: &str| {
            DateTime::parse_from_rfc3339(text)
                .unwrap()
                .with_timezone(&Utc)
        };
        let service = ServiceInformation {
            service_type: ServiceType::CaQc,
            service_name: "CA".into(),
            digital_identities: Vec::new(),
            service_status: ServiceStatus::Withdrawn,
            status_starting_time: at("2026-06-01T00:00:00Z"),
            history: vec![ServiceHistoryEntry {
                service_type: ServiceType::CaQc,
                service_status: ServiceStatus::Granted,
                status_starting_time: at("2025-01-01T00:00:00Z"),
            }],
        };
        assert_eq!(service.status_at(at("2024-01-01T00:00:00Z")), None);
        assert!(
            service
                .status_at(at("2026-01-01T00:00:00Z"))
                .unwrap()
                .is_active()
        );
        assert!(
            !service
                .status_at(at("2026-07-01T00:00:00Z"))
                .unwrap()
                .is_active()
        );
    }

    #[test]
    fn did_identity_fingerprint() {
        let id = ServiceDigitalIdentity::Did("did:ebsi:abc123".into());
        assert_eq!(id.fingerprint().len(), 32); // SHA-256
    }
}

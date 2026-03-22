/*!
 * Trust List Registry — in-memory indexed store for fast lookups.
 *
 * The registry provides O(1) lookup of trust anchors by their
 * digital identity fingerprint (SHA-256 of certificate, key, or DID).
 */

use std::collections::HashMap;

use chrono::Utc;

use crate::service_status::ServiceStatus;
use crate::service_type::ServiceType;
use crate::types::{ServiceDigitalIdentity, ServiceInformation, TrustServiceStatusList};

/// A trust anchor entry in the registry.
///
/// Contains the service information plus the provider and territory context.
#[derive(Debug, Clone)]
pub struct TrustAnchorEntry {
    /// The provider that offers this service.
    pub provider_name: String,
    /// The territory/country of the provider.
    pub territory: String,
    /// The service information (type, status, identity).
    pub service: ServiceInformation,
}

/// The result of looking up a trust anchor.
#[derive(Debug)]
pub enum LookupResult {
    /// The issuer is trusted (active service found).
    Trusted(TrustAnchorEntry),
    /// The issuer was found but the service is not active.
    Inactive {
        entry: TrustAnchorEntry,
        reason: String,
    },
    /// The issuer was not found in any trust list.
    NotFound,
}

impl LookupResult {
    /// Whether the lookup found a trusted (active) entry.
    pub fn is_trusted(&self) -> bool {
        matches!(self, Self::Trusted(_))
    }
}

/// An in-memory indexed registry of trust anchors.
///
/// Supports O(1) lookup by SHA-256 fingerprint of the digital identity.
#[derive(Debug, Default)]
pub struct TrustListRegistry {
    /// Index: fingerprint -> list of matching entries.
    /// Multiple entries can share the same fingerprint (e.g., same cert
    /// in different trust lists or different service types).
    index: HashMap<Vec<u8>, Vec<TrustAnchorEntry>>,
    /// All loaded trust list territories.
    territories: Vec<String>,
    /// Total number of entries.
    entry_count: usize,
}

impl TrustListRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Load a Trust Service Status List into the registry.
    ///
    /// Indexes all services by their digital identity fingerprint.
    pub fn load_trust_list(&mut self, tl: &TrustServiceStatusList) {
        let territory = tl.scheme_information.scheme_territory.clone();
        if !self.territories.contains(&territory) {
            self.territories.push(territory.clone());
        }

        for provider in &tl.trust_service_providers {
            for service in &provider.services {
                let fingerprint = service.digital_identity.fingerprint();
                let entry = TrustAnchorEntry {
                    provider_name: provider.name.clone(),
                    territory: provider.territory.clone(),
                    service: service.clone(),
                };

                self.index.entry(fingerprint).or_default().push(entry);
                self.entry_count += 1;
            }
        }
    }

    /// Add a single provider with one service directly.
    ///
    /// Convenience method for building registries programmatically.
    pub fn add_provider(
        &mut self,
        territory: &str,
        provider_name: &str,
        service_type: ServiceType,
        status: ServiceStatus,
        certificate_der: &[u8],
    ) {
        let identity = ServiceDigitalIdentity::X509Certificate(certificate_der.to_vec());
        let fingerprint = identity.fingerprint();

        let service = ServiceInformation {
            service_type,
            service_name: provider_name.to_string(),
            digital_identity: identity,
            service_status: status,
            status_starting_time: Utc::now(),
            history: Vec::new(),
        };

        let entry = TrustAnchorEntry {
            provider_name: provider_name.to_string(),
            territory: territory.to_string(),
            service,
        };

        if !self.territories.contains(&territory.to_string()) {
            self.territories.push(territory.to_string());
        }

        self.index.entry(fingerprint).or_default().push(entry);
        self.entry_count += 1;
    }

    /// Look up a trust anchor by X.509 certificate (DER bytes).
    ///
    /// Returns the first matching active entry, or an inactive entry if found.
    pub fn lookup_by_certificate(&self, certificate_der: &[u8]) -> LookupResult {
        let identity = ServiceDigitalIdentity::X509Certificate(certificate_der.to_vec());
        self.lookup_by_identity(&identity)
    }

    /// Look up a trust anchor by Subject Key Identifier.
    pub fn lookup_by_ski(&self, ski: &[u8]) -> LookupResult {
        let identity = ServiceDigitalIdentity::X509Ski(ski.to_vec());
        self.lookup_by_identity(&identity)
    }

    /// Look up a trust anchor by raw public key bytes.
    pub fn lookup_by_public_key(&self, key: &[u8]) -> LookupResult {
        let identity = ServiceDigitalIdentity::PublicKey(key.to_vec());
        self.lookup_by_identity(&identity)
    }

    /// Look up a trust anchor by DID URI.
    pub fn lookup_by_did(&self, did: &str) -> LookupResult {
        let identity = ServiceDigitalIdentity::Did(did.to_string());
        self.lookup_by_identity(&identity)
    }

    /// Generic lookup by any digital identity type.
    pub fn lookup_by_identity(&self, identity: &ServiceDigitalIdentity) -> LookupResult {
        let fingerprint = identity.fingerprint();

        match self.index.get(&fingerprint) {
            None => LookupResult::NotFound,
            Some(entries) => {
                // Prefer active entries
                for entry in entries {
                    if entry.service.service_status.is_active() {
                        return LookupResult::Trusted(entry.clone());
                    }
                }
                // Return inactive entry with reason
                if let Some(entry) = entries.first() {
                    LookupResult::Inactive {
                        entry: entry.clone(),
                        reason: format!("Service status: {}", entry.service.service_status),
                    }
                } else {
                    LookupResult::NotFound
                }
            }
        }
    }

    /// Find all services of a given type across all trust lists.
    pub fn find_by_service_type(&self, service_type: &ServiceType) -> Vec<&TrustAnchorEntry> {
        self.index
            .values()
            .flatten()
            .filter(|e| &e.service.service_type == service_type)
            .collect()
    }

    /// Find all services in a given territory.
    pub fn find_by_territory(&self, territory: &str) -> Vec<&TrustAnchorEntry> {
        self.index
            .values()
            .flatten()
            .filter(|e| e.territory == territory)
            .collect()
    }

    /// Find all active PID providers.
    pub fn pid_providers(&self) -> Vec<&TrustAnchorEntry> {
        self.find_by_service_type(&ServiceType::Pid)
            .into_iter()
            .filter(|e| e.service.service_status.is_active())
            .collect()
    }

    /// Find all active wallet providers.
    pub fn wallet_providers(&self) -> Vec<&TrustAnchorEntry> {
        self.find_by_service_type(&ServiceType::WalletProvider)
            .into_iter()
            .filter(|e| e.service.service_status.is_active())
            .collect()
    }

    /// Find all active QEAA providers.
    pub fn qeaa_providers(&self) -> Vec<&TrustAnchorEntry> {
        self.find_by_service_type(&ServiceType::QEaa)
            .into_iter()
            .filter(|e| e.service.service_status.is_active())
            .collect()
    }

    /// Get the total number of entries in the registry.
    pub fn entry_count(&self) -> usize {
        self.entry_count
    }

    /// Get the list of loaded territories.
    pub fn territories(&self) -> &[String] {
        &self.territories
    }

    /// Check whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.entry_count == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_cert(id: u8) -> Vec<u8> {
        vec![0x30, 0x82, id, 0x00] // Fake DER prefix + unique byte
    }

    #[test]
    fn add_and_lookup_provider() {
        let mut registry = TrustListRegistry::new();

        let cert = sample_cert(1);
        registry.add_provider(
            "DE",
            "German PID Office",
            ServiceType::Pid,
            ServiceStatus::Granted,
            &cert,
        );

        let result = registry.lookup_by_certificate(&cert);
        assert!(result.is_trusted());

        if let LookupResult::Trusted(entry) = result {
            assert_eq!(entry.provider_name, "German PID Office");
            assert_eq!(entry.territory, "DE");
            assert_eq!(entry.service.service_type, ServiceType::Pid);
        }
    }

    #[test]
    fn lookup_not_found() {
        let registry = TrustListRegistry::new();
        let result = registry.lookup_by_certificate(&[0xFF, 0xFE]);
        assert!(!result.is_trusted());
        assert!(matches!(result, LookupResult::NotFound));
    }

    #[test]
    fn lookup_inactive_service() {
        let mut registry = TrustListRegistry::new();

        let cert = sample_cert(2);
        registry.add_provider(
            "FR",
            "French CA",
            ServiceType::CaQc,
            ServiceStatus::Withdrawn,
            &cert,
        );

        let result = registry.lookup_by_certificate(&cert);
        assert!(!result.is_trusted());
        assert!(matches!(result, LookupResult::Inactive { .. }));
    }

    #[test]
    fn find_by_service_type() {
        let mut registry = TrustListRegistry::new();

        registry.add_provider(
            "DE",
            "DE PID",
            ServiceType::Pid,
            ServiceStatus::Granted,
            &sample_cert(1),
        );
        registry.add_provider(
            "AT",
            "AT PID",
            ServiceType::Pid,
            ServiceStatus::Granted,
            &sample_cert(2),
        );
        registry.add_provider(
            "DE",
            "DE CA",
            ServiceType::CaQc,
            ServiceStatus::Granted,
            &sample_cert(3),
        );

        let pids = registry.find_by_service_type(&ServiceType::Pid);
        assert_eq!(pids.len(), 2);

        let cas = registry.find_by_service_type(&ServiceType::CaQc);
        assert_eq!(cas.len(), 1);
    }

    #[test]
    fn find_by_territory() {
        let mut registry = TrustListRegistry::new();

        registry.add_provider(
            "DE",
            "DE PID",
            ServiceType::Pid,
            ServiceStatus::Granted,
            &sample_cert(1),
        );
        registry.add_provider(
            "DE",
            "DE CA",
            ServiceType::CaQc,
            ServiceStatus::Granted,
            &sample_cert(2),
        );
        registry.add_provider(
            "AT",
            "AT PID",
            ServiceType::Pid,
            ServiceStatus::Granted,
            &sample_cert(3),
        );

        let de = registry.find_by_territory("DE");
        assert_eq!(de.len(), 2);

        let at = registry.find_by_territory("AT");
        assert_eq!(at.len(), 1);
    }

    #[test]
    fn pid_providers_filter() {
        let mut registry = TrustListRegistry::new();

        registry.add_provider(
            "DE",
            "Active PID",
            ServiceType::Pid,
            ServiceStatus::Granted,
            &sample_cert(1),
        );
        registry.add_provider(
            "FR",
            "Withdrawn PID",
            ServiceType::Pid,
            ServiceStatus::Withdrawn,
            &sample_cert(2),
        );

        let active = registry.pid_providers();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].provider_name, "Active PID");
    }

    #[test]
    fn lookup_by_did() {
        let mut registry = TrustListRegistry::new();

        let did_identity = ServiceDigitalIdentity::Did("did:ebsi:abc123".into());
        let fingerprint = did_identity.fingerprint();

        let service = ServiceInformation {
            service_type: ServiceType::QEaa,
            service_name: "EBSI QEAA".into(),
            digital_identity: did_identity,
            service_status: ServiceStatus::Granted,
            status_starting_time: Utc::now(),
            history: Vec::new(),
        };

        let entry = TrustAnchorEntry {
            provider_name: "EBSI Provider".into(),
            territory: "EU".into(),
            service,
        };

        registry.index.entry(fingerprint).or_default().push(entry);
        registry.entry_count += 1;

        let result = registry.lookup_by_did("did:ebsi:abc123");
        assert!(result.is_trusted());
    }

    #[test]
    fn entry_count_and_territories() {
        let mut registry = TrustListRegistry::new();
        assert!(registry.is_empty());
        assert_eq!(registry.entry_count(), 0);

        registry.add_provider(
            "DE",
            "TSP1",
            ServiceType::Pid,
            ServiceStatus::Granted,
            &sample_cert(1),
        );
        registry.add_provider(
            "AT",
            "TSP2",
            ServiceType::CaQc,
            ServiceStatus::Granted,
            &sample_cert(2),
        );

        assert_eq!(registry.entry_count(), 2);
        assert!(!registry.is_empty());
        assert_eq!(registry.territories().len(), 2);
        assert!(registry.territories().contains(&"DE".to_string()));
        assert!(registry.territories().contains(&"AT".to_string()));
    }

    #[test]
    fn load_trust_list() {
        use crate::types::*;

        let tl = TrustServiceStatusList {
            scheme_information: SchemeInformation {
                tsl_version: 5,
                tsl_sequence_number: 1,
                tsl_type: TslType::EuGeneric,
                scheme_operator_name: "Test Authority".into(),
                scheme_territory: "DE".into(),
                list_issue_date_time: Utc::now(),
                next_update: None,
                pointers_to_other_tsl: Vec::new(),
            },
            trust_service_providers: vec![TrustServiceProvider {
                name: "German PID Provider".into(),
                trade_name: None,
                territory: "DE".into(),
                information_uris: vec!["https://example.de".into()],
                services: vec![ServiceInformation {
                    service_type: ServiceType::Pid,
                    service_name: "PID Issuance".into(),
                    digital_identity: ServiceDigitalIdentity::X509Certificate(sample_cert(10)),
                    service_status: ServiceStatus::Granted,
                    status_starting_time: Utc::now(),
                    history: Vec::new(),
                }],
            }],
        };

        let mut registry = TrustListRegistry::new();
        registry.load_trust_list(&tl);

        assert_eq!(registry.entry_count(), 1);
        assert!(
            registry
                .lookup_by_certificate(&sample_cert(10))
                .is_trusted()
        );
    }
}

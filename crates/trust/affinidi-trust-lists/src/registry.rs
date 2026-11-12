/*!
 * Trust List Registry — in-memory indexed store for fast lookups.
 *
 * The registry provides O(1) lookup of trust anchors by their
 * digital identity fingerprint (SHA-256 of certificate, key, or DID).
 */

use std::collections::HashMap;

use chrono::{DateTime, Utc};

use crate::error::{Result, TrustListError};
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
    /// `NextUpdate` of the trust list this entry was loaded from. Past it the
    /// entry is no longer trusted. `None` for entries added directly with
    /// [`TrustListRegistry::add_provider`], which do not expire.
    pub list_next_update: Option<DateTime<Utc>>,
}

impl TrustAnchorEntry {
    /// Why the entry cannot be trusted at `now`, or `Ok` if it can: its list
    /// must not be past `NextUpdate`, and its status at `now` (see
    /// [`ServiceInformation::status_at`]) must be active.
    pub fn usable_at(&self, now: DateTime<Utc>) -> std::result::Result<(), String> {
        if let Some(next_update) = self.list_next_update
            && now > next_update
        {
            return Err(format!(
                "trust list for {} passed its next update {next_update}",
                self.territory
            ));
        }
        match self.service.status_at(now) {
            Some(status) if status.is_active() => Ok(()),
            Some(status) => Err(format!("Service status: {status}")),
            None => Err(format!("no service status recorded at {now}")),
        }
    }
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
    /// Indexes every service under each of its digital identities. Refuses a
    /// list that is not current at `now` (see
    /// [`TrustServiceStatusList::is_current_at`]), so a stale or closed list
    /// cannot supply anchors.
    ///
    /// This does not authenticate the list: its XAdES signature is not
    /// verified by this crate. Load only lists whose bytes the caller has
    /// authenticated (see [`crate::xml::UnverifiedTrustList`]).
    pub fn load_trust_list(
        &mut self,
        tl: &TrustServiceStatusList,
        now: DateTime<Utc>,
    ) -> Result<()> {
        if !tl.is_current_at(now) {
            let info = &tl.scheme_information;
            return Err(TrustListError::NotCurrent(format!(
                "trust list for {} issued {} with next update {} is not current at {now}",
                info.scheme_territory,
                info.list_issue_date_time,
                info.next_update
                    .map_or_else(|| "none (closed list)".to_string(), |next| next.to_string()),
            )));
        }

        let list_next_update = tl.scheme_information.next_update;
        let territory = tl.scheme_information.scheme_territory.clone();
        if !self.territories.contains(&territory) {
            self.territories.push(territory.clone());
        }

        for provider in &tl.trust_service_providers {
            for service in &provider.services {
                if service.digital_identities.is_empty() {
                    continue;
                }
                let entry = TrustAnchorEntry {
                    provider_name: provider.name.clone(),
                    territory: provider.territory.clone(),
                    service: service.clone(),
                    list_next_update,
                };
                for identity in &service.digital_identities {
                    self.index
                        .entry(identity.fingerprint())
                        .or_default()
                        .push(entry.clone());
                }
                self.entry_count += 1;
            }
        }
        Ok(())
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
            digital_identities: vec![identity],
            service_status: status,
            status_starting_time: Utc::now(),
            history: Vec::new(),
        };

        let entry = TrustAnchorEntry {
            provider_name: provider_name.to_string(),
            territory: territory.to_string(),
            service,
            list_next_update: None,
        };

        if !self.territories.contains(&territory.to_string()) {
            self.territories.push(territory.to_string());
        }

        self.index.entry(fingerprint).or_default().push(entry);
        self.entry_count += 1;
    }

    /// Look up a trust anchor by X.509 certificate (DER bytes).
    ///
    /// Returns the first entry trusted at the system clock's current time, or
    /// an untrusted entry with the reason if only those match. See
    /// [`lookup_by_identity_at`](Self::lookup_by_identity_at).
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

    /// Generic lookup by any digital identity type, at the system clock's
    /// current time.
    pub fn lookup_by_identity(&self, identity: &ServiceDigitalIdentity) -> LookupResult {
        self.lookup_by_identity_at(identity, Utc::now())
    }

    /// Generic lookup by any digital identity type at `now`: an entry is
    /// trusted only if [`TrustAnchorEntry::usable_at`] accepts it, i.e. its
    /// list is not past `NextUpdate` and its status at `now` is active.
    pub fn lookup_by_identity_at(
        &self,
        identity: &ServiceDigitalIdentity,
        now: DateTime<Utc>,
    ) -> LookupResult {
        self.lookup_matching(identity, now, |_| true)
    }

    pub(crate) fn lookup_matching(
        &self,
        identity: &ServiceDigitalIdentity,
        now: DateTime<Utc>,
        accept: impl Fn(&TrustAnchorEntry) -> bool,
    ) -> LookupResult {
        let Some(entries) = self.index.get(&identity.fingerprint()) else {
            return LookupResult::NotFound;
        };
        let mut first_rejected = None;
        for entry in entries {
            let verdict = if accept(entry) {
                entry.usable_at(now)
            } else {
                Err(format!(
                    "service type {:?} is not accepted here",
                    entry.service.service_type
                ))
            };
            match verdict {
                Ok(()) => return LookupResult::Trusted(entry.clone()),
                Err(reason) => {
                    first_rejected.get_or_insert((entry, reason));
                }
            }
        }
        match first_rejected {
            Some((entry, reason)) => LookupResult::Inactive {
                entry: entry.clone(),
                reason,
            },
            None => LookupResult::NotFound,
        }
    }

    /// Every X.509 certificate identity of an entry, with the entry. Callers
    /// check [`TrustAnchorEntry::usable_at`] and the service type themselves.
    pub fn certificate_anchors(&self) -> impl Iterator<Item = (&TrustAnchorEntry, &[u8])> {
        self.index.values().flatten().flat_map(|entry| {
            entry
                .service
                .digital_identities
                .iter()
                .filter_map(move |identity| match identity {
                    ServiceDigitalIdentity::X509Certificate(der) => Some((entry, der.as_slice())),
                    _ => None,
                })
        })
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
    ///
    /// "Active" is the current status; list freshness is not checked here.
    pub fn pid_providers(&self) -> Vec<&TrustAnchorEntry> {
        self.find_by_service_type(&ServiceType::Pid)
            .into_iter()
            .filter(|e| e.service.service_status.is_active())
            .collect()
    }

    /// Find all active wallet providers.
    ///
    /// "Active" is the current status; list freshness is not checked here.
    pub fn wallet_providers(&self) -> Vec<&TrustAnchorEntry> {
        self.find_by_service_type(&ServiceType::WalletProvider)
            .into_iter()
            .filter(|e| e.service.service_status.is_active())
            .collect()
    }

    /// Find all active QEAA providers.
    ///
    /// "Active" is the current status; list freshness is not checked here.
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
            digital_identities: vec![did_identity],
            service_status: ServiceStatus::Granted,
            status_starting_time: Utc::now(),
            history: Vec::new(),
        };

        let entry = TrustAnchorEntry {
            provider_name: "EBSI Provider".into(),
            territory: "EU".into(),
            service,
            list_next_update: None,
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
                list_issue_date_time: Utc::now() - chrono::Duration::days(1),
                next_update: Some(Utc::now() + chrono::Duration::days(30)),
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
                    digital_identities: vec![
                        ServiceDigitalIdentity::X509Certificate(sample_cert(10)),
                        ServiceDigitalIdentity::X509Certificate(sample_cert(11)),
                    ],
                    service_status: ServiceStatus::Granted,
                    status_starting_time: Utc::now(),
                    history: Vec::new(),
                }],
            }],
        };

        let mut registry = TrustListRegistry::new();
        registry.load_trust_list(&tl, Utc::now()).unwrap();

        assert_eq!(registry.entry_count(), 1);
        assert!(
            registry
                .lookup_by_certificate(&sample_cert(10))
                .is_trusted()
        );
        assert!(
            registry
                .lookup_by_certificate(&sample_cert(11))
                .is_trusted(),
            "every identity of a service is indexed"
        );

        let after_next_update = Utc::now() + chrono::Duration::days(31);
        assert!(
            !registry
                .lookup_by_identity_at(
                    &ServiceDigitalIdentity::X509Certificate(sample_cert(10)),
                    after_next_update,
                )
                .is_trusted(),
            "a loaded entry is not trusted after its list's next update"
        );

        let mut named = tl.clone();
        named.trust_service_providers[0].services[0].digital_identities =
            vec![ServiceDigitalIdentity::X509SubjectName(
                "CN=PID, C=DE".into(),
            )];
        let mut by_name = TrustListRegistry::new();
        by_name.load_trust_list(&named, Utc::now()).unwrap();
        assert!(
            by_name
                .lookup_by_identity(&ServiceDigitalIdentity::X509SubjectName(
                    "CN=PID, C=DE".into()
                ))
                .is_trusted()
        );
        assert!(
            !by_name.lookup_by_did("CN=PID, C=DE").is_trusted(),
            "a subject name is not found as a DID"
        );

        let mut stale = tl.clone();
        stale.scheme_information.next_update = Some(Utc::now() - chrono::Duration::hours(1));
        assert!(
            TrustListRegistry::new()
                .load_trust_list(&stale, Utc::now())
                .is_err()
        );

        let mut closed = tl;
        closed.scheme_information.next_update = None;
        assert!(
            TrustListRegistry::new()
                .load_trust_list(&closed, Utc::now())
                .is_err()
        );
    }
}

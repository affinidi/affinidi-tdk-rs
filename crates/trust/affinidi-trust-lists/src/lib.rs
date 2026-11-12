/*!
 * EU Trusted Lists for eIDAS 2.0.
 *
 * Implements the trust infrastructure defined by [ETSI TS 119 612](https://www.etsi.org/deliver/etsi_ts/119600_119699/119612/)
 * for the EU Digital Identity framework.
 *
 * # Trust List Hierarchy
 *
 * ```text
 * European Commission
 *   └── List of Trusted Lists (LoTL)
 *         └── 43 Member State National Trusted Lists
 *               └── Trust Service Providers (TSPs)
 *                     └── Individual Services (trust anchors)
 *                           └── Public keys / X.509 certs + status
 * ```
 *
 * # eIDAS 2.0 Entity Types
 *
 * The Architecture Reference Framework defines 7 entity types:
 * 1. **Wallet Providers** — Certified EUDI Wallet solutions
 * 2. **PID Providers** — Person Identification Data issuers
 * 3. **QEAA Providers** — Qualified Electronic Attestation of Attributes
 * 4. **PuB-EAA Providers** — Public Body EAA issuers
 * 5. **QESRC Providers** — Qualified Electronic Signature Remote Creation
 * 6. **Access Certificate Authorities** — Issue access certificates
 * 7. **Registration Certificate Providers** — Issue registration certificates
 *
 * # Features
 *
 * - **XML Parsing**: ETSI TS 119 612 XML parsing — TSPs, services, all digital
 *   identities, service history, issue date and next update
 * - **Trust Registry**: O(1) lookup by certificate, SKI, public key, or DID.
 *   Loading refuses a list that is stale or closed, and an entry stops being
 *   trusted once its list passes `NextUpdate`. Lookups and chain validation
 *   at a given time use the service status in force at that time; the
 *   `find_*` / `*_providers` listings use the current status and do not
 *   check list freshness
 * - **X.509 Validation**: Certificate path validation to a trust anchor of
 *   the caller's chosen service types, with each certificate signature
 *   verified (no revocation checking)
 * - **COSE x5chain**: Integration point for mdoc issuerAuth certificate chains
 *
 * # Not provided: trust list signature verification
 *
 * The XAdES signature of an XML trusted list is **not verified** by this
 * crate. [`xml::parse_trust_list_xml`] returns an [`xml::UnverifiedTrustList`];
 * the caller must authenticate the list's bytes before calling
 * [`xml::UnverifiedTrustList::assume_authenticated`] and loading it.
 *
 * # Usage
 *
 * ```rust
 * use affinidi_trust_lists::*;
 *
 * // Create a registry
 * let mut registry = TrustListRegistry::new();
 *
 * // Add trust anchors (from parsed trust lists or manually)
 * registry.add_provider(
 *     "DE",
 *     "German Federal Identity Office",
 *     ServiceType::Pid,
 *     ServiceStatus::Granted,
 *     b"<certificate-bytes>",
 * );
 *
 * // Look up an issuer
 * let result = registry.lookup_by_certificate(b"<certificate-bytes>");
 * assert!(result.is_trusted());
 *
 * // Validate an x5chain from COSE_Sign1 (mdoc issuerAuth)
 * let chain_result = validate_x5chain(&[/* DER certs */], &registry, &[ServiceType::Pid]).unwrap();
 * assert!(!chain_result.valid);
 * ```
 */

pub mod error;
pub mod registry;
pub mod service_status;
pub mod service_type;
pub mod types;
pub mod x509;
pub mod xml;

pub use error::TrustListError;
pub use registry::{LookupResult, TrustAnchorEntry, TrustListRegistry};
pub use service_status::ServiceStatus;
pub use service_type::ServiceType;
pub use types::{
    OtherTslPointer, SchemeInformation, ServiceDigitalIdentity, ServiceHistoryEntry,
    ServiceInformation, TrustServiceProvider, TrustServiceStatusList, TslType,
};
pub use x509::{
    CertInfo, ChainValidationResult, validate_chain, validate_chain_at, validate_x5chain,
    validate_x5chain_at,
};
pub use xml::{UnverifiedTrustList, parse_trust_list_xml};

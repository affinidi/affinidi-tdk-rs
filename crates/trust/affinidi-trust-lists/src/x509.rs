/*!
 * X.509 certificate parsing and chain validation for eIDAS trust infrastructure.
 *
 * Provides certificate parsing to extract issuer, subject, public key, validity,
 * and Subject Key Identifier (SKI). Also provides chain validation that links
 * a certificate chain to a trust anchor in the [`TrustListRegistry`].
 *
 * # Chain Validation
 *
 * ```text
 * Leaf cert (Document Signer)
 *   └── signed by → Intermediate CA
 *         └── signed by → Trust Anchor (in TrustListRegistry)
 * ```
 *
 * [`validate_chain_at`] builds the path from the leaf to the first certificate
 * that is a usable trust anchor in the registry. When no certificate in the
 * chain is an anchor (an mdoc `x5chain` usually carries only the document
 * signer), a usable anchor certificate from the registry whose subject is the
 * last certificate's issuer and whose key verifies its signature ends the path.
 *
 * A usable anchor is a registry entry whose service type is one of the
 * caller's `anchor_types`, whose status at the validation time is active
 * (from its status history, see
 * [`ServiceInformation::status_at`](crate::ServiceInformation::status_at)),
 * and whose trust list has not passed its `NextUpdate` at that time
 * ([`TrustAnchorEntry::usable_at`]).
 *
 * For every link in that path:
 * 1. The child's issuer name equals the parent's subject name (DER comparison)
 * 2. The child's signature verifies under the parent's public key; SHA-1
 *    signature algorithms are refused
 * 3. The parent is a CA (`basicConstraints.cA`), permits certificate signing
 *    when it carries `keyUsage`, and its `pathLenConstraint` is honoured
 *
 * and every certificate in the path, the anchor included, is within its
 * validity period at the given time and carries no critical extension this
 * module does not enforce (name constraints, policy constraints, policy
 * mappings, inhibit-any-policy, or any unrecognised extension).
 *
 * Not checked: revocation (CRL / OCSP), certificate policies, and extended key
 * usage. Callers that need those must check them on [`ChainValidationResult::chain`].
 *
 * Supported signature algorithms are those of `x509-parser`'s verifier: RSA
 * PKCS#1 v1.5 and PSS with SHA-2, ECDSA on P-256 and P-384, and Ed25519.
 * Certificates signed on other curves (P-521, brainpool) do not validate.
 */

use chrono::{DateTime, Utc};
use x509_parser::oid_registry::{OID_PKCS1_SHA1WITHRSA, OID_SHA1_WITH_RSA, OID_SIG_DSA_WITH_SHA1};
use x509_parser::prelude::*;

use crate::error::{Result, TrustListError};
use crate::registry::{LookupResult, TrustAnchorEntry, TrustListRegistry};
use crate::service_type::ServiceType;
use crate::types::ServiceDigitalIdentity;

/// Parsed X.509 certificate information.
///
/// Extracted fields relevant for eIDAS trust chain validation.
#[derive(Debug, Clone)]
pub struct CertInfo {
    /// Subject distinguished name (e.g., "CN=German PID Issuer, O=Bundesdruckerei, C=DE").
    pub subject: String,
    /// Issuer distinguished name.
    pub issuer: String,
    /// Serial number (hex-encoded).
    pub serial: String,
    /// Not-before validity date (RFC 2822).
    pub not_before: String,
    /// Not-after validity date (RFC 2822).
    pub not_after: String,
    /// Subject Key Identifier (if present in extensions).
    pub subject_key_identifier: Option<Vec<u8>>,
    /// Authority Key Identifier (if present in extensions).
    pub authority_key_identifier: Option<Vec<u8>>,
    /// The raw DER bytes of the certificate.
    pub der: Vec<u8>,
    /// Whether the certificate is valid (time-based) at the system clock's
    /// current time, as of parsing.
    pub is_time_valid: bool,
    /// Whether this is a CA certificate (basicConstraints.cA = true).
    pub is_ca: bool,
}

/// Parse a DER-encoded X.509 certificate and extract key fields.
pub fn parse_certificate(der: &[u8]) -> Result<CertInfo> {
    let cert = decode(der)?;

    let not_before = cert
        .validity()
        .not_before
        .to_rfc2822()
        .unwrap_or_else(|_| "unknown".to_string());
    let not_after = cert
        .validity()
        .not_after
        .to_rfc2822()
        .unwrap_or_else(|_| "unknown".to_string());

    let subject_key_identifier = cert.extensions().iter().find_map(|ext| {
        if let ParsedExtension::SubjectKeyIdentifier(ski) = ext.parsed_extension() {
            Some(ski.0.to_vec())
        } else {
            None
        }
    });

    let authority_key_identifier = cert.extensions().iter().find_map(|ext| {
        if let ParsedExtension::AuthorityKeyIdentifier(aki) = ext.parsed_extension() {
            aki.key_identifier.as_ref().map(|ki| ki.0.to_vec())
        } else {
            None
        }
    });

    Ok(CertInfo {
        subject: cert.subject().to_string(),
        issuer: cert.issuer().to_string(),
        serial: cert.raw_serial_as_string(),
        not_before,
        not_after,
        subject_key_identifier,
        authority_key_identifier,
        der: der.to_vec(),
        is_time_valid: cert.validity().is_valid(),
        is_ca: is_ca(&cert),
    })
}

/// Result of chain validation against the trust list registry.
#[derive(Debug)]
#[non_exhaustive]
pub struct ChainValidationResult {
    /// `true` only when every link from the leaf to an active trust anchor
    /// was signature-verified and every check listed in the module
    /// documentation passed. `errors` is empty exactly when this is `true`.
    pub valid: bool,
    /// The active trust anchor the path ends at, if one was found. Present
    /// even when `valid` is `false`, so it says which anchor the chain
    /// claimed, not that it is trusted.
    pub trust_anchor: Option<TrustAnchorEntry>,
    /// The parsed certificates of the supplied chain (leaf first). An anchor
    /// taken from the registry is not appended.
    pub chain: Vec<CertInfo>,
    /// Validation errors (empty if valid).
    pub errors: Vec<String>,
}

impl ChainValidationResult {
    fn invalid(chain: Vec<CertInfo>, errors: Vec<String>) -> Self {
        Self {
            valid: false,
            trust_anchor: None,
            chain,
            errors,
        }
    }
}

/// Validate a certificate chain against the trust list registry at the
/// system clock's current time. See [`validate_chain_at`].
pub fn validate_chain(
    chain_der: &[Vec<u8>],
    registry: &TrustListRegistry,
    anchor_types: &[ServiceType],
) -> Result<ChainValidationResult> {
    validate_chain_at(chain_der, registry, anchor_types, Utc::now())
}

/// Validate a certificate chain against the trust list registry at `now`.
///
/// The chain is ordered leaf-first: `[leaf, intermediate..., root]`. The
/// checks performed are listed in the [module documentation](self). Only
/// registry entries whose service type is in `anchor_types` can anchor the
/// chain (e.g. the types under which the relevant issuers' CAs are listed);
/// an empty slice accepts none.
///
/// Returns `Ok` with `valid: false` and the reasons in `errors` for a chain
/// that does not validate; `Err` is not used for validation failures.
pub fn validate_chain_at(
    chain_der: &[Vec<u8>],
    registry: &TrustListRegistry,
    anchor_types: &[ServiceType],
    now: DateTime<Utc>,
) -> Result<ChainValidationResult> {
    if chain_der.is_empty() {
        return Ok(ChainValidationResult::invalid(
            Vec::new(),
            vec!["empty certificate chain".into()],
        ));
    }

    let check_time = ASN1Time::from_timestamp(now.timestamp())
        .map_err(|e| TrustListError::Certificate(format!("validation time out of range: {e}")))?;

    let mut infos = Vec::with_capacity(chain_der.len());
    let mut certs = Vec::with_capacity(chain_der.len());
    for (position, der) in chain_der.iter().enumerate() {
        match (parse_certificate(der), decode(der)) {
            (Ok(info), Ok(cert)) => {
                infos.push(info);
                certs.push(cert);
            }
            (Err(e), _) | (_, Err(e)) => {
                return Ok(ChainValidationResult::invalid(
                    infos,
                    vec![format!("certificate {position} parse error: {e}")],
                ));
            }
        }
    }

    let mut errors = Vec::new();

    let accept = |entry: &TrustAnchorEntry| anchor_types.contains(&entry.service.service_type);
    let mut anchor_in_chain = None;
    for (position, der) in chain_der.iter().enumerate() {
        let identity = ServiceDigitalIdentity::X509Certificate(der.clone());
        match registry.lookup_matching(&identity, now, accept) {
            LookupResult::Trusted(entry) => {
                anchor_in_chain = Some((position, entry));
                break;
            }
            LookupResult::Inactive { reason, .. } => {
                errors.push(format!(
                    "certificate {position} is a trust list entry that cannot anchor this chain ({reason})"
                ));
            }
            LookupResult::NotFound => {}
        }
    }

    let (path_len, trust_anchor, external_anchor) = match anchor_in_chain {
        Some((position, entry)) => (position + 1, Some(entry), None),
        None => {
            let last = &certs[certs.len() - 1];
            match find_issuing_anchor(last, registry, &accept, now) {
                Some((entry, anchor_der)) => (certs.len(), Some(entry), Some(anchor_der)),
                None => (certs.len(), None, None),
            }
        }
    };

    let external_cert = match external_anchor.as_deref().map(decode).transpose() {
        Ok(cert) => cert,
        Err(e) => {
            errors.push(format!("trust anchor certificate parse error: {e}"));
            None
        }
    };

    let mut path: Vec<(String, &X509Certificate)> = certs[..path_len]
        .iter()
        .enumerate()
        .map(|(position, cert)| (format!("certificate {position}"), cert))
        .collect();
    if let Some(cert) = external_cert.as_ref() {
        path.push(("trust anchor".to_string(), cert));
    }

    for (label, cert) in &path {
        if !cert.validity().is_valid_at(check_time) {
            errors.push(format!(
                "{label} ({}) is not within its validity period",
                cert.subject()
            ));
        }
        if let Some(reason) = unenforced_critical_extension(cert) {
            errors.push(format!("{label} carries {reason}"));
        }
    }

    for (index, pair) in path.windows(2).enumerate() {
        let (child_label, child) = &pair[0];
        let (parent_label, parent) = &pair[1];
        if let Err(reason) = check_link(child, parent, index) {
            errors.push(format!(
                "{child_label} is not validly issued by {parent_label}: {reason}"
            ));
        }
    }

    if trust_anchor.is_none() {
        errors.push("no usable trust anchor in the registry issues this chain".into());
    }

    Ok(ChainValidationResult {
        valid: errors.is_empty(),
        trust_anchor,
        chain: infos,
        errors,
    })
}

/// Validate an x5chain from a COSE_Sign1 header against the trust list
/// registry at the system clock's current time. See [`validate_x5chain_at`].
pub fn validate_x5chain(
    x5chain: &[Vec<u8>],
    registry: &TrustListRegistry,
    anchor_types: &[ServiceType],
) -> Result<ChainValidationResult> {
    validate_chain_at(x5chain, registry, anchor_types, Utc::now())
}

/// Validate an x5chain from a COSE_Sign1 header against the trust list registry.
///
/// The `x5chain` parameter contains DER-encoded certificates from the COSE
/// header (label 33), ordered leaf-first. It may carry only the document
/// signer certificate; the issuing anchor (e.g. an IACA) is then taken from
/// the registry. A `valid` result establishes that the leaf certificate chains
/// to a usable anchor of one of `anchor_types`; verifying the COSE signature
/// with the leaf's key is the caller's step.
pub fn validate_x5chain_at(
    x5chain: &[Vec<u8>],
    registry: &TrustListRegistry,
    anchor_types: &[ServiceType],
    now: DateTime<Utc>,
) -> Result<ChainValidationResult> {
    validate_chain_at(x5chain, registry, anchor_types, now)
}

/// Extract the leaf certificate's public key bytes from a DER certificate.
///
/// Returns the raw SubjectPublicKeyInfo bytes (algorithm + key material).
pub fn extract_public_key(der: &[u8]) -> Result<Vec<u8>> {
    Ok(decode(der)?.public_key().raw.to_vec())
}

/// Check if a DER certificate is self-issued (subject == issuer). This
/// compares names only; it does not verify the signature.
pub fn is_self_signed(der: &[u8]) -> Result<bool> {
    let info = parse_certificate(der)?;
    Ok(info.subject == info.issuer)
}

const ECDSA_WITH_SHA1: &str = "1.2.840.10045.4.1";

fn decode(der: &[u8]) -> Result<X509Certificate<'_>> {
    let (rest, cert) = X509Certificate::from_der(der)
        .map_err(|e| TrustListError::Certificate(format!("DER parse error: {e}")))?;
    if !rest.is_empty() {
        return Err(TrustListError::Certificate(
            "trailing bytes after certificate".into(),
        ));
    }
    Ok(cert)
}

fn is_ca(cert: &X509Certificate) -> bool {
    matches!(cert.basic_constraints(), Ok(Some(bc)) if bc.value.ca)
}

/// `intermediates_below` is the number of certificates between `parent` and
/// the leaf, i.e. the CA certificates `parent`'s path length must allow.
fn check_link(
    child: &X509Certificate,
    parent: &X509Certificate,
    intermediates_below: usize,
) -> std::result::Result<(), String> {
    if child.issuer().as_raw() != parent.subject().as_raw() {
        return Err(format!(
            "issuer '{}' does not match subject '{}'",
            child.issuer(),
            parent.subject()
        ));
    }

    let constraints = parent
        .basic_constraints()
        .map_err(|e| format!("issuer basicConstraints unreadable: {e}"))?
        .filter(|bc| bc.value.ca)
        .ok_or("issuer is not a CA certificate (basicConstraints.cA is not set)")?;
    if let Some(limit) = constraints.value.path_len_constraint
        && intermediates_below > limit as usize
    {
        return Err(format!(
            "issuer pathLenConstraint {limit} allows fewer intermediates than the {intermediates_below} below it"
        ));
    }

    if let Some(usage) = parent
        .key_usage()
        .map_err(|e| format!("issuer keyUsage unreadable: {e}"))?
        && !usage.value.key_cert_sign()
    {
        return Err("issuer keyUsage does not permit certificate signing".into());
    }

    let algorithm = &child.signature_algorithm.algorithm;
    if *algorithm == OID_PKCS1_SHA1WITHRSA
        || *algorithm == OID_SHA1_WITH_RSA
        || *algorithm == OID_SIG_DSA_WITH_SHA1
        || algorithm.to_id_string() == ECDSA_WITH_SHA1
    {
        return Err("SHA-1 signature algorithm is not accepted".into());
    }

    child
        .verify_signature(Some(parent.public_key()))
        .map_err(|e| format!("signature does not verify: {e}"))
}

fn unenforced_critical_extension(cert: &X509Certificate) -> Option<String> {
    cert.extensions()
        .iter()
        .filter(|ext| ext.critical)
        .find_map(|ext| match ext.parsed_extension() {
            ParsedExtension::NameConstraints(_) => {
                Some("a critical name constraints extension, which is not enforced".into())
            }
            ParsedExtension::PolicyConstraints(_)
            | ParsedExtension::PolicyMappings(_)
            | ParsedExtension::InhibitAnyPolicy(_) => {
                Some("a critical policy extension, which is not enforced".into())
            }
            ParsedExtension::UnsupportedExtension { .. } | ParsedExtension::ParseError { .. } => {
                Some(format!("an unrecognised critical extension {}", ext.oid))
            }
            _ => None,
        })
}

/// A usable anchor certificate in the registry that issued `cert`: its
/// subject equals `cert`'s issuer and its key verifies `cert`'s signature.
fn find_issuing_anchor(
    cert: &X509Certificate,
    registry: &TrustListRegistry,
    accept: &dyn Fn(&TrustAnchorEntry) -> bool,
    now: DateTime<Utc>,
) -> Option<(TrustAnchorEntry, Vec<u8>)> {
    registry
        .certificate_anchors()
        .filter(|(entry, _)| accept(entry) && entry.usable_at(now).is_ok())
        .find(|(_, anchor_der)| {
            decode(anchor_der).is_ok_and(|anchor| {
                anchor.subject().as_raw() == cert.issuer().as_raw()
                    && cert.verify_signature(Some(anchor.public_key())).is_ok()
            })
        })
        .map(|(entry, anchor_der)| (entry.clone(), anchor_der.to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ServiceStatus, ServiceType};
    use rcgen::{
        BasicConstraints, CertificateParams, CertifiedIssuer, CustomExtension, DnType, IsCa,
        KeyPair, KeyUsagePurpose,
    };

    const ANCHOR_TYPES: &[ServiceType] = &[ServiceType::CaQc];

    fn fixture_cert() -> Vec<u8> {
        include_bytes!("../tests/fixtures/test_cert.der").to_vec()
    }

    fn ca_params(name: &str, constraint: BasicConstraints) -> CertificateParams {
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.distinguished_name.push(DnType::CommonName, name);
        params.is_ca = IsCa::Ca(constraint);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        params
    }

    fn leaf_params(name: &str) -> CertificateParams {
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.distinguished_name.push(DnType::CommonName, name);
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params
    }

    fn root(name: &str) -> CertifiedIssuer<'static, KeyPair> {
        CertifiedIssuer::self_signed(
            ca_params(name, BasicConstraints::Unconstrained),
            KeyPair::generate().unwrap(),
        )
        .unwrap()
    }

    fn leaf_signed_by(name: &str, issuer: &CertifiedIssuer<'_, KeyPair>) -> Vec<u8> {
        leaf_params(name)
            .signed_by(&KeyPair::generate().unwrap(), issuer)
            .unwrap()
            .der()
            .to_vec()
    }

    fn registry_with(anchor: &[u8]) -> TrustListRegistry {
        let mut registry = TrustListRegistry::new();
        registry.add_provider(
            "DE",
            "Test IACA",
            ServiceType::CaQc,
            ServiceStatus::Granted,
            anchor,
        );
        registry
    }

    #[test]
    fn validate_empty_chain() {
        let registry = TrustListRegistry::new();
        let result = validate_chain(&[], &registry, ANCHOR_TYPES).unwrap();
        assert!(!result.valid);
        assert!(result.errors[0].contains("empty"));
    }

    #[test]
    fn validate_chain_not_in_registry() {
        let registry = TrustListRegistry::new();
        let result = validate_chain(&[fixture_cert()], &registry, ANCHOR_TYPES).unwrap();
        assert!(!result.valid);
        assert!(result.errors.iter().any(|e| e.contains("trust anchor")));
    }

    #[test]
    fn validate_chain_found_in_registry() {
        let cert = fixture_cert();
        let registry = registry_with(&cert);
        let result = validate_chain(&[cert], &registry, ANCHOR_TYPES).unwrap();
        assert!(result.trust_anchor.is_some());
    }

    #[test]
    fn parse_cert_fixture() {
        let info = parse_certificate(&fixture_cert()).unwrap();
        assert!(!info.subject.is_empty());
        assert!(!info.issuer.is_empty());
    }

    #[test]
    fn invalid_der_fails() {
        assert!(parse_certificate(b"not a certificate").is_err());
    }

    #[test]
    fn validate_x5chain_empty_is_invalid() {
        let registry = TrustListRegistry::new();
        assert!(
            !validate_x5chain(&[], &registry, ANCHOR_TYPES)
                .unwrap()
                .valid
        );
    }

    #[test]
    fn leaf_and_anchor_in_chain_validates() {
        let iaca = root("Test IACA");
        let leaf = leaf_signed_by("Document Signer", &iaca);
        let registry = registry_with(iaca.der());

        let result = validate_chain(&[leaf, iaca.der().to_vec()], &registry, ANCHOR_TYPES).unwrap();
        assert!(result.valid, "{:?}", result.errors);
        assert!(result.trust_anchor.is_some());
    }

    #[test]
    fn leaf_alone_validates_against_registry_anchor() {
        let iaca = root("Test IACA");
        let leaf = leaf_signed_by("Document Signer", &iaca);
        let registry = registry_with(iaca.der());

        let result = validate_x5chain(&[leaf], &registry, ANCHOR_TYPES).unwrap();
        assert!(result.valid, "{:?}", result.errors);
        assert_eq!(result.chain.len(), 1);
    }

    #[test]
    fn leaf_with_matching_issuer_name_but_other_key_is_rejected() {
        let listed = root("Test IACA");
        let lookalike = root("Test IACA");
        let leaf = leaf_signed_by("Document Signer", &lookalike);
        let registry = registry_with(listed.der());

        let with_anchor = validate_chain(
            &[leaf.clone(), listed.der().to_vec()],
            &registry,
            ANCHOR_TYPES,
        )
        .unwrap();
        assert!(!with_anchor.valid);
        assert!(
            with_anchor
                .errors
                .iter()
                .any(|e| e.contains("signature does not verify")),
            "{:?}",
            with_anchor.errors
        );

        let leaf_only = validate_x5chain(&[leaf], &registry, ANCHOR_TYPES).unwrap();
        assert!(!leaf_only.valid);
        assert!(leaf_only.trust_anchor.is_none());
    }

    #[test]
    fn three_level_chain_validates() {
        let iaca = root("Test IACA");
        let intermediate = CertifiedIssuer::signed_by(
            ca_params("Intermediate", BasicConstraints::Constrained(0)),
            KeyPair::generate().unwrap(),
            &iaca,
        )
        .unwrap();
        let leaf = leaf_signed_by("Document Signer", &intermediate);
        let registry = registry_with(iaca.der());

        let result = validate_chain(
            &[leaf, intermediate.der().to_vec()],
            &registry,
            ANCHOR_TYPES,
        )
        .unwrap();
        assert!(result.valid, "{:?}", result.errors);
    }

    #[test]
    fn issuer_without_ca_flag_is_rejected() {
        let iaca = root("Test IACA");
        let not_ca = CertifiedIssuer::signed_by(
            leaf_params("Not A CA"),
            KeyPair::generate().unwrap(),
            &iaca,
        )
        .unwrap();
        let leaf = leaf_signed_by("Document Signer", &not_ca);
        let registry = registry_with(iaca.der());

        let result =
            validate_chain(&[leaf, not_ca.der().to_vec()], &registry, ANCHOR_TYPES).unwrap();
        assert!(!result.valid);
        assert!(result.errors.iter().any(|e| e.contains("not a CA")));
    }

    #[test]
    fn path_length_constraint_is_honoured() {
        let iaca = CertifiedIssuer::self_signed(
            ca_params("Test IACA", BasicConstraints::Constrained(0)),
            KeyPair::generate().unwrap(),
        )
        .unwrap();
        let intermediate = CertifiedIssuer::signed_by(
            ca_params("Intermediate", BasicConstraints::Unconstrained),
            KeyPair::generate().unwrap(),
            &iaca,
        )
        .unwrap();
        let leaf = leaf_signed_by("Document Signer", &intermediate);
        let registry = registry_with(iaca.der());

        let result = validate_chain(
            &[leaf, intermediate.der().to_vec()],
            &registry,
            ANCHOR_TYPES,
        )
        .unwrap();
        assert!(!result.valid);
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.contains("pathLenConstraint")),
            "{:?}",
            result.errors
        );
    }

    #[test]
    fn expired_at_given_time_is_rejected() {
        let iaca = root("Test IACA");
        let leaf = leaf_signed_by("Document Signer", &iaca);
        let registry = registry_with(iaca.der());

        let far_future = Utc::now() + chrono::Duration::days(365 * 5000);
        let result = validate_chain_at(&[leaf], &registry, ANCHOR_TYPES, far_future).unwrap();
        assert!(!result.valid);
        assert!(result.errors.iter().any(|e| e.contains("validity period")));
    }

    #[test]
    fn inactive_anchor_is_not_trusted() {
        let iaca = root("Test IACA");
        let leaf = leaf_signed_by("Document Signer", &iaca);
        let mut registry = TrustListRegistry::new();
        registry.add_provider(
            "DE",
            "Test IACA",
            ServiceType::CaQc,
            ServiceStatus::Withdrawn,
            iaca.der(),
        );

        let result = validate_chain(&[leaf, iaca.der().to_vec()], &registry, ANCHOR_TYPES).unwrap();
        assert!(!result.valid);
        assert!(result.trust_anchor.is_none());
    }

    #[test]
    fn anchor_of_another_service_type_is_not_used() {
        let iaca = root("Test IACA");
        let leaf = leaf_signed_by("Document Signer", &iaca);
        let registry = registry_with(iaca.der());

        let other_type = validate_chain(
            &[leaf.clone(), iaca.der().to_vec()],
            &registry,
            &[ServiceType::Pid],
        )
        .unwrap();
        assert!(!other_type.valid);
        assert!(other_type.trust_anchor.is_none());

        let leaf_only =
            validate_x5chain(std::slice::from_ref(&leaf), &registry, &[ServiceType::Pid]).unwrap();
        assert!(!leaf_only.valid);

        assert!(!validate_x5chain(&[leaf], &registry, &[]).unwrap().valid);
    }

    #[test]
    fn issuer_key_usage_without_cert_signing_is_rejected() {
        let mut params = ca_params("Test IACA", BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        let iaca = CertifiedIssuer::self_signed(params, KeyPair::generate().unwrap()).unwrap();
        let leaf = leaf_signed_by("Document Signer", &iaca);
        let registry = registry_with(iaca.der());

        let result = validate_chain(&[leaf, iaca.der().to_vec()], &registry, ANCHOR_TYPES).unwrap();
        assert!(!result.valid);
        assert!(
            result.errors.iter().any(|e| e.contains("keyUsage")),
            "{:?}",
            result.errors
        );
    }

    #[test]
    fn unrecognised_critical_extension_is_rejected() {
        let iaca = root("Test IACA");
        let mut params = leaf_params("Document Signer");
        let mut extension =
            CustomExtension::from_oid_content(&[1, 3, 6, 1, 4, 1, 99999, 1], vec![0x05, 0x00]);
        extension.set_criticality(true);
        params.custom_extensions = vec![extension];
        let leaf = params
            .signed_by(&KeyPair::generate().unwrap(), &iaca)
            .unwrap()
            .der()
            .to_vec();
        let registry = registry_with(iaca.der());

        let result = validate_x5chain(&[leaf], &registry, ANCHOR_TYPES).unwrap();
        assert!(!result.valid);
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.contains("unrecognised critical extension")),
            "{:?}",
            result.errors
        );
    }

    fn der_header(tag: u8, length: usize) -> Vec<u8> {
        let mut header = vec![tag];
        if length < 0x80 {
            header.push(length as u8);
        } else {
            let bytes: Vec<u8> = length
                .to_be_bytes()
                .into_iter()
                .skip_while(|byte| *byte == 0)
                .collect();
            header.push(0x80 | bytes.len() as u8);
            header.extend(bytes);
        }
        header
    }

    /// Splits one DER TLV off the front of `input`: (tag, content, rest).
    fn der_split(input: &[u8]) -> (u8, &[u8], &[u8]) {
        let tag = input[0];
        let (length, header_len) = if input[1] < 0x80 {
            (input[1] as usize, 2)
        } else {
            let count = (input[1] & 0x7f) as usize;
            let length = input[2..2 + count]
                .iter()
                .fold(0usize, |acc, byte| (acc << 8) | *byte as usize);
            (length, 2 + count)
        };
        (
            tag,
            &input[header_len..header_len + length],
            &input[header_len + length..],
        )
    }

    fn replace_bytes(haystack: &[u8], from: &[u8], to: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut rest = haystack;
        while !rest.is_empty() {
            if rest.starts_with(from) {
                out.extend_from_slice(to);
                rest = &rest[from.len()..];
            } else {
                out.push(rest[0]);
                rest = &rest[1..];
            }
        }
        out
    }

    /// Relabels an ECDSA-SHA256 certificate's signature algorithm as
    /// ECDSA-SHA1, re-encoding the enclosing lengths.
    fn relabel_as_sha1(cert: &[u8]) -> Vec<u8> {
        const ECDSA_SHA256: &[u8] = &[
            0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02,
        ];
        const ECDSA_SHA1: &[u8] = &[
            0x30, 0x09, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x01,
        ];
        let (_, body, _) = der_split(cert);
        let (tbs_tag, tbs, after_tbs) = der_split(body);
        let tbs = replace_bytes(tbs, ECDSA_SHA256, ECDSA_SHA1);
        let after_tbs = replace_bytes(after_tbs, ECDSA_SHA256, ECDSA_SHA1);
        let mut new_body = der_header(tbs_tag, tbs.len());
        new_body.extend(tbs);
        new_body.extend(after_tbs);
        let mut out = der_header(0x30, new_body.len());
        out.extend(new_body);
        out
    }

    #[test]
    fn sha1_signature_algorithm_is_rejected() {
        let iaca = root("Test IACA");
        let leaf = relabel_as_sha1(&leaf_signed_by("Document Signer", &iaca));
        assert_eq!(
            decode(&leaf)
                .unwrap()
                .signature_algorithm
                .algorithm
                .to_id_string(),
            ECDSA_WITH_SHA1
        );
        let registry = registry_with(iaca.der());

        let result = validate_chain(&[leaf, iaca.der().to_vec()], &registry, ANCHOR_TYPES).unwrap();
        assert!(!result.valid);
        assert!(
            result.errors.iter().any(|e| e.contains("SHA-1")),
            "{:?}",
            result.errors
        );
    }

    #[test]
    fn anchor_from_a_list_past_next_update_is_not_used() {
        use crate::types::*;

        let iaca = root("Test IACA");
        let leaf = leaf_signed_by("Document Signer", &iaca);
        let issued = Utc::now() - chrono::Duration::days(1);
        let next_update = Utc::now() + chrono::Duration::days(30);
        let tl = TrustServiceStatusList {
            scheme_information: SchemeInformation {
                tsl_version: 5,
                tsl_sequence_number: 1,
                tsl_type: TslType::EuGeneric,
                scheme_operator_name: "Authority".into(),
                scheme_territory: "DE".into(),
                list_issue_date_time: issued,
                next_update: Some(next_update),
                pointers_to_other_tsl: Vec::new(),
            },
            trust_service_providers: vec![TrustServiceProvider {
                name: "IACA operator".into(),
                trade_name: None,
                territory: "DE".into(),
                information_uris: Vec::new(),
                services: vec![ServiceInformation {
                    service_type: ServiceType::CaQc,
                    service_name: "IACA".into(),
                    digital_identities: vec![ServiceDigitalIdentity::X509Certificate(
                        iaca.der().to_vec(),
                    )],
                    service_status: ServiceStatus::Granted,
                    status_starting_time: issued,
                    history: Vec::new(),
                }],
            }],
        };
        let mut registry = TrustListRegistry::new();
        registry.load_trust_list(&tl, Utc::now()).unwrap();

        let current = validate_x5chain_at(
            std::slice::from_ref(&leaf),
            &registry,
            ANCHOR_TYPES,
            Utc::now(),
        )
        .unwrap();
        assert!(current.valid, "{:?}", current.errors);

        let later = next_update + chrono::Duration::days(1);
        assert!(
            !validate_x5chain_at(std::slice::from_ref(&leaf), &registry, ANCHOR_TYPES, later)
                .unwrap()
                .valid
        );
        assert!(
            !validate_chain_at(&[leaf, iaca.der().to_vec()], &registry, ANCHOR_TYPES, later)
                .unwrap()
                .valid
        );
    }
}

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
 * Validation checks:
 * 1. Each certificate's issuer matches the next certificate's subject
 * 2. Each certificate is within its validity period
 * 3. The root/anchor certificate is found in the TrustListRegistry
 *
 * Note: Cryptographic signature verification of the chain is **not** performed
 * here — that requires algorithm-specific verification (ES256, ES384, etc.)
 * which belongs in the credential layer. This module validates the **structural**
 * integrity and trust anchor binding.
 */

use x509_parser::prelude::*;

use crate::error::{Result, TrustListError};
use crate::registry::{LookupResult, TrustListRegistry};

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
    /// Not-before validity date (RFC 3339).
    pub not_before: String,
    /// Not-after validity date (RFC 3339).
    pub not_after: String,
    /// Subject Key Identifier (if present in extensions).
    pub subject_key_identifier: Option<Vec<u8>>,
    /// Authority Key Identifier (if present in extensions).
    pub authority_key_identifier: Option<Vec<u8>>,
    /// The raw DER bytes of the certificate.
    pub der: Vec<u8>,
    /// Whether the certificate is currently valid (time-based).
    pub is_time_valid: bool,
    /// Whether this is a CA certificate (basicConstraints.cA = true).
    pub is_ca: bool,
}

/// Parse a DER-encoded X.509 certificate and extract key fields.
pub fn parse_certificate(der: &[u8]) -> Result<CertInfo> {
    let (_, cert) = X509Certificate::from_der(der)
        .map_err(|e| TrustListError::Certificate(format!("DER parse error: {e}")))?;

    let subject = cert.subject().to_string();
    let issuer = cert.issuer().to_string();
    let serial = cert.raw_serial_as_string();

    let not_before = cert.validity().not_before.to_rfc2822()
        .unwrap_or_else(|_| "unknown".to_string());
    let not_after = cert.validity().not_after.to_rfc2822()
        .unwrap_or_else(|_| "unknown".to_string());

    let is_time_valid = cert.validity().is_valid();

    // Extract SKI
    let subject_key_identifier = cert
        .extensions()
        .iter()
        .find_map(|ext| {
            if let ParsedExtension::SubjectKeyIdentifier(ski) = ext.parsed_extension() {
                Some(ski.0.to_vec())
            } else {
                None
            }
        });

    // Extract AKI
    let authority_key_identifier = cert
        .extensions()
        .iter()
        .find_map(|ext| {
            if let ParsedExtension::AuthorityKeyIdentifier(aki) = ext.parsed_extension() {
                aki.key_identifier.as_ref().map(|ki| ki.0.to_vec())
            } else {
                None
            }
        });

    // Check basicConstraints for CA
    let is_ca = cert
        .extensions()
        .iter()
        .any(|ext| {
            if let ParsedExtension::BasicConstraints(bc) = ext.parsed_extension() {
                bc.ca
            } else {
                false
            }
        });

    Ok(CertInfo {
        subject,
        issuer,
        serial,
        not_before,
        not_after,
        subject_key_identifier,
        authority_key_identifier,
        der: der.to_vec(),
        is_time_valid,
        is_ca,
    })
}

/// Result of chain validation against the trust list registry.
#[derive(Debug)]
pub struct ChainValidationResult {
    /// Whether the chain is valid and trusted.
    pub valid: bool,
    /// The trust anchor entry (if found in registry).
    pub trust_anchor: Option<crate::registry::TrustAnchorEntry>,
    /// The parsed certificates in the chain (leaf first).
    pub chain: Vec<CertInfo>,
    /// Validation errors (empty if valid).
    pub errors: Vec<String>,
}

/// Validate a certificate chain against the trust list registry.
///
/// The chain should be ordered leaf-first: `[leaf, intermediate..., root]`.
/// Each certificate in the chain is checked for:
/// 1. Validity period (not expired, not yet valid)
/// 2. Issuer/subject chain linking (each cert's issuer matches the next cert's subject)
/// 3. The last certificate (or any certificate) must be found as a trust anchor
///
/// # Arguments
///
/// * `chain_der` — DER-encoded certificates, leaf first
/// * `registry` — Trust list registry containing trust anchors
pub fn validate_chain(
    chain_der: &[Vec<u8>],
    registry: &TrustListRegistry,
) -> Result<ChainValidationResult> {
    if chain_der.is_empty() {
        return Ok(ChainValidationResult {
            valid: false,
            trust_anchor: None,
            chain: Vec::new(),
            errors: vec!["empty certificate chain".into()],
        });
    }

    let mut parsed_chain = Vec::new();
    let mut errors = Vec::new();

    // Parse all certificates
    for (i, der) in chain_der.iter().enumerate() {
        match parse_certificate(der) {
            Ok(info) => {
                if !info.is_time_valid {
                    errors.push(format!(
                        "certificate {} ({}) is not within validity period",
                        i, info.subject
                    ));
                }
                parsed_chain.push(info);
            }
            Err(e) => {
                errors.push(format!("certificate {} parse error: {e}", i));
                return Ok(ChainValidationResult {
                    valid: false,
                    trust_anchor: None,
                    chain: parsed_chain,
                    errors,
                });
            }
        }
    }

    // Validate issuer/subject chain linking
    for i in 0..parsed_chain.len() - 1 {
        let current = &parsed_chain[i];
        let next = &parsed_chain[i + 1];

        if current.issuer != next.subject {
            errors.push(format!(
                "chain break at {}: issuer '{}' != next subject '{}'",
                i, current.issuer, next.subject
            ));
        }
    }

    // Look up trust anchor — try each cert from root to leaf
    let mut trust_anchor = None;
    for cert in parsed_chain.iter().rev() {
        let result = registry.lookup_by_certificate(&cert.der);
        if let LookupResult::Trusted(entry) = result {
            trust_anchor = Some(entry);
            break;
        }
    }

    if trust_anchor.is_none() {
        errors.push("no certificate in chain found as trust anchor in registry".into());
    }

    let valid = errors.is_empty() && trust_anchor.is_some();

    Ok(ChainValidationResult {
        valid,
        trust_anchor,
        chain: parsed_chain,
        errors,
    })
}

/// Validate an x5chain from a COSE_Sign1 header against the trust list registry.
///
/// This is the primary integration point for mdoc issuer verification.
/// The `x5chain` parameter contains DER-encoded certificates from the
/// COSE unprotected header (label 33), ordered leaf-first.
///
/// # Returns
///
/// `Ok(ChainValidationResult)` with validation details.
pub fn validate_x5chain(
    x5chain: &[Vec<u8>],
    registry: &TrustListRegistry,
) -> Result<ChainValidationResult> {
    validate_chain(x5chain, registry)
}

/// Extract the leaf certificate's public key bytes from a DER certificate.
///
/// Returns the raw SubjectPublicKeyInfo bytes (algorithm + key material).
pub fn extract_public_key(der: &[u8]) -> Result<Vec<u8>> {
    let (_, cert) = X509Certificate::from_der(der)
        .map_err(|e| TrustListError::Certificate(format!("DER parse error: {e}")))?;

    Ok(cert.public_key().raw.to_vec())
}

/// Check if a DER certificate is self-signed (subject == issuer).
pub fn is_self_signed(der: &[u8]) -> Result<bool> {
    let info = parse_certificate(der)?;
    Ok(info.subject == info.issuer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ServiceStatus, ServiceType};

    // Generate a minimal self-signed X.509 cert for testing.
    // This uses x509-parser's test infrastructure.
    fn make_test_cert() -> Vec<u8> {
        // Minimal DER-encoded self-signed X.509v3 certificate
        // (pre-built for testing — not cryptographically valid but structurally valid)
        // This is a real X.509 structure that x509-parser can parse.
        //
        // We use rcgen-style minimal cert encoding.
        // For test purposes, we'll use a known-good minimal cert.
        include_bytes!("../tests/fixtures/test_cert.der").to_vec()
    }

    // Helper: check if we have test fixtures available
    fn has_test_fixtures() -> bool {
        std::path::Path::new(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/test_cert.der"
        ))
        .exists()
    }

    #[test]
    fn validate_empty_chain() {
        let registry = TrustListRegistry::new();
        let result = validate_chain(&[], &registry).unwrap();
        assert!(!result.valid);
        assert!(result.errors[0].contains("empty"));
    }

    #[test]
    fn validate_chain_not_in_registry() {
        if !has_test_fixtures() {
            return; // Skip if no test cert available
        }
        let cert = make_test_cert();
        let registry = TrustListRegistry::new();
        let result = validate_chain(&[cert], &registry).unwrap();
        assert!(!result.valid);
        assert!(result.errors.iter().any(|e| e.contains("trust anchor")));
    }

    #[test]
    fn validate_chain_found_in_registry() {
        if !has_test_fixtures() {
            return;
        }
        let cert = make_test_cert();
        let mut registry = TrustListRegistry::new();
        registry.add_provider("DE", "Test CA", ServiceType::CaQc, ServiceStatus::Granted, &cert);

        let result = validate_chain(&[cert], &registry).unwrap();
        assert!(result.trust_anchor.is_some());
    }

    #[test]
    fn parse_cert_if_available() {
        if !has_test_fixtures() {
            return;
        }
        let cert = make_test_cert();
        let info = parse_certificate(&cert).unwrap();
        assert!(!info.subject.is_empty());
        assert!(!info.issuer.is_empty());
    }

    #[test]
    fn invalid_der_fails() {
        let result = parse_certificate(b"not a certificate");
        assert!(result.is_err());
    }

    #[test]
    fn validate_x5chain_delegates() {
        let registry = TrustListRegistry::new();
        let result = validate_x5chain(&[], &registry).unwrap();
        assert!(!result.valid);
    }
}

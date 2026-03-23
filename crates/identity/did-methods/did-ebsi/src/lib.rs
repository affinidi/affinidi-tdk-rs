/*!
 * did:ebsi — EBSI DID method for legal entities.
 *
 * Implements resolution of `did:ebsi` identifiers registered on the
 * European Blockchain Services Infrastructure (EBSI) DID Registry.
 *
 * # DID Format
 *
 * ```text
 * did:ebsi:z<base58btc(version_byte + 16_random_bytes)>
 * ```
 *
 * - Version byte: `0x01`
 * - Identifier: 16 cryptographically random bytes
 * - Base58btc encoded with `z` multibase prefix
 * - Total DID length: ~32-33 characters
 *
 * # Resolution
 *
 * DIDs are resolved via the EBSI DID Registry API v5:
 * ```text
 * GET https://api-pilot.ebsi.eu/did-registry/v5/identifiers/{did}
 * ```
 *
 * The response is a DID Document in `application/did+ld+json` format
 * containing `JsonWebKey2020` verification methods with P-256 and/or
 * secp256k1 public keys.
 *
 * # Key Types
 *
 * - **ES256** (P-256 / secp256r1): Required minimum for VC/VP operations
 * - **ES256K** (secp256k1): Required for blockchain transactions
 */

use thiserror::Error;

/// EBSI DID method errors.
#[derive(Error, Debug)]
pub enum EbsiError {
    /// The DID format is invalid.
    #[error("Invalid EBSI DID: {0}")]
    InvalidDid(String),

    /// The DID could not be resolved.
    #[error("Resolution failed: {0}")]
    ResolutionFailed(String),

    /// The DID document could not be parsed.
    #[error("Parse error: {0}")]
    ParseError(String),

    /// HTTP request failed.
    #[error("HTTP error: {0}")]
    Http(String),
}

/// Default EBSI DID Registry API base URL (pilot environment).
pub const EBSI_PILOT_API: &str = "https://api-pilot.ebsi.eu/did-registry/v5/identifiers";

/// EBSI conformance environment API base URL.
pub const EBSI_CONFORMANCE_API: &str =
    "https://api-conformance.ebsi.eu/did-registry/v5/identifiers";

/// EBSI DID version byte.
pub const EBSI_VERSION_BYTE: u8 = 0x01;

/// Expected length of decoded EBSI identifier (1 version + 16 random = 17 bytes).
pub const EBSI_IDENTIFIER_LENGTH: usize = 17;

/// Validate a did:ebsi identifier string.
///
/// Checks:
/// - Starts with 'z' (base58btc multibase prefix)
/// - Decodes to exactly 17 bytes (1 version + 16 random)
/// - Version byte is 0x01
pub fn validate_ebsi_identifier(identifier: &str) -> Result<(), EbsiError> {
    if !identifier.starts_with('z') {
        return Err(EbsiError::InvalidDid(
            "identifier must start with 'z' (base58btc)".into(),
        ));
    }

    let decoded = bs58::decode(&identifier[1..])
        .into_vec()
        .map_err(|e| EbsiError::InvalidDid(format!("base58 decode failed: {e}")))?;

    if decoded.len() != EBSI_IDENTIFIER_LENGTH {
        return Err(EbsiError::InvalidDid(format!(
            "decoded identifier must be {} bytes, got {}",
            EBSI_IDENTIFIER_LENGTH,
            decoded.len()
        )));
    }

    if decoded[0] != EBSI_VERSION_BYTE {
        return Err(EbsiError::InvalidDid(format!(
            "version byte must be 0x{:02x}, got 0x{:02x}",
            EBSI_VERSION_BYTE, decoded[0]
        )));
    }

    Ok(())
}

/// Generate a new random did:ebsi identifier.
///
/// Creates a random 16-byte subject identifier, prepends version byte 0x01,
/// and base58btc-encodes with 'z' prefix.
pub fn generate_ebsi_did() -> String {
    use rand::Rng;
    let mut rng = rand::rng();
    let mut bytes = vec![EBSI_VERSION_BYTE];
    let random: [u8; 16] = rng.random();
    bytes.extend_from_slice(&random);

    let encoded = bs58::encode(&bytes).into_string();
    format!("did:ebsi:z{encoded}")
}

/// Resolve a did:ebsi identifier via the EBSI DID Registry API.
///
/// Makes an HTTP GET request to the specified API endpoint and returns
/// the DID Document as a parsed JSON value.
///
/// # Arguments
///
/// * `did` - The full DID string (e.g., "did:ebsi:zfEmvX5twhXjQJiCWsukvQA")
/// * `api_base` - The API base URL (use `EBSI_PILOT_API` or `EBSI_CONFORMANCE_API`)
pub async fn resolve_ebsi_did(
    did: &str,
    api_base: &str,
) -> Result<affinidi_did_common::Document, EbsiError> {
    let url = format!("{api_base}/{did}");

    let response = reqwest::get(&url)
        .await
        .map_err(|e| EbsiError::Http(format!("GET {url}: {e}")))?;

    if !response.status().is_success() {
        return Err(EbsiError::ResolutionFailed(format!(
            "HTTP {}: {}",
            response.status(),
            url
        )));
    }

    let body = response
        .text()
        .await
        .map_err(|e| EbsiError::Http(format!("reading response body: {e}")))?;

    let document: affinidi_did_common::Document = serde_json::from_str(&body)
        .map_err(|e| EbsiError::ParseError(format!("parsing DID document: {e}")))?;

    Ok(document)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_known_ebsi_did() {
        // Real EBSI DID from the pilot network
        assert!(validate_ebsi_identifier("zfEmvX5twhXjQJiCWsukvQA").is_ok());
        assert!(validate_ebsi_identifier("znHeZWvhAK2FK2Dk1jXNe7m").is_ok());
        assert!(validate_ebsi_identifier("zcGvqgZTHCtkjgtcKRL7H8k").is_ok());
    }

    #[test]
    fn validate_rejects_missing_z_prefix() {
        assert!(validate_ebsi_identifier("fEmvX5twhXjQJiCWsukvQA").is_err());
    }

    #[test]
    fn validate_rejects_too_short() {
        assert!(validate_ebsi_identifier("zabc").is_err());
    }

    #[test]
    fn validate_rejects_invalid_base58() {
        // '0', 'O', 'I', 'l' are not valid base58
        assert!(validate_ebsi_identifier("z0OIlxxxxxxxxxxxxxxxxxx").is_err());
    }

    #[test]
    fn generate_produces_valid_did() {
        let did = generate_ebsi_did();
        assert!(did.starts_with("did:ebsi:z"));

        // Extract identifier and validate
        let identifier = &did["did:ebsi:".len()..];
        assert!(validate_ebsi_identifier(identifier).is_ok());
    }

    #[test]
    fn generate_produces_unique_dids() {
        let did1 = generate_ebsi_did();
        let did2 = generate_ebsi_did();
        assert_ne!(did1, did2);
    }

    #[test]
    fn decode_known_did_structure() {
        // did:ebsi:zfEmvX5twhXjQJiCWsukvQA
        let identifier = "zfEmvX5twhXjQJiCWsukvQA";
        let decoded = bs58::decode(&identifier[1..]).into_vec().unwrap();

        assert_eq!(decoded.len(), 17); // 1 version + 16 random
        assert_eq!(decoded[0], 0x01); // Version byte
    }
}

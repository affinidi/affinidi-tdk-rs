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
#[non_exhaustive]
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

    /// The response document's `id` did not match the DID being resolved.
    ///
    /// Nothing but this check ties the registry's response to the DID that
    /// was asked for — without it, the registry (or anyone able to tamper
    /// with the response) could answer a lookup for one `did:ebsi` with a
    /// document naming a different one, and it would be accepted.
    #[error("EBSI response document id {got:?} does not match the requested DID {expected:?}")]
    DocumentIdMismatch {
        /// The DID that was requested.
        expected: String,
        /// The `id` the response document actually carried.
        got: String,
    },
}

/// Default EBSI DID Registry API base URL (pilot environment).
pub const EBSI_PILOT_API: &str = "https://api-pilot.ebsi.eu/did-registry/v5/identifiers";

/// EBSI conformance environment API base URL.
pub const EBSI_CONFORMANCE_API: &str =
    "https://api-conformance.ebsi.eu/did-registry/v5/identifiers";

/// Largest DID document response this resolver will read. A registry DID
/// document is a few KB.
pub const MAX_DOCUMENT_BYTES: usize = 1 << 20;

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
    // `RngExt`, not `Rng`: rand 0.10 renamed the old `RngCore` to `Rng` and
    // moved the sampling methods (`random`, `random_range`) onto `RngExt`.
    // Same call, same distribution — only the trait that carries it moved.
    use rand::RngExt;
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
    // Validate before interpolating into the URL: a did:ebsi method-specific
    // id is base58btc, so once validated it can only contain [1-9A-HJ-NP-Za-km-z]
    // and cannot inject `/`, `?`, `#`, `..` etc. into the request path.
    let identifier = did
        .strip_prefix("did:ebsi:")
        .ok_or_else(|| EbsiError::InvalidDid("must start with did:ebsi:".into()))?;
    validate_ebsi_identifier(identifier)?;

    let url = format!("{api_base}/did:ebsi:{identifier}");

    // The EBSI registry is the trust anchor here; following a 3xx would let
    // it (or anything on-path) pivot the resolver to an arbitrary internal
    // address (SSRF) and serve a forged DID document.
    let client = reqwest::Client::builder()
        .user_agent(concat!("affinidi-did-ebsi/", env!("CARGO_PKG_VERSION")))
        .timeout(std::time::Duration::from_secs(20))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| EbsiError::Http(format!("building HTTP client: {e}")))?;

    let mut response = client
        .get(&url)
        .send()
        .await
        .map_err(|e| EbsiError::Http(format!("GET {url}: {e}")))?;

    if !response.status().is_success() {
        return Err(EbsiError::ResolutionFailed(format!(
            "HTTP {}: {}",
            response.status(),
            url
        )));
    }

    // Refuse a body that declares itself too large before reading it, then
    // count the body as it arrives: a response without a Content-Length, or
    // with one smaller than its body, stops being read at the limit.
    if let Some(length) = response.content_length()
        && length > MAX_DOCUMENT_BYTES as u64
    {
        return Err(EbsiError::Http(format!(
            "{url} declares {length} bytes, over the {MAX_DOCUMENT_BYTES}-byte limit"
        )));
    }
    let mut body: Vec<u8> = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| EbsiError::Http(format!("reading response body: {e}")))?
    {
        if body.len() + chunk.len() > MAX_DOCUMENT_BYTES {
            return Err(EbsiError::Http(format!(
                "{url} sent more than the {MAX_DOCUMENT_BYTES}-byte limit"
            )));
        }
        body.extend_from_slice(&chunk);
    }

    let document: affinidi_did_common::Document = serde_json::from_slice(&body)
        .map_err(|e| EbsiError::ParseError(format!("parsing DID document: {e}")))?;
    verify_document_id(did, &document)?;

    Ok(document)
}

/// The DID Resolution spec requires a resolved document's `id` to equal the
/// DID that was resolved. Check this ourselves rather than trust the
/// registry: see [`EbsiError::DocumentIdMismatch`] for why.
fn verify_document_id(
    did: &str,
    document: &affinidi_did_common::Document,
) -> Result<(), EbsiError> {
    if document.id.as_str() == did {
        Ok(())
    } else {
        Err(EbsiError::DocumentIdMismatch {
            expected: did.to_string(),
            got: document.id.as_str().to_string(),
        })
    }
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
    fn verify_document_id_accepts_a_match() {
        let document = affinidi_did_common::Document::new("did:ebsi:zfEmvX5twhXjQJiCWsukvQA")
            .expect("valid did:ebsi document id");
        assert!(verify_document_id("did:ebsi:zfEmvX5twhXjQJiCWsukvQA", &document).is_ok());
    }

    #[test]
    fn verify_document_id_refuses_a_mismatch() {
        // The registry answering for one did:ebsi must not be able to hand
        // back a document that names a different one.
        let document = affinidi_did_common::Document::new("did:ebsi:znHeZWvhAK2FK2Dk1jXNe7m")
            .expect("valid did:ebsi document id");
        let err = verify_document_id("did:ebsi:zfEmvX5twhXjQJiCWsukvQA", &document).unwrap_err();
        assert!(
            matches!(
                err,
                EbsiError::DocumentIdMismatch { ref expected, ref got }
                    if expected == "did:ebsi:zfEmvX5twhXjQJiCWsukvQA"
                        && got == "did:ebsi:znHeZWvhAK2FK2Dk1jXNe7m"
            ),
            "{err:?}"
        );
    }

    /// `Document::id` has no `#[serde(default)]`, so a document missing `id`
    /// entirely is already refused by deserialization, before
    /// `verify_document_id` is ever reached.
    #[test]
    fn document_without_id_fails_to_parse() {
        let err =
            serde_json::from_str::<affinidi_did_common::Document>(r#"{"service":[]}"#).unwrap_err();
        assert!(err.to_string().contains("id"), "{err}");
    }

    #[test]
    fn decode_known_did_structure() {
        // did:ebsi:zfEmvX5twhXjQJiCWsukvQA
        let identifier = "zfEmvX5twhXjQJiCWsukvQA";
        let decoded = bs58::decode(&identifier[1..]).into_vec().unwrap();

        assert_eq!(decoded.len(), 17); // 1 version + 16 random
        assert_eq!(decoded[0], 0x01); // Version byte
    }

    /// A local server that answers every request with `head`, then
    /// `body_chunk` repeated `repeat` times as chunked transfer encoding
    /// (forever when `repeat` is `None`), then the terminating chunk.
    async fn serve(head: &'static str, body_chunk: Vec<u8>, repeat: Option<usize>) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                let body_chunk = body_chunk.clone();
                tokio::spawn(async move {
                    let mut request = Vec::new();
                    let mut buffer = [0u8; 1024];
                    while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                        match socket.read(&mut buffer).await {
                            Ok(0) | Err(_) => return,
                            Ok(read) => request.extend_from_slice(&buffer[..read]),
                        }
                    }
                    if socket.write_all(head.as_bytes()).await.is_err() {
                        return;
                    }
                    let mut chunk = format!("{:x}\r\n", body_chunk.len()).into_bytes();
                    chunk.extend_from_slice(&body_chunk);
                    chunk.extend_from_slice(b"\r\n");
                    let mut sent = 0;
                    while repeat.is_none_or(|limit| sent < limit) {
                        if socket.write_all(&chunk).await.is_err() {
                            return;
                        }
                        sent += 1;
                    }
                    let _ = socket.write_all(b"0\r\n\r\n").await;
                });
            }
        });
        format!("http://{address}")
    }

    const CHUNKED: &str = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n";
    const DID: &str = "did:ebsi:zfEmvX5twhXjQJiCWsukvQA";

    #[tokio::test]
    async fn a_chunked_document_within_the_limit_resolves() {
        let document = format!(r#"{{"id":"{DID}"}}"#).into_bytes();
        let api_base = serve(CHUNKED, document, Some(1)).await;
        let resolved = resolve_ebsi_did(DID, &api_base).await.unwrap();
        assert_eq!(resolved.id.as_str(), DID);
    }

    #[tokio::test]
    async fn a_body_without_a_content_length_stops_at_the_limit() {
        let api_base = serve(CHUNKED, vec![b' '; 64 * 1024], None).await;
        let err = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            resolve_ebsi_did(DID, &api_base),
        )
        .await
        .expect("reading must stop at the limit, not run until the request timeout")
        .unwrap_err();
        assert!(err.to_string().contains("limit"), "{err}");
    }

    #[tokio::test]
    async fn a_declared_length_over_the_limit_is_refused_before_reading() {
        let api_base = serve(
            "HTTP/1.1 200 OK\r\nContent-Length: 1073741824\r\n\r\n",
            Vec::new(),
            Some(0),
        )
        .await;
        let err = resolve_ebsi_did(DID, &api_base).await.unwrap_err();
        assert!(err.to_string().contains("declares"), "{err}");
    }
}

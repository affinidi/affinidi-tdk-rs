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
 *
 * # Usage
 *
 * Hold an [`EbsiResolver`] for repeated lookups, so its HTTP client and
 * connection pool are reused:
 *
 * ```no_run
 * # async fn run() -> Result<(), did_ebsi::EbsiError> {
 * let resolver = did_ebsi::EbsiResolver::new(did_ebsi::EBSI_PILOT_API)?;
 * let document = resolver.resolve("did:ebsi:zfEmvX5twhXjQJiCWsukvQA").await?;
 * # Ok(()) }
 * ```
 */

use affinidi_did_common::{Document, NetworkError};
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

    /// The registry answered with an unsuccessful HTTP status. The status,
    /// the URL and the registry's `Retry-After` are kept as data, so a
    /// caller can tell a rate limit (HTTP 429) from a DID that is not
    /// registered (HTTP 404).
    #[error("{0}")]
    Network(NetworkError),

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

/// Default request timeout.
pub const DEFAULT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(20);

/// A did:ebsi resolver: a reusable HTTP client and the registry API it asks.
///
/// The client never follows a redirect: the registry is the trust anchor, and
/// a 3xx would let it (or anything on-path) send the resolver to an arbitrary
/// address and serve a forged document from there.
#[derive(Debug, Clone)]
pub struct EbsiResolver {
    client: reqwest::Client,
    api_base: String,
}

impl EbsiResolver {
    /// A resolver for the registry at `api_base` ([`EBSI_PILOT_API`] or
    /// [`EBSI_CONFORMANCE_API`]) with the default client ([`DEFAULT_TIMEOUT`]).
    ///
    /// # Errors
    /// [`EbsiError::Http`] if the HTTP client cannot be built.
    pub fn new(api_base: impl Into<String>) -> Result<Self, EbsiError> {
        let builder = reqwest::Client::builder()
            .user_agent(concat!("affinidi-did-ebsi/", env!("CARGO_PKG_VERSION")))
            .timeout(DEFAULT_TIMEOUT);
        Self::with_client_builder(builder, api_base)
    }

    /// A resolver over a client the caller configures (timeouts, headers,
    /// TLS, proxy, connection pool). Set a timeout on `builder`: none is
    /// added. Redirects are turned off after the caller's settings, so
    /// nothing set on `builder` turns them back on.
    ///
    /// # Errors
    /// [`EbsiError::Http`] if the HTTP client cannot be built.
    pub fn with_client_builder(
        builder: reqwest::ClientBuilder,
        api_base: impl Into<String>,
    ) -> Result<Self, EbsiError> {
        let client = builder
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| EbsiError::Http(format!("building HTTP client: {e}")))?;
        Ok(Self {
            client,
            api_base: api_base.into(),
        })
    }

    /// The registry API this resolver asks.
    pub fn api_base(&self) -> &str {
        &self.api_base
    }

    /// Resolve a did:ebsi identifier via the registry, returning its DID
    /// document.
    ///
    /// # Errors
    /// [`EbsiError::InvalidDid`] for a malformed DID; [`EbsiError::Network`]
    /// when the registry answers with an unsuccessful status;
    /// [`EbsiError::Http`] when no answer arrives or the body is over
    /// [`MAX_DOCUMENT_BYTES`]; [`EbsiError::ParseError`] when the body is not
    /// a DID document; [`EbsiError::DocumentIdMismatch`] when it is another
    /// DID's.
    pub async fn resolve(&self, did: &str) -> Result<Document, EbsiError> {
        // Validate before interpolating into the URL: a did:ebsi
        // method-specific id is base58btc, so once validated it can only
        // contain [1-9A-HJ-NP-Za-km-z] and cannot inject `/`, `?`, `#`, `..`
        // etc. into the request path.
        let identifier = did
            .strip_prefix("did:ebsi:")
            .ok_or_else(|| EbsiError::InvalidDid("must start with did:ebsi:".into()))?;
        validate_ebsi_identifier(identifier)?;

        let url = format!("{}/did:ebsi:{identifier}", self.api_base);
        fetch_document(&self.client, did, &url).await
    }
}

/// Resolve a did:ebsi identifier via the EBSI DID Registry API.
///
/// Makes an HTTP GET request to the specified API endpoint and returns the
/// [`Document`] it serves, after checking that it is the document of `did`.
/// Builds a client for the one call; hold an [`EbsiResolver`] to reuse one.
///
/// # Arguments
///
/// * `did` - The full DID string (e.g., "did:ebsi:zfEmvX5twhXjQJiCWsukvQA")
/// * `api_base` - The API base URL (use `EBSI_PILOT_API` or `EBSI_CONFORMANCE_API`)
///
/// # Errors
/// As [`EbsiResolver::resolve`].
pub async fn resolve_ebsi_did(did: &str, api_base: &str) -> Result<Document, EbsiError> {
    EbsiResolver::new(api_base)?.resolve(did).await
}

async fn fetch_document(
    client: &reqwest::Client,
    did: &str,
    url: &str,
) -> Result<Document, EbsiError> {
    let mut response = client
        .get(url)
        .send()
        .await
        .map_err(|e| EbsiError::Http(format!("GET {url}: {e}")))?;

    let status = response.status();
    if !status.is_success() {
        let retry_after = response
            .headers()
            .get(reqwest::header::RETRY_AFTER)
            .and_then(|value| value.to_str().ok());
        return Err(EbsiError::Network(
            NetworkError::new(format!("HTTP {status}"))
                .with_url(url)
                .with_status(status.as_u16())
                .with_retry_after_header(retry_after),
        ));
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

    // A relative id or reference (`"#key-1"`) is legal in a DID document; it
    // is resolved against the document's `id`, which must be `did`.
    let document = Document::from_json_slice(&body)
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

/// did:ebsi as an `affinidi-did-resolver-traits`
/// [`AsyncResolver`](affinidi_did_resolver_traits::AsyncResolver).
#[cfg(feature = "resolver-traits")]
mod resolver_impl {
    use std::future::Future;
    use std::pin::Pin;

    use affinidi_did_common::{DID, DIDMethod};
    use affinidi_did_resolver_traits::{
        AsyncResolver, NetworkFetchError, Resolution, ResolverError,
    };

    use crate::{EbsiError, EbsiResolver};

    /// The [`ResolverError`] for a failed did:ebsi resolution: an
    /// unsuccessful registry status (with its URL and `Retry-After`) and a
    /// transport failure are [`ResolverError::NetworkFetch`], everything else
    /// [`ResolverError::ResolutionFailed`].
    pub(crate) fn resolver_error(err: EbsiError) -> ResolverError {
        match err {
            EbsiError::Network(network) => ResolverError::from(network),
            EbsiError::Http(message) => {
                ResolverError::NetworkFetch(NetworkFetchError::new(message))
            }
            other => ResolverError::ResolutionFailed(other.to_string()),
        }
    }

    /// Resolves did:ebsi against the resolver's registry, and declines
    /// (`None`) every other method. A DID URL resolves to the document of
    /// its DID.
    impl AsyncResolver for EbsiResolver {
        fn name(&self) -> &str {
            "EbsiResolver"
        }

        fn resolve<'a>(
            &'a self,
            did: &'a DID,
        ) -> Pin<Box<dyn Future<Output = Resolution> + Send + 'a>> {
            Box::pin(async move {
                if !matches!(did.method_ref(), DIDMethod::Ebsi { .. }) {
                    return None;
                }
                let bare = format!("did:ebsi:{}", did.method_specific_id_ref());
                Some(
                    EbsiResolver::resolve(self, &bare)
                        .await
                        .map_err(resolver_error),
                )
            })
        }
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
    async fn an_unsuccessful_status_is_kept_as_data() {
        let api_base = serve(
            "HTTP/1.1 429 Too Many Requests\r\nRetry-After: 7\r\nTransfer-Encoding: chunked\r\n\r\n",
            Vec::new(),
            Some(0),
        )
        .await;
        let err = resolve_ebsi_did(DID, &api_base).await.unwrap_err();
        let EbsiError::Network(network) = &err else {
            panic!("expected EbsiError::Network, got {err:?}");
        };
        assert!(network.is_rate_limited());
        assert_eq!(network.retry_after, Some(std::time::Duration::from_secs(7)));
        assert_eq!(
            network.url.as_deref(),
            Some(format!("{api_base}/{DID}").as_str())
        );
    }

    #[tokio::test]
    async fn a_resolver_is_reused_across_lookups() {
        let document = format!(r#"{{"id":"{DID}"}}"#).into_bytes();
        let api_base = serve(CHUNKED, document, Some(1)).await;
        let resolver = EbsiResolver::new(&api_base).unwrap();
        assert_eq!(resolver.api_base(), api_base);
        for _ in 0..2 {
            assert_eq!(resolver.resolve(DID).await.unwrap().id.as_str(), DID);
        }
    }

    #[cfg(feature = "resolver-traits")]
    #[tokio::test]
    async fn the_resolver_trait_resolves_ebsi_and_declines_other_methods() {
        use affinidi_did_common::DID as ParsedDid;
        use affinidi_did_resolver_traits::{AsyncResolver, ResolverError};

        let document = format!(r#"{{"id":"{DID}"}}"#).into_bytes();
        let resolver = EbsiResolver::new(serve(CHUNKED, document, Some(1)).await).unwrap();
        assert_eq!(AsyncResolver::name(&resolver), "EbsiResolver");
        let did: ParsedDid = format!("{DID}#key-1").parse().unwrap();
        let resolved = AsyncResolver::resolve(&resolver, &did)
            .await
            .expect("handled")
            .expect("resolves");
        assert_eq!(resolved.id.as_str(), DID);
        let web: ParsedDid = "did:web:example.com".parse().unwrap();
        assert!(AsyncResolver::resolve(&resolver, &web).await.is_none());

        let limited = EbsiResolver::new(
            serve(
                "HTTP/1.1 429 Too Many Requests\r\nRetry-After: 7\r\nTransfer-Encoding: chunked\r\n\r\n",
                Vec::new(),
                Some(0),
            )
            .await,
        )
        .unwrap();
        let Some(Err(ResolverError::NetworkFetch(fetch))) =
            AsyncResolver::resolve(&limited, &did).await
        else {
            panic!("a 429 is a network fetch failure");
        };
        assert!(fetch.is_rate_limited());
    }

    #[tokio::test]
    async fn a_document_with_relative_ids_resolves() {
        let document = format!(
            r##"{{"id":"{DID}","verificationMethod":[{{"id":"#key-1","type":"JsonWebKey2020","controller":"{DID}"}}],"assertionMethod":["#key-1"]}}"##
        )
        .into_bytes();
        let api_base = serve(CHUNKED, document, Some(1)).await;
        let resolved = resolve_ebsi_did(DID, &api_base).await.unwrap();
        assert_eq!(
            resolved.verification_method[0].id.as_str(),
            format!("{DID}#key-1")
        );
        assert_eq!(
            resolved.assertion_method[0].get_id(),
            format!("{DID}#key-1")
        );
    }

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

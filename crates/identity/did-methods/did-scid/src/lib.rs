/*! Implementation of the `did:scid` (Self-Certifying Identifier) DID method.
 *
 * Supported sub-methods:
 *   - `did:scid:vh:1` — Verifiable History via did:webvh or did:cheqd
 *
 * Two invocation modes are supported:
 *   - **URL mode**: `did:scid:vh:1:<scid>?src=<source>` — the `src` parameter
 *     encodes either a `did:cheqd:<network>` prefix or a WebVH host/path.
 *   - **Peer mode**: `did:scid:vh:1:<scid>` with the source supplied
 *     out-of-band via [`ScidMethod`].
 *
 * ### WebVH `src` formats accepted
 *
 * The `src` parameter for WebVH is intentionally permissive — any of the
 * following are normalised to the canonical did:webvh tail:
 *
 *   - `example.com`
 *   - `example.com/path/to/dir`
 *   - `localhost:3000` / `localhost:3000/path` (the port is `%3A`-encoded)
 *   - `https://example.com/path` (scheme is stripped)
 *   - Any of the above with a trailing slash
 */

use crate::errors::DIDSCIDError;
use affinidi_did_common::Document;
use didwebvh_rs::{DIDWebVHState, log_entry::LogEntryMethods};
use regex::Regex;
use std::sync::LazyLock;
use std::time::Duration;
use tracing::{debug, error};

pub mod errors;

static SCID_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^did:scid:vh:1:([^\?]*)(?:\?src=(.*))?$").unwrap());

#[derive(Clone, Debug)]
pub enum ScidMethod {
    WebVH(String),

    #[cfg(feature = "did-cheqd")]
    Cheqd(String),
}

/// Resolve a SCID DID Method
///
/// * `did` — the `did:scid:vh:1:...` identifier to resolve.
/// * `peer_src` — out-of-band source when `did` has no `?src=` query (peer mode):
///   - [`ScidMethod::WebVH`]: host/path string. Accepts the same formats as
///     URL-mode `src` (see `normalize_webvh_src`) — bare host, host with port,
///     optional scheme/trailing slash, etc.
///   - [`ScidMethod::Cheqd`]: the network name (`mainnet` or `testnet`).
/// * `timeout` — optional resolution timeout.
pub async fn resolve(
    did: &str,
    peer_src: Option<ScidMethod>,
    timeout: Option<Duration>,
) -> Result<Document, DIDSCIDError> {
    if did.starts_with("did:scid:vh:1") {
        // Implement the resolution logic here
        match convert_scid_to_method(did, peer_src)? {
            ScidMethod::WebVH(webvh_did) => {
                debug!("Resolving WebVH DID: {}", webvh_did);
                let mut method = DIDWebVHState::default();
                match method
                    .resolve(
                        &webvh_did,
                        didwebvh_rs::resolve::ResolveOptions {
                            timeout,
                            ..Default::default()
                        },
                    )
                    .await
                {
                    Ok((log_entry, _)) => {
                        Ok(serde_json::from_value(log_entry.get_did_document()?)?)
                    }
                    Err(e) => {
                        error!("Error: {:?}", e);
                        Err(DIDSCIDError::WebVHError(e))
                    }
                }
            }
            #[cfg(feature = "did-cheqd")]
            ScidMethod::Cheqd(cheqd_did) => {
                use did_resolver_cheqd::DIDCheqd;
                use ssi_dids_core::{DID, DIDResolver};

                debug!("Resolving Cheqd DID: {}", cheqd_did);
                let parsed = DID::new::<str>(&cheqd_did).map_err(|e| {
                    DIDSCIDError::DidUrlError(format!(
                        "derived cheqd DID is not a valid DID ({cheqd_did}): {e}"
                    ))
                })?;
                match DIDCheqd::default().resolve(parsed).await {
                    Ok(res) => {
                        let doc_value = serde_json::to_value(res.document.into_document())?;
                        Ok(serde_json::from_value(doc_value)?)
                    }
                    Err(e) => {
                        error!("Error: {:?}", e);
                        Err(DIDSCIDError::CheqdError(e.to_string()))
                    }
                }
            }
        }
    } else {
        Err(DIDSCIDError::UnsupportedFormat)
    }
}

/// Derive a `did:cheqd` method DID from a URL-mode `?src=did:cheqd:...` source.
///
/// `did-cheqd` is optional because `did-resolver-cheqd` forces the rustls `ring`
/// TLS backend (via `tonic 0.12`); see the crate's feature docs. When the
/// feature is disabled this returns a clear error instead of failing to compile.
#[cfg(feature = "did-cheqd")]
fn derive_cheqd_url(src: &str, scid: &str) -> Result<ScidMethod, DIDSCIDError> {
    let cheqd = format!("{src}:{scid}");
    debug!("derived cheqd DID: {cheqd}");
    Ok(ScidMethod::Cheqd(cheqd))
}

#[cfg(not(feature = "did-cheqd"))]
fn derive_cheqd_url(_src: &str, _scid: &str) -> Result<ScidMethod, DIDSCIDError> {
    Err(DIDSCIDError::CheqdError(
        "did:cheqd source requires the `did-cheqd` feature".to_string(),
    ))
}

/// Converts a SCID DID to a valid Method DID Identifier
/// peer_src: Optional meta_data if operating in peer mode
fn convert_scid_to_method(
    id: &str,
    peer_src: Option<ScidMethod>,
) -> Result<ScidMethod, DIDSCIDError> {
    let Some(caps) = SCID_RE.captures(id) else {
        return Err(DIDSCIDError::UnsupportedFormat);
    };

    let scid = &caps[1];

    if let Some(src) = caps.get(2).map(|m| m.as_str()) {
        if src.starts_with("did:cheqd:") {
            derive_cheqd_url(src, scid)
        } else if src.starts_with("did:") {
            Err(DIDSCIDError::UnsupportedFormat)
        } else {
            let tail = normalize_webvh_src(src)?;
            let webvh = format!("did:webvh:{scid}:{tail}");
            debug!("derived webvh DID: {webvh}");
            Ok(ScidMethod::WebVH(webvh))
        }
    } else {
        // Peer Mode — caller supplies the source out-of-band.
        match peer_src {
            Some(ScidMethod::WebVH(src)) => {
                let tail = normalize_webvh_src(&src)?;
                let webvh = format!("did:webvh:{scid}:{tail}");
                debug!("derived peer webvh DID: {webvh}");
                Ok(ScidMethod::WebVH(webvh))
            }
            #[cfg(feature = "did-cheqd")]
            Some(ScidMethod::Cheqd(src)) => {
                let cheqd = format!("did:cheqd:{src}:{scid}");
                debug!("derived peer cheqd DID: {cheqd}");
                Ok(ScidMethod::Cheqd(cheqd))
            }
            None => Err(DIDSCIDError::MissingPeerSource),
        }
    }
}

/// Normalises a WebVH `src` (URL-style or partial) into a did:webvh method tail.
///
/// Accepts:
///   - bare host:           `example.com`
///   - host with port:      `localhost:3000`
///   - host + path:         `example.com/path/seg`
///   - scheme prefix:       `https://example.com/path` (scheme is stripped)
///   - trailing slash:      `example.com/` (slash is trimmed)
///
/// Per the did:webvh spec, a colon in `host:port` is encoded as `%3A`, while
/// `/` in the path is mapped to `:`. Already-encoded `%3A` in the input is
/// preserved.
fn normalize_webvh_src(src: &str) -> Result<String, DIDSCIDError> {
    let stripped = src
        .strip_prefix("https://")
        .or_else(|| src.strip_prefix("http://"))
        .unwrap_or(src);

    let stripped = stripped.trim_end_matches('/');
    if stripped.is_empty() {
        return Err(DIDSCIDError::InvalidSrc(
            "source is empty after stripping scheme/slashes".to_string(),
        ));
    }

    let (host, path) = match stripped.split_once('/') {
        Some((h, p)) => (h, Some(p)),
        None => (stripped, None),
    };

    if host.is_empty() {
        return Err(DIDSCIDError::InvalidSrc(
            "missing host component".to_string(),
        ));
    }

    let host_encoded = match host.split_once(':') {
        Some((h, port)) => {
            if h.is_empty() {
                return Err(DIDSCIDError::InvalidSrc(
                    "missing host component before port".to_string(),
                ));
            }
            port.parse::<u16>()
                .map_err(|_| DIDSCIDError::InvalidSrc(format!("invalid port in host {host:?}")))?;
            format!("{h}%3A{port}")
        }
        None => host.to_string(),
    };

    let mut out = host_encoded;
    if let Some(path) = path {
        let path = path.trim_end_matches('/');
        if !path.is_empty() {
            out.push(':');
            out.push_str(&path.replace('/', ":"));
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use crate::{convert_scid_to_method, errors::DIDSCIDError, normalize_webvh_src, resolve};

    // -- normalize_webvh_src ------------------------------------------------

    #[test]
    fn normalize_bare_host() {
        assert_eq!(normalize_webvh_src("example.com").unwrap(), "example.com");
    }

    #[test]
    fn normalize_host_with_path() {
        assert_eq!(
            normalize_webvh_src("example.com/a/b/c").unwrap(),
            "example.com:a:b:c",
        );
    }

    #[test]
    fn normalize_host_with_port() {
        assert_eq!(
            normalize_webvh_src("localhost:3000").unwrap(),
            "localhost%3A3000",
        );
    }

    #[test]
    fn normalize_host_with_port_and_path() {
        assert_eq!(
            normalize_webvh_src("localhost:3000/path/to/dir").unwrap(),
            "localhost%3A3000:path:to:dir",
        );
    }

    #[test]
    fn normalize_strips_https_scheme() {
        assert_eq!(
            normalize_webvh_src("https://localhost:3000/path").unwrap(),
            "localhost%3A3000:path",
        );
    }

    #[test]
    fn normalize_strips_http_scheme() {
        assert_eq!(
            normalize_webvh_src("http://example.com/").unwrap(),
            "example.com",
        );
    }

    #[test]
    fn normalize_trims_trailing_slash() {
        assert_eq!(normalize_webvh_src("example.com/").unwrap(), "example.com",);
        assert_eq!(
            normalize_webvh_src("https://localhost:3000/").unwrap(),
            "localhost%3A3000",
        );
    }

    #[test]
    fn normalize_preserves_existing_percent_3a() {
        // Already-encoded port should pass through unchanged.
        assert_eq!(
            normalize_webvh_src("localhost%3A3000/path").unwrap(),
            "localhost%3A3000:path",
        );
    }

    #[test]
    fn normalize_rejects_empty() {
        assert!(matches!(
            normalize_webvh_src(""),
            Err(DIDSCIDError::InvalidSrc(_))
        ));
        assert!(matches!(
            normalize_webvh_src("https:///"),
            Err(DIDSCIDError::InvalidSrc(_))
        ));
    }

    #[test]
    fn normalize_rejects_bad_port() {
        assert!(matches!(
            normalize_webvh_src("localhost:notaport/x"),
            Err(DIDSCIDError::InvalidSrc(_))
        ));
        assert!(matches!(
            normalize_webvh_src("localhost:999999"),
            Err(DIDSCIDError::InvalidSrc(_))
        ));
    }

    // -- convert_scid_to_method via URL mode -------------------------------

    #[test]
    fn url_mode_with_port_encodes_colon() {
        match convert_scid_to_method("did:scid:vh:1:abcde?src=localhost:3000/path", None) {
            Ok(crate::ScidMethod::WebVH(did)) => {
                assert_eq!(did, "did:webvh:abcde:localhost%3A3000:path")
            }
            other => panic!("Incorrect conversion: {other:?}"),
        }
    }

    #[test]
    fn url_mode_with_scheme_strips_it() {
        match convert_scid_to_method("did:scid:vh:1:abcde?src=https://localhost:3000/path", None) {
            Ok(crate::ScidMethod::WebVH(did)) => {
                assert_eq!(did, "did:webvh:abcde:localhost%3A3000:path")
            }
            other => panic!("Incorrect conversion: {other:?}"),
        }
    }

    #[test]
    fn url_mode_with_trailing_slash() {
        match convert_scid_to_method("did:scid:vh:1:abcde?src=example.com/", None) {
            Ok(crate::ScidMethod::WebVH(did)) => {
                assert_eq!(did, "did:webvh:abcde:example.com")
            }
            other => panic!("Incorrect conversion: {other:?}"),
        }
    }

    // -- peer mode normalisation -------------------------------------------

    #[test]
    fn peer_mode_with_port_url() {
        match convert_scid_to_method(
            "did:scid:vh:1:abcde",
            Some(crate::ScidMethod::WebVH(
                "https://localhost:3000/path".to_string(),
            )),
        ) {
            Ok(crate::ScidMethod::WebVH(did)) => {
                assert_eq!(did, "did:webvh:abcde:localhost%3A3000:path")
            }
            other => panic!("Incorrect conversion: {other:?}"),
        }
    }

    // -- prefix tightening / robustness ------------------------------------

    #[test]
    fn rejects_cheqd_lookalike_prefix() {
        // "did:cheqdXYZ" must NOT be treated as a cheqd source.
        match convert_scid_to_method("did:scid:vh:1:abcde?src=did:cheqdXYZ:mainnet", None) {
            Err(DIDSCIDError::UnsupportedFormat) => {}
            other => panic!("Expected UnsupportedFormat, got: {other:?}"),
        }
    }

    // -- pre-existing happy paths ------------------------------------------

    #[cfg(feature = "did-cheqd")]
    #[test]
    fn test_cheqd_conversion() {
        match convert_scid_to_method("did:scid:vh:1:abcde?src=did:cheqd:mainnet", None) {
            Ok(crate::ScidMethod::Cheqd(did)) => assert_eq!(did, "did:cheqd:mainnet:abcde"),
            _ => panic!("Incorrect conversion"),
        }
    }

    #[cfg(feature = "did-cheqd")]
    #[test]
    fn test_cheqd_peer_conversion() {
        match convert_scid_to_method(
            "did:scid:vh:1:abcde",
            Some(crate::ScidMethod::Cheqd("mainnet".to_string())),
        ) {
            Ok(crate::ScidMethod::Cheqd(did)) => assert_eq!(did, "did:cheqd:mainnet:abcde"),
            _ => panic!("Incorrect conversion"),
        }
    }

    #[test]
    fn test_webvh_conversion() {
        match convert_scid_to_method(
            "did:scid:vh:1:abcde?src=stormer78.github.io/identity/fpp",
            None,
        ) {
            Ok(crate::ScidMethod::WebVH(did)) => {
                assert_eq!(did, "did:webvh:abcde:stormer78.github.io:identity:fpp")
            }
            _ => panic!("Incorrect conversion"),
        }
    }

    #[test]
    fn test_webvhpeer_conversion() {
        match convert_scid_to_method(
            "did:scid:vh:1:abcde",
            Some(crate::ScidMethod::WebVH("stormer78.github.io".to_string())),
        ) {
            Ok(crate::ScidMethod::WebVH(did)) => {
                assert_eq!(did, "did:webvh:abcde:stormer78.github.io")
            }
            _ => panic!("Incorrect conversion"),
        }
    }

    #[test]
    fn test_missing_peer() {
        match convert_scid_to_method("did:scid:vh:1:abcde", None) {
            Err(DIDSCIDError::MissingPeerSource) => {}
            _ => panic!("Incorrect conversion"),
        }
    }

    #[test]
    fn test_bad_did_method() {
        match convert_scid_to_method("did:scid:vh:1:abcde?src=did:example:abcd", None) {
            Err(DIDSCIDError::UnsupportedFormat) => {}
            _ => panic!("Incorrect conversion"),
        }
    }

    #[test]
    fn test_bad_id() {
        match convert_scid_to_method("did:scid:invalid:1:abcde?src=did:example:abcd", None) {
            Err(DIDSCIDError::UnsupportedFormat) => {}
            _ => panic!("Incorrect conversion"),
        }
    }

    #[tokio::test]
    #[ignore = "requires external network (identity.foundation)"]
    async fn test_scid_webvh_resolution() {
        match resolve("did:scid:vh:1:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai?src=identity.foundation/didwebvh-implementations/implementations/affinidi-didwebvh-rs", None, None).await {
            Ok(doc) => {
                assert_eq!(doc.id.as_str(), "did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs");
            }
            Err(_) => panic!("Couldn't resolve SCID WebVH DID")
        }
    }

    #[cfg(feature = "did-cheqd")]
    #[tokio::test]
    #[ignore = "requires external network (cheqd.net)"]
    async fn test_scid_cheqd_resolution() {
        match resolve(
            "did:scid:vh:1:cad53e1d-71e0-48d2-9352-39cc3d0fac99?src=did:cheqd:testnet",
            None,
            None,
        )
        .await
        {
            Ok(doc) => {
                assert_eq!(
                    doc.id.as_str(),
                    "did:cheqd:testnet:cad53e1d-71e0-48d2-9352-39cc3d0fac99"
                );
            }
            Err(_) => panic!("Couldn't resolve SCID Cheqd DID"),
        }
    }
}

/*! Implementation of the `did:scid` (Self-Certifying Identifier) DID method.
 *
 * Supported formats:
 *   - `did:scid:vh:1` — Verifiable History via did:webvh or did:cheqd
 *   - `did:scid:ke:1` — a KERI AID via did:webs (requires the `did-webs`
 *     feature)
 *
 * ⚠️ The did:scid method type registry (Appendix A of the specification) is
 * still marked TODO, and `ke` is listed there as a *proposed* entry rather
 * than a registered one. It is implemented here because did:webs is named
 * explicitly as a supported verification metadata format, but the code could
 * still change before the registry is settled.
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

/// `did:scid:<format>:<version>:<scid>[?src=<source>]`
///
/// The format name is two characters by convention and the version is one or
/// more digits; both are captured rather than hard-coded so an unknown format
/// produces a clear error instead of failing to match at all.
static SCID_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^did:scid:([a-z0-9]+):([0-9]+):([^\?]*)(?:\?src=(.*))?$").unwrap()
});

/// The verification metadata format a `did:scid` resolves through.
///
/// `#[non_exhaustive]`: the did:scid method type registry is still open — see
/// the note on [`resolve`] — so more formats are expected.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum ScidMethod {
    WebVH(String),

    /// `did:webs` — a KERI AID with its key event log published on the web.
    Webs(String),

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
    // No prefix test here: `convert_scid_to_method` matches the whole
    // `did:scid:<format>:<version>:<scid>` shape and reports an unknown format
    // or version by name. A `starts_with("did:scid:vh:1")` gate used to sit in
    // front of it, which made every format other than `vh` unreachable through
    // this function no matter what the conversion supported.
    match convert_scid_to_method(did, peer_src)? {
        ScidMethod::WebVH(webvh_did) => {
            debug!("Resolving WebVH DID: {webvh_did}");
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
                Ok((log_entry, _)) => Ok(serde_json::from_value(log_entry.get_did_document()?)?),
                Err(e) => {
                    error!("Error: {e:?}");
                    Err(DIDSCIDError::WebVHError(e))
                }
            }
        }
        ScidMethod::Webs(webs_did) => resolve_webs(&webs_did).await,
        // Retired in 0.2.6. The `did:cheqd` shape still parses and this arm still
        // exists, so nothing a consumer named has gone away — only the
        // implementation. It came from `did-resolver-cheqd`, a crate with no
        // published source repository and a single 2025 release, which pinned
        // `ssi-dids-core 0.1` and pulled eight advisories (including an h2 DoS)
        // into the lockfile. Register your own resolver for the method if you
        // need it; see the CHANGELOG.
        #[cfg(feature = "did-cheqd")]
        ScidMethod::Cheqd(cheqd_did) => {
            debug!("did:cheqd resolution is retired; refusing {cheqd_did}");
            Err(DIDSCIDError::CheqdError(format!(
                "did:cheqd resolution was retired in did-scid 0.2.6 and this crate no longer \
                 resolves {cheqd_did}; register your own resolver for the method"
            )))
        }
    }
}

/// Derive a `did:cheqd` method DID from a URL-mode `?src=did:cheqd:...` source.
///
/// `did-cheqd` is now an inert feature: it gates the `did:cheqd` *shape* only.
/// Resolution was retired in 0.2.6 (see `resolve`), so enabling it changes what
/// parses, not what resolves. When the feature is disabled this returns a clear
/// error instead of failing to compile.
#[cfg(feature = "did-cheqd")]
fn derive_cheqd_url(src: &str, scid: &str) -> Result<ScidMethod, DIDSCIDError> {
    let cheqd = format!("{src}:{scid}");
    debug!("derived cheqd DID: {cheqd}");
    Ok(ScidMethod::Cheqd(cheqd))
}

/// Resolve a derived `did:webs` DID.
#[cfg(feature = "did-webs")]
async fn resolve_webs(webs_did: &str) -> Result<Document, DIDSCIDError> {
    debug!("Resolving Webs DID: {webs_did}");
    affinidi_did_webs::resolve(webs_did).await.map_err(|e| {
        error!("did:webs resolution error: {e:?}");
        DIDSCIDError::WebsError(e.to_string())
    })
}

/// `did-webs` is optional so that `did-scid` does not pull the KERI stack into
/// builds that never resolve `did:scid:ke`. Without the feature the format is
/// still parsed — so the error says what is missing rather than looking like a
/// malformed DID.
#[cfg(not(feature = "did-webs"))]
async fn resolve_webs(_webs_did: &str) -> Result<Document, DIDSCIDError> {
    Err(DIDSCIDError::WebsError(
        "did:scid:ke resolution requires the `did-webs` feature".to_string(),
    ))
}

#[cfg(not(feature = "did-cheqd"))]
fn derive_cheqd_url(_src: &str, _scid: &str) -> Result<ScidMethod, DIDSCIDError> {
    Err(DIDSCIDError::CheqdError(
        "did:cheqd source requires the `did-cheqd` feature".to_string(),
    ))
}

/// The did:scid format names this implementation understands.
///
/// Two characters by convention, per the specification. `vh` is did:webvh; `ke`
/// is did:webs.
const FORMAT_WEBVH: &str = "vh";
const FORMAT_WEBS: &str = "ke";

/// Converts a SCID DID to a valid Method DID Identifier
/// peer_src: Optional meta_data if operating in peer mode
fn convert_scid_to_method(
    id: &str,
    peer_src: Option<ScidMethod>,
) -> Result<ScidMethod, DIDSCIDError> {
    let Some(caps) = SCID_RE.captures(id) else {
        return Err(DIDSCIDError::UnsupportedFormat);
    };

    let format = &caps[1];
    let version = &caps[2];
    let scid = &caps[3];

    if version != "1" {
        return Err(DIDSCIDError::UnsupportedVersion(format!(
            "format {format:?} version {version:?}"
        )));
    }

    match format {
        FORMAT_WEBVH => convert_webvh(scid, caps.get(4).map(|m| m.as_str()), peer_src),
        FORMAT_WEBS => convert_webs(scid, caps.get(4).map(|m| m.as_str()), peer_src),
        other => Err(DIDSCIDError::UnknownFormat(other.to_string())),
    }
}

/// `did:scid:vh:1:<scid>` — did:webvh, or did:cheqd via a DID-valued source.
fn convert_webvh(
    scid: &str,
    src: Option<&str>,
    peer_src: Option<ScidMethod>,
) -> Result<ScidMethod, DIDSCIDError> {
    if let Some(src) = src {
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
            Some(other) => Err(DIDSCIDError::InvalidSrc(format!(
                "did:scid:vh cannot resolve through {other:?}"
            ))),
            None => Err(DIDSCIDError::MissingPeerSource),
        }
    }
}

/// `did:scid:ke:1:<AID>` — did:webs.
///
/// ⚠️ The SCID lands in a **different position** than it does for did:webvh.
/// `did:webvh` puts it first (`did:webvh:<scid>:<host>:<path>`), while
/// `did:webs` puts the AID **last** (`did:webs:<host>:<path>:<AID>`), because
/// the AID is the final path element of the URL the artifacts are served from.
/// Reusing the webvh formatting here would silently produce a DID that
/// resolves to the wrong location.
fn convert_webs(
    scid: &str,
    src: Option<&str>,
    peer_src: Option<ScidMethod>,
) -> Result<ScidMethod, DIDSCIDError> {
    let source = match (src, peer_src) {
        (Some(src), _) => {
            if src.starts_with("did:") {
                // A DID-valued source names a method that stores the
                // verification metadata. did:webs stores it on the web, so a
                // DID source is not meaningful for this format.
                return Err(DIDSCIDError::UnsupportedFormat);
            }
            src.to_string()
        }
        (None, Some(ScidMethod::Webs(src))) => src,
        (None, Some(other)) => {
            return Err(DIDSCIDError::InvalidSrc(format!(
                "did:scid:ke cannot resolve through {other:?}"
            )));
        }
        (None, None) => return Err(DIDSCIDError::MissingPeerSource),
    };

    // The tail encoding is the same as did:webvh's — host with `%3A`-encoded
    // port, path segments joined by `:` — only the SCID's position differs.
    let tail = normalize_webvh_src(&source)?;
    let webs = format!("did:webs:{tail}:{scid}");
    debug!("derived webs DID: {webs}");
    Ok(ScidMethod::Webs(webs))
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
    use crate::{
        ScidMethod, convert_scid_to_method, errors::DIDSCIDError, normalize_webvh_src, resolve,
    };

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

    // -- did:scid:ke (did:webs) --------------------------------------------

    const AID: &str = "ENro7uf0ePmiK3jdTo2YCdXLqW7z7xoP6qhhBou6gBLe";

    #[test]
    fn webs_puts_the_scid_last_not_first() {
        // The trap this test exists for: did:webvh puts the SCID FIRST, while
        // did:webs puts the AID LAST, because the AID is the final path
        // element of the URL the artifacts are served from. Reusing the webvh
        // formatting would produce a DID that resolves to the wrong location
        // while looking perfectly well-formed.
        match convert_scid_to_method(&format!("did:scid:ke:1:{AID}?src=example.com/dids"), None) {
            Ok(ScidMethod::Webs(did)) => {
                assert_eq!(did, format!("did:webs:example.com:dids:{AID}"));
            }
            other => panic!("Incorrect conversion: {other:?}"),
        }

        // Same inputs through the vh format, for contrast.
        match convert_scid_to_method(&format!("did:scid:vh:1:{AID}?src=example.com/dids"), None) {
            Ok(ScidMethod::WebVH(did)) => {
                assert_eq!(did, format!("did:webvh:{AID}:example.com:dids"));
            }
            other => panic!("Incorrect conversion: {other:?}"),
        }
    }

    #[test]
    fn webs_encodes_the_port_in_the_host() {
        match convert_scid_to_method(&format!("did:scid:ke:1:{AID}?src=localhost:3000/x"), None) {
            Ok(ScidMethod::Webs(did)) => {
                assert_eq!(did, format!("did:webs:localhost%3A3000:x:{AID}"));
            }
            other => panic!("Incorrect conversion: {other:?}"),
        }
    }

    #[test]
    fn webs_peer_mode_uses_the_supplied_source() {
        match convert_scid_to_method(
            &format!("did:scid:ke:1:{AID}"),
            Some(ScidMethod::Webs("example.com".to_string())),
        ) {
            Ok(ScidMethod::Webs(did)) => assert_eq!(did, format!("did:webs:example.com:{AID}")),
            other => panic!("Incorrect conversion: {other:?}"),
        }
    }

    #[test]
    fn webs_rejects_a_did_valued_source() {
        // A DID source names a method that stores the verification metadata.
        // did:webs stores it on the web, so a DID source means nothing here.
        assert!(matches!(
            convert_scid_to_method(&format!("did:scid:ke:1:{AID}?src=did:cheqd:mainnet"), None),
            Err(DIDSCIDError::UnsupportedFormat),
        ));
    }

    #[test]
    fn webs_without_a_source_needs_peer_mode() {
        assert!(matches!(
            convert_scid_to_method(&format!("did:scid:ke:1:{AID}"), None),
            Err(DIDSCIDError::MissingPeerSource),
        ));
    }

    #[test]
    fn formats_do_not_borrow_each_others_peer_sources() {
        // A webvh peer source must not satisfy a ke DID, or vice versa: they
        // place the SCID differently, so crossing them yields a wrong location.
        assert!(
            convert_scid_to_method(
                &format!("did:scid:ke:1:{AID}"),
                Some(ScidMethod::WebVH("example.com".to_string())),
            )
            .is_err()
        );
        assert!(
            convert_scid_to_method(
                &format!("did:scid:vh:1:{AID}"),
                Some(ScidMethod::Webs("example.com".to_string())),
            )
            .is_err()
        );
    }

    // -- the PUBLIC entry point --------------------------------------------
    //
    // Everything above tests `convert_scid_to_method`, which is private. These
    // go through `resolve` itself, because a gate in front of the conversion
    // once made every format except `vh` unreachable while all the conversion
    // tests still passed.

    #[tokio::test]
    async fn resolve_reaches_the_webs_path() {
        // Without the `did-webs` feature this stops at "the feature is
        // missing", and with it, it would try to fetch. Either way it must get
        // *past* the format dispatch — an `UnsupportedFormat` here means `ke`
        // is unreachable through the public API.
        let err = resolve(&format!("did:scid:ke:1:{AID}?src=example.com"), None, None)
            .await
            .expect_err("no network in tests");
        assert!(
            !matches!(err, DIDSCIDError::UnsupportedFormat),
            "did:scid:ke must reach the did:webs path, got {err:?}",
        );
    }

    #[tokio::test]
    async fn resolve_reports_an_unknown_format_by_name() {
        let err = resolve(&format!("did:scid:jl:1:{AID}?src=example.com"), None, None)
            .await
            .expect_err("jl is not implemented");
        match err {
            DIDSCIDError::UnknownFormat(f) => assert_eq!(f, "jl"),
            other => panic!("expected UnknownFormat, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn resolve_rejects_a_non_scid_did() {
        assert!(matches!(
            resolve("did:web:example.com", None, None).await,
            Err(DIDSCIDError::UnsupportedFormat),
        ));
    }

    #[tokio::test]
    async fn resolve_rejects_an_unsupported_version() {
        assert!(matches!(
            resolve(&format!("did:scid:vh:2:{AID}?src=example.com"), None, None).await,
            Err(DIDSCIDError::UnsupportedVersion(_)),
        ));
    }

    // -- format and version handling ---------------------------------------

    #[test]
    fn unknown_formats_say_so() {
        // `jl` (did:jlinc) is in the registry as a proposed entry but is not
        // implemented. The error should name the format rather than claim the
        // DID is malformed.
        let err = convert_scid_to_method(&format!("did:scid:jl:1:{AID}?src=example.com"), None)
            .expect_err("jl is not implemented");
        assert!(err.to_string().contains("jl"), "{err}");
    }

    #[test]
    fn unsupported_versions_say_so() {
        assert!(matches!(
            convert_scid_to_method(&format!("did:scid:vh:2:{AID}?src=example.com"), None),
            Err(DIDSCIDError::UnsupportedVersion(_)),
        ));
    }

    #[test]
    fn a_missing_version_is_not_a_did_scid() {
        assert!(matches!(
            convert_scid_to_method(&format!("did:scid:vh:{AID}?src=example.com"), None),
            Err(DIDSCIDError::UnsupportedFormat),
        ));
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
        // A well-formed did:scid naming a format we do not resolve now reports
        // the format by name. It used to be indistinguishable from a string
        // that is not a did:scid at all.
        match convert_scid_to_method("did:scid:invalid:1:abcde?src=did:example:abcd", None) {
            Err(DIDSCIDError::UnknownFormat(f)) => assert_eq!(f, "invalid"),
            other => panic!("Incorrect conversion: {other:?}"),
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
}

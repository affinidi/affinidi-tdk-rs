/*! Implementation of the `did:scid` (Self-Certifying Identifier) DID method.
 *
 * Supported formats:
 *   - `did:scid:vh:1` — Verifiable History via did:webvh
 *   - `did:scid:ke:1` — a KERI AID via did:webs (requires the `did-webs`
 *     feature)
 *
 * `did:cheqd` sources still parse behind the inert `did-cheqd` feature, but
 * their resolution was retired in 0.2.6 and always fails.
 *
 * ### The document a did:scid resolves to
 *
 * For both formats the document is the DID's own: its `id` is the bare
 * `did:scid:<format>:1:<scid>` DID, with no `src`, every reference the
 * source document makes to itself is rewritten under that DID, and
 * `alsoKnownAs` lists the did:scid DID URL of the source's location and the
 * source DID (`did:webvh:…` or `did:webs:…`).
 *
 * ⚠️ The did:scid method type registry (Appendix A of the specification) is
 * still marked TODO, and `ke` is listed there as a *proposed* entry rather
 * than a registered one. It is implemented here because did:webs is named
 * explicitly as a supported verification metadata format, but the code could
 * still change before the registry is settled.
 *
 * Two invocation modes are supported:
 *   - **URL mode**: `did:scid:vh:1:<scid>?src=<source>` — the `src` parameter
 *     is a WebVH host/path (or, for `ke`, the did:webs host/path).
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
use std::time::Duration;
use tracing::debug;

pub mod errors;

/// The parts of `did:scid:<format>:<version>:<scid>[?src=<source>]`.
///
/// The format name is two characters by convention and the version is one or
/// more digits; both are read rather than hard-coded so an unknown format
/// produces a clear error instead of failing to match at all.
struct ScidParts<'a> {
    format: &'a str,
    version: &'a str,
    scid: &'a str,
    src: Option<&'a str>,
}

impl<'a> ScidParts<'a> {
    /// `None` when `id` is not of that shape: the prefix, a format of
    /// lowercase letters and digits, a version of digits, and at most a
    /// `src` query.
    fn split(id: &'a str) -> Option<Self> {
        let rest = id.strip_prefix("did:scid:")?;
        let (format, rest) = rest.split_once(':')?;
        let (version, rest) = rest.split_once(':')?;
        if format.is_empty()
            || !format
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
            || version.is_empty()
            || !version.bytes().all(|b| b.is_ascii_digit())
        {
            return None;
        }
        let (scid, src) = match rest.split_once('?') {
            None => (rest, None),
            Some((scid, query)) => (scid, Some(query.strip_prefix("src=")?)),
        };
        Some(Self {
            format,
            version,
            scid,
            src,
        })
    }
}

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
///   - [`ScidMethod::WebVH`] (`vh`) or [`ScidMethod::Webs`] (`ke`): host/path
///     string. Accepts the same formats as URL-mode `src` (see
///     `normalize_webvh_src`) — bare host, host with port, optional
///     scheme/trailing slash, etc.
/// * `timeout` — optional resolution timeout, for both formats.
///
/// The result is the DID's own document: its `id` is the bare
/// `did:scid:<format>:1:<scid>` DID, with no `src`, and every reference the
/// source document makes to itself is under that DID. `alsoKnownAs` lists the
/// did:scid DID URL of the source's location and the source DID
/// (`did:webvh:…` or `did:webs:…`).
pub async fn resolve(
    did: &str,
    peer_src: Option<ScidMethod>,
    timeout: Option<Duration>,
) -> Result<Document, DIDSCIDError> {
    resolve_with_options(
        did,
        peer_src,
        didwebvh_rs::resolve::ResolveOptions {
            timeout,
            ..Default::default()
        },
    )
    .await
}

/// A resolved `did:scid:vh:1` DID, with what a caller needs to remember about
/// where it came from.
///
/// The `src` of a did:scid DID URL is a locator, not part of the identity, so
/// a caller that wants to resolve the bare DID later keeps [`source`](Self::source),
/// and one that wants to refuse an older copy of the log served from another
/// source keeps [`version_number`](Self::version_number). A copy that is not
/// older can still be a fork, signed with a leaked update key and served from a
/// host of the forger's choosing; [`version_ids`](Self::version_ids) lets a
/// caller check that it contains the version it already verified.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct ScidResolution {
    /// The DID's own document: `id` is the bare did:scid DID and every
    /// reference to the DID is under it (see
    /// [`didwebvh_rs::did_web::to_scid_did_document`]).
    pub document: Document,
    /// The did:webvh DID of the log as resolved.
    pub webvh_did: String,
    /// The log's location, in `src` form (`example.com/alice`).
    pub source: String,
    /// The latest log entry's version number.
    pub version_number: u32,
    /// The latest log entry's version id.
    pub version_id: String,
    /// The version id of every entry verified, oldest first.
    pub version_ids: Vec<String>,
    /// The did:webvh witness threshold the latest entry was verified against:
    /// how many approvals from the witnesses named by the entry before it it
    /// carries. `None` when that entry names no witnesses, so the latest
    /// version is unwitnessed.
    pub witness_threshold: Option<u32>,
}

/// Resolve a `did:scid:vh:1` DID to its own document, reporting the source and
/// version it was resolved at.
///
/// The source is the `src` of `did` when it has one, and `peer_src` otherwise.
/// Other formats are refused with [`DIDSCIDError::UnsupportedFormat`]; use
/// [`resolve_with_options`] for them.
pub async fn resolve_scid(
    did: &str,
    peer_src: Option<ScidMethod>,
    options: didwebvh_rs::resolve::ResolveOptions,
) -> Result<ScidResolution, DIDSCIDError> {
    match convert_scid_to_method(did, peer_src)? {
        ScidMethod::WebVH(webvh_did) => resolve_webvh_native(&webvh_did, options).await,
        _ => Err(DIDSCIDError::UnsupportedFormat),
    }
}

async fn resolve_webvh_native(
    webvh_did: &str,
    options: didwebvh_rs::resolve::ResolveOptions,
) -> Result<ScidResolution, DIDSCIDError> {
    debug!("Resolving WebVH DID: {webvh_did}");
    let mut method = DIDWebVHState::default();
    match method.resolve(webvh_did, options).await {
        // didwebvh-rs resolves a deactivated DID `Ok` and flags it in the
        // metadata only; this returns a bare `Document`, so refuse it here or
        // the retired keys stay usable.
        Ok((_, metadata)) if metadata.deactivated => Err(DIDSCIDError::WebVHError(
            didwebvh_rs::DIDWebVHError::DeactivatedError(format!(
                "{webvh_did} has been deactivated"
            )),
        )),
        Ok((log_entry, metadata)) => {
            let webvh_document = log_entry.get_did_document()?;
            let document = didwebvh_rs::did_web::to_scid_did_document(&webvh_document)?;
            let log_did = webvh_document
                .get("id")
                .and_then(serde_json::Value::as_str)
                .unwrap_or(webvh_did)
                .to_string();
            let source = DIDWebVHState::convert_webvh_id_to_scid_id(&log_did)
                .split_once("?src=")
                .map(|(_, src)| src.to_string())
                .unwrap_or_default();
            Ok(ScidResolution {
                document: serde_json::from_value(document)?,
                webvh_did: log_did,
                source,
                version_number: metadata.version_number,
                version_id: metadata.version_id,
                version_ids: method
                    .log_entries()
                    .iter()
                    .map(|entry| entry.get_version_id().to_string())
                    .collect(),
                witness_threshold: method
                    .log_entries()
                    .last()
                    .and_then(|entry| entry.validated_parameters.active_witness.as_deref())
                    .and_then(|witnesses| witnesses.threshold())
                    .filter(|threshold| *threshold > 0),
            })
        }
        Err(e) => {
            debug!("did:webvh resolution of {webvh_did} failed: {e}");
            Err(DIDSCIDError::WebVHError(e))
        }
    }
}

/// Resolve a SCID DID Method under `options`.
///
/// [`resolve`] uses `ResolveOptions::default()`, whose host policy refuses
/// non-public hosts; use this to resolve under the caller's own policy, such
/// as a local stack serving `did:scid:vh:1:<scid>?src=localhost:8000`, the same
/// way its `did:webvh` form would be.
///
/// Both formats honour the options' `timeout` and `host_policy`: the `vh`
/// format passes them to the did:webvh resolution, and the `ke` format builds
/// a did:webs resolver with them (`HostPolicy::AllowPrivate` maps to
/// `affinidi_did_webs::HostPolicy::AllowPrivate`). The other options are
/// did:webvh's own. To reuse one did:webs resolver and its connection pool
/// across calls, use [`resolve_with_webs_resolver`].
pub async fn resolve_with_options(
    did: &str,
    peer_src: Option<ScidMethod>,
    options: didwebvh_rs::resolve::ResolveOptions,
) -> Result<Document, DIDSCIDError> {
    resolve_inner(did, peer_src, options, None).await
}

/// As [`resolve_with_options`], resolving the `ke` format with `webs`, a
/// did:webs resolver the caller holds, so its HTTP client and connection
/// pool are reused across calls. `webs` carries its own host policy and
/// timeouts; `options` then applies to the `vh` format only.
#[cfg(feature = "did-webs")]
pub async fn resolve_with_webs_resolver(
    did: &str,
    peer_src: Option<ScidMethod>,
    options: didwebvh_rs::resolve::ResolveOptions,
    webs: &affinidi_did_webs::WebsResolver,
) -> Result<Document, DIDSCIDError> {
    resolve_inner(did, peer_src, options, Some(webs)).await
}

/// A did:webs resolver the caller supplied, when the `did-webs` feature is on.
#[cfg(feature = "did-webs")]
type WebsHandle<'a> = Option<&'a affinidi_did_webs::WebsResolver>;
#[cfg(not(feature = "did-webs"))]
type WebsHandle<'a> = Option<&'a std::convert::Infallible>;

async fn resolve_inner(
    did: &str,
    peer_src: Option<ScidMethod>,
    options: didwebvh_rs::resolve::ResolveOptions,
    webs: WebsHandle<'_>,
) -> Result<Document, DIDSCIDError> {
    // No prefix test here: `convert_scid_to_method` matches the whole
    // `did:scid:<format>:<version>:<scid>` shape and reports an unknown format
    // or version by name. A `starts_with("did:scid:vh:1")` gate used to sit in
    // front of it, which made every format other than `vh` unreachable through
    // this function no matter what the conversion supported.
    match convert_scid_to_method(did, peer_src)? {
        ScidMethod::WebVH(webvh_did) => resolve_webvh_native(&webvh_did, options)
            .await
            .map(|resolution| resolution.document),
        ScidMethod::Webs(webs_did) => resolve_webs(&webs_did, &options, webs).await,
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

/// Resolve a derived `did:webs` DID with `webs`, or with a resolver built
/// from `options` when the caller supplied none.
#[cfg(feature = "did-webs")]
async fn resolve_webs(
    webs_did: &str,
    options: &didwebvh_rs::resolve::ResolveOptions,
    webs: WebsHandle<'_>,
) -> Result<Document, DIDSCIDError> {
    debug!("Resolving Webs DID: {webs_did}");
    let built;
    let resolver = match webs {
        Some(resolver) => resolver,
        None => {
            built = webs_resolver(options)?;
            &built
        }
    };
    let resolution = resolver
        .resolve_with_metadata(webs_did)
        .await
        .map_err(|e| {
            debug!("did:webs resolution of {webs_did} failed: {e}");
            webs_error(e)
        })?;
    webs_document(webs_did, resolution)
}

/// A did:webs resolver under the timeout and host policy of `options`.
#[cfg(feature = "did-webs")]
fn webs_resolver(
    options: &didwebvh_rs::resolve::ResolveOptions,
) -> Result<affinidi_did_webs::WebsResolver, DIDSCIDError> {
    let policy = match options.host_policy {
        didwebvh_rs::resolve::HostPolicy::AllowPrivate => {
            affinidi_did_webs::HostPolicy::AllowPrivate
        }
        _ => affinidi_did_webs::HostPolicy::PublicOnly,
    };
    affinidi_did_webs::WebsResolver::with_client_builder_and_timeout(
        reqwest::Client::builder(),
        policy,
        options
            .timeout
            .unwrap_or(affinidi_did_webs::fetch::DEFAULT_TIMEOUT),
    )
    .map_err(webs_error)
}

/// A failed did:webs resolution: an unsuccessful HTTP status stays data.
#[cfg(feature = "did-webs")]
fn webs_error(e: affinidi_did_webs::DidWebsError) -> DIDSCIDError {
    match e {
        affinidi_did_webs::DidWebsError::Network(network) => DIDSCIDError::Network(network),
        other => DIDSCIDError::WebsError(other.to_string()),
    }
}

/// The document of a resolved `did:webs` DID, unless it is deactivated.
///
/// Like `resolve_webvh_native`: this returns a bare `Document`, so a
/// deactivation reported only in the metadata would leave the retired keys
/// usable. It is refused here whichever `affinidi-did-webs` 0.13 release
/// resolved it. Compiled for tests too, where `affinidi-did-webs` is a
/// dev-dependency, so its test runs without the feature.
///
/// The document returned is the did:scid DID's own, as for `vh` (see
/// [`to_scid_ke_document`]).
#[cfg(any(feature = "did-webs", test))]
fn webs_document(
    webs_did: &str,
    resolution: affinidi_did_webs::Resolution,
) -> Result<Document, DIDSCIDError> {
    if resolution.metadata.deactivated {
        return Err(DIDSCIDError::Deactivated(webs_did.to_string()));
    }
    to_scid_ke_document(webs_did, &resolution.document)
}

/// `did-webs` is optional so that `did-scid` does not pull the KERI stack into
/// builds that never resolve `did:scid:ke`. Without the feature the format is
/// still parsed — so the error says what is missing rather than looking like a
/// malformed DID.
#[cfg(not(feature = "did-webs"))]
async fn resolve_webs(
    _webs_did: &str,
    _options: &didwebvh_rs::resolve::ResolveOptions,
    _webs: WebsHandle<'_>,
) -> Result<Document, DIDSCIDError> {
    Err(DIDSCIDError::WebsError(
        "did:scid:ke resolution requires the `did-webs` feature".to_string(),
    ))
}

/// The `did:scid:ke:1` DID and DID URL a `did:webs` DID corresponds to: the
/// bare DID, and the DID URL whose `src` names the location (the did:webs
/// host and path, `:` read as `/`, a port kept `%3A`-encoded as did:webvh's
/// conversion keeps it).
#[cfg(any(feature = "did-webs", test))]
fn webs_to_scid_ids(webs_did: &str) -> Option<(String, String)> {
    let rest = webs_did.strip_prefix("did:webs:")?;
    let (location, aid) = rest.rsplit_once(':')?;
    if location.is_empty() || aid.is_empty() {
        return None;
    }
    let bare = format!("did:scid:{FORMAT_WEBS}:1:{aid}");
    let with_src = format!("{bare}?src={}", location.replace(':', "/"));
    Some((bare, with_src))
}

/// Convert a resolved `did:webs` document into the `did:scid:ke:1` DID's own
/// document, as `vh` does for did:webvh: the `id` and every reference the
/// document makes to itself move to the bare did:scid DID, and `alsoKnownAs`
/// gains the did:scid DID URL of the location and the did:webs DID.
#[cfg(any(feature = "did-webs", test))]
fn to_scid_ke_document(webs_did: &str, document: &Document) -> Result<Document, DIDSCIDError> {
    use serde_json::Value;

    fn rewrite(value: &mut Value, from: &str, to: &str) {
        match value {
            Value::String(s) => {
                if s == from {
                    *s = to.to_string();
                } else if let Some(fragment) =
                    s.strip_prefix(from).and_then(|rest| rest.strip_prefix('#'))
                {
                    *s = format!("{to}#{fragment}");
                }
            }
            Value::Array(items) => items.iter_mut().for_each(|item| rewrite(item, from, to)),
            Value::Object(map) => map.values_mut().for_each(|item| rewrite(item, from, to)),
            _ => {}
        }
    }

    let (scid_did, scid_url) = webs_to_scid_ids(webs_did).ok_or_else(|| {
        DIDSCIDError::DidUrlError(format!("{webs_did} is not a did:webs DID with an AID"))
    })?;
    let mut value = serde_json::to_value(document)?;
    rewrite(&mut value, webs_did, &scid_did);

    let mut aliases: Vec<Value> = match value.get("alsoKnownAs") {
        Some(Value::Array(aliases)) => aliases
            .iter()
            .filter(|alias| alias.as_str() != Some(scid_did.as_str()))
            .cloned()
            .collect(),
        _ => Vec::new(),
    };
    for alias in [scid_url.as_str(), webs_did] {
        if !aliases.iter().any(|a| a.as_str() == Some(alias)) {
            aliases.push(Value::String(alias.to_string()));
        }
    }
    if let Some(object) = value.as_object_mut() {
        object.insert("alsoKnownAs".to_string(), Value::Array(aliases));
    }
    Ok(serde_json::from_value(value)?)
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
    let Some(ScidParts {
        format,
        version,
        scid,
        src,
    }) = ScidParts::split(id)
    else {
        return Err(DIDSCIDError::UnsupportedFormat);
    };

    if version != "1" {
        return Err(DIDSCIDError::UnsupportedVersion(format!(
            "format {format:?} version {version:?}"
        )));
    }

    match format {
        FORMAT_WEBVH => convert_webvh(scid, src, peer_src),
        FORMAT_WEBS => convert_webs(scid, src, peer_src),
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

    #[test]
    fn shapes_that_are_not_a_did_scid() {
        for id in [
            "did:scid:VH:1:abc?src=example.com",
            "did:scid::1:abc?src=example.com",
            "did:scid:vh::abc?src=example.com",
            "did:scid:vh:1a:abc?src=example.com",
            "did:scid:vh:1:abc?other=example.com",
            "did:scidx:vh:1:abc",
            "did:scid:vh",
        ] {
            assert!(
                matches!(
                    convert_scid_to_method(id, None),
                    Err(DIDSCIDError::UnsupportedFormat)
                ),
                "{id}"
            );
        }
    }

    #[test]
    fn webs_ids_map_to_scid_ids() {
        assert_eq!(
            crate::webs_to_scid_ids(&format!("did:webs:localhost%3A3000:dids:{AID}")),
            Some((
                format!("did:scid:ke:1:{AID}"),
                format!("did:scid:ke:1:{AID}?src=localhost%3A3000/dids"),
            ))
        );
        assert_eq!(crate::webs_to_scid_ids("did:web:example.com"), None);
    }

    #[test]
    fn a_webs_document_becomes_the_scid_dids_own() {
        let webs = format!("did:webs:example.com:{AID}");
        let document: affinidi_did_common::Document = serde_json::from_value(serde_json::json!({
            "id": webs,
            "alsoKnownAs": [format!("did:keri:{AID}")],
            "verificationMethod": [{
                "id": format!("{webs}#key-1"),
                "type": "Multikey",
                "controller": webs,
                "publicKeyMultibase": "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
            }],
            "authentication": [format!("{webs}#key-1")]
        }))
        .unwrap();

        let scid = crate::to_scid_ke_document(&webs, &document).unwrap();
        let bare = format!("did:scid:ke:1:{AID}");
        assert_eq!(scid.id.as_str(), bare);
        assert_eq!(
            scid.verification_method[0].id.as_str(),
            format!("{bare}#key-1")
        );
        assert_eq!(scid.verification_method[0].controller.as_str(), bare);
        assert_eq!(scid.authentication[0].get_id(), format!("{bare}#key-1"));
        assert_eq!(
            scid.also_known_as,
            vec![
                format!("did:keri:{AID}"),
                format!("{bare}?src=example.com"),
                webs.clone(),
            ]
        );
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

    /// The `ke` format runs under the options' host policy: the default
    /// refuses a loopback source before fetching, and `AllowPrivate` gets
    /// past the policy to the (absent) server.
    #[cfg(feature = "did-webs")]
    #[tokio::test]
    async fn ke_honours_the_host_policy() {
        use didwebvh_rs::resolve::{HostPolicy, ResolveOptions};

        let did = format!("did:scid:ke:1:{AID}?src=localhost:1");
        let refused = crate::resolve_with_options(&did, None, ResolveOptions::default())
            .await
            .expect_err("loopback under PublicOnly");
        assert!(refused.to_string().contains("host policy"), "{refused:?}");

        let options = ResolveOptions {
            timeout: Some(std::time::Duration::from_secs(5)),
            ..Default::default()
        }
        .with_host_policy(HostPolicy::AllowPrivate);
        let unreachable = crate::resolve_with_options(&did, None, options)
            .await
            .expect_err("nothing listens on port 1");
        assert!(
            !unreachable.to_string().contains("host policy"),
            "{unreachable:?}"
        );
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

#[cfg(test)]
mod webs_tests {
    use crate::{errors::DIDSCIDError, webs_document};
    use affinidi_did_webs::create::{CreateConfig, create};
    use affinidi_did_webs::update::{Change, UpdateConfig, update};
    use affinidi_did_webs::{DidWebs, resolve_with_metadata};
    use affinidi_keri::config::{InceptionConfig, RotationConfig};

    const SALT: &[u8] = &[3u8; 16];

    #[test]
    fn an_active_webs_did_resolves_to_the_scid_dids_document() {
        let created = create(
            CreateConfig::builder("example.com")
                .inception(InceptionConfig::builder().salt(SALT.to_vec()).build())
                .build(),
        )
        .expect("create");
        let did = DidWebs::parse(created.did()).expect("parse");
        let resolution =
            resolve_with_metadata(&did, &created.artifacts().keri_cesr, None).expect("resolves");
        let document = webs_document(created.did(), resolution).expect("an active DID");

        let aid = did.aid();
        let bare = format!("did:scid:ke:1:{aid}");
        assert_eq!(document.id.as_str(), bare);
        assert!(
            document
                .verification_method
                .iter()
                .all(|vm| vm.id.as_str().starts_with(&format!("{bare}#"))),
            "{document:?}"
        );
        assert!(document.also_known_as.contains(&created.did().to_string()));
        assert!(
            document
                .also_known_as
                .contains(&format!("{bare}?src=example.com"))
        );
    }

    #[test]
    fn a_deactivated_webs_did_is_refused_and_an_active_one_returned() {
        let created = create(
            CreateConfig::builder("example.com")
                .inception(InceptionConfig::builder().salt(SALT.to_vec()).build())
                .build(),
        )
        .expect("create");
        let did = DidWebs::parse(created.did()).expect("parse");

        let active =
            resolve_with_metadata(&did, &created.artifacts().keri_cesr, None).expect("resolves");
        let document = webs_document(created.did(), active).expect("an active DID");
        assert!(!document.verification_method.is_empty());

        let deactivated = update(
            UpdateConfig {
                did: created.did().to_string(),
                prior: created.artifacts().clone(),
                custody: created.custody().clone(),
                change: Change::Rotate(RotationConfig {
                    next_count: 0,
                    next_threshold: 0,
                    ..RotationConfig::default()
                }),
            },
            SALT,
        )
        .expect("rotate to no next keys");
        let resolution = resolve_with_metadata(&did, &deactivated.artifacts().keri_cesr, None)
            .expect("resolves with its metadata");
        assert!(resolution.metadata.deactivated);

        let err = webs_document(created.did(), resolution).expect_err("deactivated");
        assert!(
            matches!(&err, DIDSCIDError::Deactivated(d) if d == created.did()),
            "{err:?}"
        );
    }
}

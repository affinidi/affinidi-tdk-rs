//! Parsing a `did:webs` identifier and deriving the URLs it points at.
//!
//! ```text
//! did:webs:<host>[%3A<port>][:<path segment>...]:<AID>
//! ```
//!
//! The last label is a KERI **AID**; everything before it is a `did:web`-style
//! host and path. The AID is itself the final path element of the URL, so
//! `did:webs` never resolves to `/.well-known/` the way a pathless `did:web`
//! does — there is always at least one path element.

use crate::errors::DidWebsError;

/// The two artifacts a `did:webs` identifier publishes.
///
/// `did.json` is a cache of the DID document; `keri.cesr` is the key event log
/// it must be derived from. Only the second one carries any authority.
pub const DID_JSON: &str = "did.json";
/// The CESR stream artifact name.
pub const KERI_CESR: &str = "keri.cesr";

/// A parsed `did:webs` identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DidWebs {
    /// The DID, without any query or fragment, e.g.
    /// `did:webs:example.com:path:EAid…`.
    did: String,
    /// The `versionId` DID parameter, when the DID URL carried one.
    version_id: Option<u64>,
    /// Host, with the port decoded if one was present (`example.com:3000`).
    host: String,
    /// Path segments between the host and the AID.
    path: Vec<String>,
    /// The KERI autonomic identifier — the last label.
    aid: String,
}

impl DidWebs {
    /// Parse a `did:webs` identifier.
    ///
    /// # Errors
    /// Returns [`DidWebsError::InvalidDid`] if the identifier is not a
    /// `did:webs` DID with a host and a trailing AID.
    pub fn parse(did: &str) -> Result<Self, DidWebsError> {
        let rest = did.strip_prefix("did:webs:").ok_or_else(|| {
            DidWebsError::InvalidDid(format!("{did:?} does not start with 'did:webs:'"))
        })?;

        // A DID URL's query/fragment is not part of the method-specific id.
        let (rest, query) = split_query(rest);
        if rest.is_empty() {
            return Err(DidWebsError::InvalidDid(
                "empty method-specific identifier".into(),
            ));
        }
        let version_id = parse_version_id(query, did)?;

        let labels: Vec<&str> = rest.split(':').collect();
        if labels.len() < 2 {
            return Err(DidWebsError::InvalidDid(format!(
                "{did:?} has no AID: did:webs requires a host and a trailing AID"
            )));
        }
        if labels.iter().any(|l| l.is_empty()) {
            return Err(DidWebsError::InvalidDid(format!(
                "{did:?} contains an empty label"
            )));
        }

        let aid = labels[labels.len() - 1].to_string();
        validate_aid(&aid, did)?;

        // `%3A` is how did:web encodes the port separator. It is written
        // lowercase in the wild as often as uppercase.
        let host_label = labels[0];
        let host = decode_port_separator(host_label);
        if host.is_empty() || host.starts_with(':') {
            return Err(DidWebsError::InvalidDid(format!("{did:?} has no host")));
        }

        let path = labels[1..labels.len() - 1]
            .iter()
            .map(|s| (*s).to_string())
            .collect();

        Ok(Self {
            did: format!("did:webs:{rest}"),
            version_id,
            host,
            path,
            aid,
        })
    }

    /// The DID, without any query or fragment the DID URL carried.
    pub fn did(&self) -> &str {
        &self.did
    }

    /// The `versionId` DID parameter: the sequence number of the KERI event
    /// the document should be resolved as of, when one was asked for.
    pub fn version_id(&self) -> Option<u64> {
        self.version_id
    }

    /// The `did:keri` form of this identifier's AID.
    pub fn did_keri(&self) -> String {
        format!("did:keri:{}", self.aid)
    }

    /// The KERI AID — the identifier whose key event log authorises this DID.
    pub fn aid(&self) -> &str {
        &self.aid
    }

    /// The host, with any `%3A`-encoded port decoded.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The path segments between the host and the AID.
    pub fn path(&self) -> &[String] {
        &self.path
    }

    /// The URL an artifact is published at.
    ///
    /// The AID is always the final path element, so `did.json` for
    /// `did:webs:example.com:EAid` is at `https://example.com/EAid/did.json`.
    pub fn artifact_url(&self, artifact: &str) -> String {
        self.artifact_url_with_scheme("https", artifact)
    }

    /// Whether this DID's host is a loopback address.
    ///
    /// `did:webs` artifacts are fetched over HTTPS, but a host that can only
    /// be reached from this machine cannot be intercepted, and local tooling
    /// rarely has a certificate for it — the reference implementation serves
    /// its own examples over plain HTTP. Resolvers therefore permit `http` for
    /// loopback, the same accommodation `did:web` implementations make.
    pub fn is_loopback(&self) -> bool {
        let host = self.host.split(':').next().unwrap_or(&self.host);
        host == "localhost" || host == "127.0.0.1" || host == "::1" || host == "[::1]"
    }

    /// The URL an artifact is published at, over an explicit scheme.
    ///
    /// Prefer [`artifact_url`](Self::artifact_url). This exists for resolvers
    /// that permit plain HTTP for loopback or in a controlled environment.
    pub fn artifact_url_with_scheme(&self, scheme: &str, artifact: &str) -> String {
        let mut url = format!("{scheme}://{}", self.host);
        for segment in &self.path {
            url.push('/');
            url.push_str(segment);
        }
        url.push('/');
        url.push_str(&self.aid);
        url.push('/');
        url.push_str(artifact);
        url
    }

    /// The `did:web` identifier that shares this DID's document.
    ///
    /// Every `did:webs` has a `did:web` twin at the same location: the same
    /// `did.json`, with no knowledge of `keri.cesr`. The spec records it in the
    /// document as `equivalentId`, and it is the id the published `did.json`
    /// actually carries — so it is also what a fetched document must be
    /// compared against.
    pub fn did_web_twin(&self) -> String {
        // Formed by replacing the prefix, as the specification describes, so
        // the twin keeps exactly the encoding the DID was written with.
        format!("did:web:{}", &self.did["did:webs:".len()..])
    }
}

/// Split a method-specific identifier from its query, dropping any fragment.
fn split_query(rest: &str) -> (&str, Option<&str>) {
    let rest = rest.split('#').next().unwrap_or_default();
    match rest.split_once('?') {
        Some((id, query)) => (id, Some(query)),
        None => (rest, None),
    }
}

/// The `versionId` parameter, as a decimal sequence number.
///
/// Decimal because that is how resolution metadata reports `versionId`, and how
/// the reference implementation reads it back.
fn parse_version_id(query: Option<&str>, did: &str) -> Result<Option<u64>, DidWebsError> {
    let Some(query) = query else {
        return Ok(None);
    };
    for pair in query.split('&') {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        if key == "versionId" {
            return value.parse().map(Some).map_err(|_| {
                DidWebsError::InvalidDid(format!(
                    "{did:?} has a versionId that is not a sequence number: {value:?}"
                ))
            });
        }
    }
    Ok(None)
}

/// Reject anything that is not plausibly a CESR primitive.
///
/// This is a syntax check, not a security one — the AID is proven by the KEL,
/// not by how it looks. Its job is to keep a malformed label out of a URL.
fn validate_aid(aid: &str, did: &str) -> Result<(), DidWebsError> {
    if aid.len() < 4 {
        return Err(DidWebsError::InvalidDid(format!(
            "{did:?} has an AID too short to be a CESR primitive: {aid:?}"
        )));
    }
    if !aid
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(DidWebsError::InvalidDid(format!(
            "{did:?} has an AID with characters outside the CESR base64url alphabet: {aid:?}"
        )));
    }
    Ok(())
}

/// `%3A` (either case) back to `:`.
fn decode_port_separator(host: &str) -> String {
    let mut out = String::with_capacity(host.len());
    let bytes = host.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && bytes[i + 1] == b'3'
            && bytes[i + 2] | 0x20 == b'a'
        {
            out.push(':');
            i += 3;
        } else {
            out.push(bytes[i] as char);
            i += 1;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const AID: &str = "ENro7uf0ePmiK3jdTo2YCdXLqW7z7xoP6qhhBou6gBLe";

    #[test]
    fn parses_host_and_aid() {
        let d = DidWebs::parse(&format!("did:webs:example.com:{AID}")).expect("valid");
        assert_eq!(d.host(), "example.com");
        assert!(d.path().is_empty());
        assert_eq!(d.aid(), AID);
    }

    #[test]
    fn parses_path_segments() {
        let d = DidWebs::parse(&format!("did:webs:example.com:a:b:{AID}")).expect("valid");
        assert_eq!(d.host(), "example.com");
        assert_eq!(d.path(), ["a", "b"]);
        assert_eq!(d.aid(), AID);
    }

    #[test]
    fn decodes_the_port_separator_in_either_case() {
        // Real artifacts write it lowercase; the spec writes it uppercase.
        for encoded in ["did-webs-service%3a7676", "did-webs-service%3A7676"] {
            let d = DidWebs::parse(&format!("did:webs:{encoded}:{AID}")).expect("valid");
            assert_eq!(d.host(), "did-webs-service:7676", "for {encoded}");
        }
    }

    #[test]
    fn derives_artifact_urls_with_the_aid_as_the_last_path_element() {
        let d = DidWebs::parse(&format!("did:webs:example.com:dids:{AID}")).expect("valid");
        assert_eq!(
            d.artifact_url(DID_JSON),
            format!("https://example.com/dids/{AID}/did.json"),
        );
        assert_eq!(
            d.artifact_url(KERI_CESR),
            format!("https://example.com/dids/{AID}/keri.cesr"),
        );
    }

    #[test]
    fn a_pathless_did_still_has_the_aid_as_a_path_element() {
        // Unlike did:web, did:webs never resolves to /.well-known/.
        let d = DidWebs::parse(&format!("did:webs:example.com:{AID}")).expect("valid");
        assert_eq!(
            d.artifact_url(DID_JSON),
            format!("https://example.com/{AID}/did.json"),
        );
    }

    #[test]
    fn port_is_restored_in_the_url() {
        let d = DidWebs::parse(&format!("did:webs:localhost%3A3000:{AID}")).expect("valid");
        assert_eq!(
            d.artifact_url(KERI_CESR),
            format!("https://localhost:3000/{AID}/keri.cesr"),
        );
    }

    #[test]
    fn did_web_twin_round_trips_the_port_encoding() {
        let d = DidWebs::parse(&format!("did:webs:localhost%3A3000:x:{AID}")).expect("valid");
        assert_eq!(
            d.did_web_twin(),
            format!("did:web:localhost%3A3000:x:{AID}")
        );
    }

    #[test]
    fn query_and_fragment_are_not_part_of_the_identifier() {
        let d =
            DidWebs::parse(&format!("did:webs:example.com:{AID}?versionId=1#key")).expect("valid");
        assert_eq!(d.aid(), AID);
        // The DID is the identifier alone, so it can be a document's `id`.
        assert_eq!(d.did(), format!("did:webs:example.com:{AID}"));
        assert_eq!(d.version_id(), Some(1));
    }

    #[test]
    fn a_did_without_version_id_asks_for_the_latest() {
        let d = DidWebs::parse(&format!("did:webs:example.com:{AID}?other=x")).expect("valid");
        assert_eq!(d.version_id(), None);
    }

    #[test]
    fn a_version_id_that_is_not_a_number_is_refused() {
        assert!(DidWebs::parse(&format!("did:webs:example.com:{AID}?versionId=latest")).is_err());
    }

    #[test]
    fn the_did_web_twin_keeps_the_encoding_the_did_was_written_with() {
        // Designated aliases are compared against the twin, and real artifacts
        // write the port separator lowercase.
        let d = DidWebs::parse(&format!("did:webs:host%3a7676:{AID}")).expect("valid");
        assert_eq!(d.did_web_twin(), format!("did:web:host%3a7676:{AID}"));
        assert_eq!(d.did_keri(), format!("did:keri:{AID}"));
    }

    #[test]
    fn loopback_hosts_are_recognised() {
        for host in [
            "localhost",
            "127.0.0.1",
            "localhost%3A7676",
            "127.0.0.1%3A8080",
        ] {
            let d = DidWebs::parse(&format!("did:webs:{host}:{AID}")).expect("valid");
            assert!(d.is_loopback(), "{host} should be loopback");
        }
        for host in [
            "example.com",
            "did-webs-service%3a7676",
            "127.0.0.1.example.com",
        ] {
            let d = DidWebs::parse(&format!("did:webs:{host}:{AID}")).expect("valid");
            assert!(!d.is_loopback(), "{host} should not be loopback");
        }
    }

    #[test]
    fn a_scheme_can_be_supplied_explicitly() {
        let d = DidWebs::parse(&format!("did:webs:localhost%3A7676:{AID}")).expect("valid");
        assert_eq!(
            d.artifact_url_with_scheme("http", DID_JSON),
            format!("http://localhost:7676/{AID}/did.json"),
        );
        // The default stays HTTPS.
        assert!(d.artifact_url(DID_JSON).starts_with("https://"));
    }

    #[test]
    fn rejects_a_non_webs_did() {
        assert!(DidWebs::parse(&format!("did:web:example.com:{AID}")).is_err());
        assert!(DidWebs::parse("not a did").is_err());
    }

    #[test]
    fn rejects_a_did_with_no_aid() {
        assert!(DidWebs::parse("did:webs:example.com").is_err());
        assert!(DidWebs::parse("did:webs:").is_err());
    }

    #[test]
    fn rejects_empty_labels() {
        assert!(DidWebs::parse(&format!("did:webs:example.com::{AID}")).is_err());
    }

    #[test]
    fn rejects_an_aid_that_could_not_be_a_cesr_primitive() {
        // A label with a path traversal or a slash must never reach a URL.
        assert!(DidWebs::parse("did:webs:example.com:../../etc/passwd").is_err());
        assert!(DidWebs::parse("did:webs:example.com:ab").is_err());
        assert!(DidWebs::parse(&format!("did:webs:example.com:{AID}/x")).is_err());
    }
}

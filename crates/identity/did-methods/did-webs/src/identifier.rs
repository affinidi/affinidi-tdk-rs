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
    /// The full DID as written, e.g. `did:webs:example.com:path:EAid…`.
    did: String,
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
        let rest = rest
            .split(['?', '#'])
            .next()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| DidWebsError::InvalidDid("empty method-specific identifier".into()))?;

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
            did: did.to_string(),
            host,
            path,
            aid,
        })
    }

    /// The DID as written.
    pub fn did(&self) -> &str {
        &self.did
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
        let mut url = format!("https://{}", self.host);
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
        let mut did = format!("did:web:{}", encode_port_separator(&self.host));
        for segment in &self.path {
            did.push(':');
            did.push_str(segment);
        }
        did.push(':');
        did.push_str(&self.aid);
        did
    }
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

/// `:` to `%3A`, for writing a host back into a DID.
fn encode_port_separator(host: &str) -> String {
    host.replace(':', "%3A")
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
        let d = DidWebs::parse(&format!("did:webs:example.com:{AID}#key-0")).expect("valid");
        assert_eq!(d.aid(), AID);
        let d = DidWebs::parse(&format!("did:webs:example.com:{AID}?versionId=1")).expect("valid");
        assert_eq!(d.aid(), AID);
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

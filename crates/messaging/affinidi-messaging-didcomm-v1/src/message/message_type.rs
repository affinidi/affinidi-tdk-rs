//! v1 message type URIs, which come in **two interchangeable forms**.
//!
//! # The two prefixes
//!
//! A DIDComm v1 message type is `<document-uri>/<protocol>/<version>/<name>`,
//! and the document URI is one of two strings that mean exactly the same thing:
//!
//! ```text
//! did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/basicmessage/1.0/message   (legacy)
//! https://didcomm.org/basicmessage/1.0/message                   (RFC 0348)
//! ```
//!
//! Aries RFC 0348 introduced the second and requires implementations to
//! **accept both**. Which one an agent *sends* is a configuration choice, not a
//! protocol version: Credo exposes it as `useDidSovPrefixWhereAllowed` and
//! defaults to the `https://didcomm.org` form — verified against a live agent,
//! whose `routing/1.0/forward` arrives with the modern prefix even though
//! almost every specification example shows the legacy one.
//!
//! Comparing type URIs with `==` therefore silently drops half the ecosystem,
//! in a way that looks like "the peer sent an unknown message type" rather than
//! like a bug. [`types_match`] is the comparison to use.
//!
//! There is no v2.1 counterpart to any of this: v2.1 has a single
//! `https://didcomm.org/...` form.
//!
//! # Which form to send
//!
//! [`TypeFormat::DidSov`] is this crate's default, because the compatibility is
//! asymmetric: pre-RFC-0348 agents understand *only* the legacy form, while
//! every agent that understands the modern form also accepts the legacy one.
//! Callers that prefer the modern form can ask for it explicitly.

use crate::error::DIDCommV1Error;

/// The legacy document URI, from the Sovrin genesis DID.
pub const DID_SOV_DOCUMENT_URI: &str = "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec";
/// The RFC 0348 document URI.
pub const DIDCOMM_ORG_DOCUMENT_URI: &str = "https://didcomm.org";

/// Which document URI to emit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum TypeFormat {
    /// `did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/…` — understood by every
    /// Aries-lineage agent, including pre-RFC-0348 ones. The default; see the
    /// [module docs](self).
    #[default]
    DidSov,
    /// `https://didcomm.org/…` — RFC 0348, and what Credo emits by default.
    DidCommOrg,
}

/// A parsed v1 message type URI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageType {
    /// The document URI, verbatim as parsed.
    pub document_uri: String,
    /// The protocol name, e.g. `basicmessage`.
    pub protocol_name: String,
    /// The protocol version, e.g. `1.0`.
    pub protocol_version: String,
    /// The message name, e.g. `message`.
    pub message_name: String,
}

impl MessageType {
    /// Parse `<document-uri>/<protocol>/<version>/<name>`.
    ///
    /// The document URI may itself contain `/` (the `https://` form does), so
    /// the split is anchored from the right.
    pub fn parse(uri: &str) -> Result<Self, DIDCommV1Error> {
        let invalid = || {
            DIDCommV1Error::InvalidMessage(format!(
                "`{uri}` is not a v1 message type \
                 (expected <document-uri>/<protocol>/<version>/<name>)"
            ))
        };

        let (rest, message_name) = uri.rsplit_once('/').ok_or_else(invalid)?;
        let (rest, protocol_version) = rest.rsplit_once('/').ok_or_else(invalid)?;
        let (document_uri, protocol_name) = rest.rsplit_once('/').ok_or_else(invalid)?;

        if document_uri.is_empty()
            || protocol_name.is_empty()
            || protocol_version.is_empty()
            || message_name.is_empty()
        {
            return Err(invalid());
        }
        // A version must look like `<major>.<minor>`, or the rightmost-split
        // parse would happily accept an arbitrary path as a message type.
        if !protocol_version
            .split_once('.')
            .is_some_and(|(major, minor)| {
                !major.is_empty()
                    && !minor.is_empty()
                    && major.chars().all(|c| c.is_ascii_digit())
                    && minor.chars().all(|c| c.is_ascii_digit())
            })
        {
            return Err(invalid());
        }

        Ok(Self {
            document_uri: document_uri.to_string(),
            protocol_name: protocol_name.to_string(),
            protocol_version: protocol_version.to_string(),
            message_name: message_name.to_string(),
        })
    }

    /// Render with the given document URI.
    pub fn to_uri(&self, format: TypeFormat) -> String {
        let document_uri = match format {
            TypeFormat::DidSov => DID_SOV_DOCUMENT_URI,
            TypeFormat::DidCommOrg => DIDCOMM_ORG_DOCUMENT_URI,
        };
        format!(
            "{document_uri}/{}/{}/{}",
            self.protocol_name, self.protocol_version, self.message_name
        )
    }

    /// Whether this type names the same protocol message as `other`, treating
    /// the two known document URIs as equivalent.
    ///
    /// A document URI that is neither of the two known prefixes is compared
    /// literally — a third-party protocol namespace is not interchangeable with
    /// anything.
    pub fn matches(&self, other: &MessageType) -> bool {
        self.protocol_name == other.protocol_name
            && self.protocol_version == other.protocol_version
            && self.message_name == other.message_name
            && (self.document_uri == other.document_uri
                || (is_known_document_uri(&self.document_uri)
                    && is_known_document_uri(&other.document_uri)))
    }
}

/// Whether `uri` is one of the two interchangeable v1 document URIs.
pub fn is_known_document_uri(uri: &str) -> bool {
    uri == DID_SOV_DOCUMENT_URI || uri == DIDCOMM_ORG_DOCUMENT_URI
}

/// Whether two message type URIs name the same message.
///
/// **Use this instead of `==`.** See the [module docs](self): `==` rejects every
/// peer that happens to be configured for the other prefix. Unparseable inputs
/// fall back to exact string equality.
pub fn types_match(a: &str, b: &str) -> bool {
    match (MessageType::parse(a), MessageType::parse(b)) {
        (Ok(a), Ok(b)) => a.matches(&b),
        _ => a == b,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LEGACY: &str = "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/basicmessage/1.0/message";
    const MODERN: &str = "https://didcomm.org/basicmessage/1.0/message";

    #[test]
    fn parses_both_document_uris() {
        let legacy = MessageType::parse(LEGACY).unwrap();
        assert_eq!(legacy.document_uri, DID_SOV_DOCUMENT_URI);
        assert_eq!(legacy.protocol_name, "basicmessage");
        assert_eq!(legacy.protocol_version, "1.0");
        assert_eq!(legacy.message_name, "message");

        let modern = MessageType::parse(MODERN).unwrap();
        assert_eq!(modern.document_uri, DIDCOMM_ORG_DOCUMENT_URI);
        assert_eq!(modern.protocol_name, "basicmessage");
    }

    /// The property this module exists for.
    #[test]
    fn the_two_prefixes_are_interchangeable() {
        assert!(types_match(LEGACY, MODERN));
        assert!(types_match(MODERN, LEGACY));
        assert_ne!(LEGACY, MODERN, "...but they are not equal as strings");
    }

    #[test]
    fn different_messages_do_not_match() {
        assert!(!types_match(
            LEGACY,
            "https://didcomm.org/basicmessage/2.0/message"
        ));
        assert!(!types_match(
            LEGACY,
            "https://didcomm.org/routing/1.0/forward"
        ));
        assert!(!types_match(
            LEGACY,
            "https://didcomm.org/basicmessage/1.0/other"
        ));
    }

    /// An unknown namespace is not interchangeable with the standard ones —
    /// otherwise `https://evil.example/basicmessage/1.0/message` would be
    /// accepted as a basic message.
    #[test]
    fn third_party_namespaces_are_compared_literally() {
        assert!(!types_match(
            LEGACY,
            "https://evil.example/basicmessage/1.0/message"
        ));
        assert!(types_match(
            "https://example.org/custom/1.0/ping",
            "https://example.org/custom/1.0/ping"
        ));
    }

    #[test]
    fn renders_either_form() {
        let parsed = MessageType::parse(MODERN).unwrap();
        assert_eq!(parsed.to_uri(TypeFormat::DidSov), LEGACY);
        assert_eq!(parsed.to_uri(TypeFormat::DidCommOrg), MODERN);
        assert_eq!(TypeFormat::default(), TypeFormat::DidSov);
    }

    #[test]
    fn rejects_malformed_types() {
        for bad in [
            "",
            "basicmessage",
            "https://didcomm.org/basicmessage",
            "https://didcomm.org/basicmessage/message",
            // A version that is not <major>.<minor> — otherwise any path parses.
            "https://didcomm.org/a/b/c",
            "https://didcomm.org/basicmessage/1.0/",
        ] {
            assert!(
                MessageType::parse(bad).is_err(),
                "`{bad}` should not parse as a message type"
            );
        }
    }

    /// Unparseable inputs must still compare sanely rather than matching
    /// everything.
    #[test]
    fn unparseable_types_fall_back_to_equality() {
        assert!(types_match("garbage", "garbage"));
        assert!(!types_match("garbage", "other-garbage"));
        assert!(!types_match("garbage", LEGACY));
    }
}

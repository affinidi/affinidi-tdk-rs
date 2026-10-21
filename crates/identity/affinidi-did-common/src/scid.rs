//! The `src` locator of a `did:scid` DID URL.
//!
//! A `did:scid` identity is the DID `did:scid:<format>:<version>:<scid>`. Its
//! `src` query parameter (`did:scid:vh:1:<scid>?src=example.com/alice`) says
//! where the verification metadata is published; it is not part of the
//! identity, and the log can move to another `src` without the DID changing.
//! A reference may carry `src` so that its recipient can resolve it on first
//! contact (`did:scid:vh:1:<scid>?src=example.com#key-1`), while the DID
//! document lists its keys under the DID alone (`did:scid:vh:1:<scid>#key-1`).
//!
//! These helpers compare and look up such references by DID and fragment.
//! They touch nothing but a `did:scid` DID URL whose only query parameter is
//! `src`: another method's query, or a `did:scid` query with other parameters,
//! is part of the reference and is kept.

use std::borrow::Cow;

const PREFIX: &str = "did:scid:";

/// Splits a `did:scid` DID URL with a `src` query into the DID and the source.
fn split_src(did_url: &str) -> Option<(&str, &str, &str)> {
    if !did_url.starts_with(PREFIX) {
        return None;
    }
    let (did, rest) = did_url.split_once('?')?;
    let (query, fragment) = match rest.find('#') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    };
    let src = query.strip_prefix("src=")?;
    if src.is_empty() || src.contains('&') {
        return None;
    }
    Some((did, src, fragment))
}

/// Removes the `src` locator from a `did:scid` DID URL, keeping any fragment.
///
/// `did:scid:vh:1:Qm?src=example.com#key-1` becomes `did:scid:vh:1:Qm#key-1`,
/// and `did:scid:vh:1:Qm?src=example.com` becomes `did:scid:vh:1:Qm`. Anything
/// else is returned unchanged.
pub fn strip_scid_src(did_url: &str) -> Cow<'_, str> {
    match split_src(did_url) {
        Some((did, _, "")) => Cow::Borrowed(did),
        Some((did, _, fragment)) => Cow::Owned(format!("{did}{fragment}")),
        None => Cow::Borrowed(did_url),
    }
}

/// The `src` locator of a `did:scid` DID URL, if it carries one.
pub fn scid_src(did_url: &str) -> Option<&str> {
    split_src(did_url).map(|(_, src, _)| src)
}

/// Gives a bare `did:scid` reference the `src` locator `src`, before any
/// fragment: `did:scid:vh:1:Qm#key-1` becomes
/// `did:scid:vh:1:Qm?src=example.com#key-1`.
///
/// Use this where a recipient resolves the reference before it knows the
/// source, such as a DIDComm `skid`. A reference that is not a bare `did:scid`
/// DID or DID URL with a fragment, or that already carries a query, is returned
/// unchanged.
pub fn with_scid_src(reference: &str, src: &str) -> String {
    if !reference.starts_with(PREFIX) || reference.contains('?') || reference.contains('/') {
        return reference.to_string();
    }
    match reference.split_once('#') {
        Some((did, fragment)) => format!("{did}?src={src}#{fragment}"),
        None => format!("{reference}?src={src}"),
    }
}

/// Whether two references name the same thing, ignoring a `did:scid` `src`.
///
/// Use this, not `==`, to match a key or sender reference against a DID
/// document: a reference may carry the `src` its document does not.
pub fn same_reference(a: &str, b: &str) -> bool {
    a == b || strip_scid_src(a) == strip_scid_src(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_src() {
        assert_eq!(
            strip_scid_src("did:scid:vh:1:Qm?src=example.com/alice"),
            "did:scid:vh:1:Qm"
        );
        assert_eq!(
            strip_scid_src("did:scid:vh:1:Qm?src=localhost%3A8000/a#key-1"),
            "did:scid:vh:1:Qm#key-1"
        );
    }

    #[test]
    fn leaves_everything_else() {
        for did in [
            "did:scid:vh:1:Qm",
            "did:scid:vh:1:Qm#key-1",
            "did:scid:vh:1:Qm?src=example.com&versionId=2",
            "did:scid:vh:1:Qm?versionId=2#key-1",
            "did:scid:vh:1:Qm?src=",
            "did:webvh:Qm:example.com?versionId=1#key-1",
            "did:example:123?src=example.com",
        ] {
            assert_eq!(strip_scid_src(did), did, "{did}");
        }
    }

    #[test]
    fn src_is_read() {
        assert_eq!(
            scid_src("did:scid:vh:1:Qm?src=example.com/alice#k"),
            Some("example.com/alice")
        );
        assert_eq!(scid_src("did:scid:vh:1:Qm"), None);
    }

    #[test]
    fn src_is_added_to_a_bare_reference() {
        assert_eq!(
            with_scid_src("did:scid:vh:1:Qm#key-1", "example.com/alice"),
            "did:scid:vh:1:Qm?src=example.com/alice#key-1"
        );
        assert_eq!(
            with_scid_src("did:scid:vh:1:Qm", "example.com"),
            "did:scid:vh:1:Qm?src=example.com"
        );
        for unchanged in [
            "did:scid:vh:1:Qm?src=a.example#key-1",
            "did:webvh:Qm:example.com#key-1",
        ] {
            assert_eq!(with_scid_src(unchanged, "b.example"), unchanged);
        }
    }

    #[test]
    fn references_match_by_did_and_fragment() {
        assert!(same_reference(
            "did:scid:vh:1:Qm?src=example.com#key-1",
            "did:scid:vh:1:Qm#key-1"
        ));
        assert!(same_reference(
            "did:scid:vh:1:Qm?src=a.example#key-1",
            "did:scid:vh:1:Qm?src=b.example#key-1"
        ));
        assert!(!same_reference(
            "did:scid:vh:1:Qm?src=example.com#key-1",
            "did:scid:vh:1:Qm#key-2"
        ));
        assert!(!same_reference(
            "did:scid:vh:1:Qm#key-1",
            "did:webvh:Qm:example.com#key-1"
        ));
    }
}

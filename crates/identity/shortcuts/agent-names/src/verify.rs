//! Layer-1 anti-spoofing: does the DID actually claim this name back?

use affinidi_did_common::Document;

use crate::{error::AgentNameError, name::AgentName};

/// Verify that `doc` claims `name` via `alsoKnownAs`.
///
/// This is the **mandatory** Layer-1 check from the agent name specification.
/// Resolving a name yields a DID by following a redirect that the name's own
/// web server controls — so on its own it proves nothing: anyone can publish a
/// redirect pointing at somebody else's DID. Only the DID's controller can add
/// an `alsoKnownAs` entry to its DID Document, so requiring the document to
/// name the shortcut back is what makes the binding two-sided.
///
/// # What this does and does not buy you
///
/// It stops an unrelated party from pointing a name they control at a DID they
/// do not. It does **not** survive DNS poisoning or a breach of the name's own
/// web server — an attacker with either can serve a redirect to a DID they
/// control whose document legitimately claims the name. Defending against that
/// is Layer 2 (the agent name credential), which this crate does not implement.
///
/// # Matching
///
/// Both sides are canonicalised before comparison, so all the spellings of one
/// name agree (host case, default port, trailing slash — see [`AgentName`]).
/// An entry that cannot be parsed as an agent name (a plain `did:` URI, say) is
/// skipped rather than treated as an error, since `alsoKnownAs` legitimately
/// holds other identifier types.
///
/// Matching is exact after canonicalisation. There is deliberately no prefix or
/// wildcard matching: `example.com/@alice` must not be satisfied by an entry for
/// `example.com/@alicia`, nor a path-qualified name by its bare parent.
pub fn verify_also_known_as(doc: &Document, name: &AgentName) -> Result<(), AgentNameError> {
    if also_known_as_contains(doc, name) {
        return Ok(());
    }
    Err(AgentNameError::NotAuthorized {
        name: name.as_str().to_string(),
        did: doc.id.to_string(),
    })
}

/// The predicate behind [`verify_also_known_as`], for callers who want a `bool`.
pub fn also_known_as_contains(doc: &Document, name: &AgentName) -> bool {
    doc.also_known_as
        .iter()
        .any(|entry| entry_matches(entry, name))
}

fn entry_matches(entry: &str, name: &AgentName) -> bool {
    // Canonicalise the document's entry the same way we canonicalised the
    // requested name, so cosmetic differences do not cause a false negative.
    if let Ok(parsed) = AgentName::parse(entry) {
        return parsed == *name;
    }
    // Not parseable as an agent name (e.g. a `did:` URI): fall back to an exact
    // match against both canonical spellings, then give up.
    entry == name.as_str() || entry == name.without_scheme()
}

/// Every entry in `doc`'s `alsoKnownAs` that is a well-formed agent name.
///
/// This is the **authoritative** direction for DID → name: the document says
/// which names it claims. There is deliberately no helper that constructs a
/// likely agent name from a `did:web` / `did:webvh` domain — the name→DID link
/// is a web redirect and is not derivable from DID structure, so a "candidate
/// name" would be an unverified guess wearing an authoritative-looking API.
pub fn extract_agent_names(doc: &Document) -> Vec<AgentName> {
    doc.also_known_as
        .iter()
        .filter_map(|entry| AgentName::parse(entry).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use affinidi_did_common::DocumentBuilder;

    fn doc_with(aka: &[&str]) -> Document {
        DocumentBuilder::new("did:webvh:QmScid:example.com")
            .unwrap()
            .also_known_as_many(aka.iter().copied())
            .build()
    }

    fn name(s: &str) -> AgentName {
        AgentName::parse(s).unwrap()
    }

    // --- accept ---

    #[test]
    fn accepts_exact_match() {
        let doc = doc_with(&["https://example.com/@alice"]);
        assert!(verify_also_known_as(&doc, &name("example.com/@alice")).is_ok());
    }

    #[test]
    fn accepts_scheme_less_entry() {
        let doc = doc_with(&["example.com/@alice"]);
        assert!(verify_also_known_as(&doc, &name("https://example.com/@alice")).is_ok());
    }

    #[test]
    fn accepts_entry_with_trailing_slash() {
        let doc = doc_with(&["https://example.com/@alice/"]);
        assert!(verify_also_known_as(&doc, &name("example.com/@alice")).is_ok());
    }

    #[test]
    fn accepts_entry_with_different_host_case() {
        let doc = doc_with(&["https://EXAMPLE.com/@alice"]);
        assert!(verify_also_known_as(&doc, &name("example.com/@alice")).is_ok());
    }

    #[test]
    fn accepts_when_one_of_several_entries_matches() {
        let doc = doc_with(&[
            "did:web:other.example",
            "https://other.com/@bob",
            "https://example.com/@alice",
        ]);
        assert!(verify_also_known_as(&doc, &name("example.com/@alice")).is_ok());
    }

    #[test]
    fn accepts_path_qualified_name() {
        let doc = doc_with(&["https://firstperson.network/@drummond/h2hsummit"]);
        assert!(
            verify_also_known_as(&doc, &name("firstperson.network/@drummond/h2hsummit")).is_ok()
        );
    }

    // --- reject ---

    #[test]
    fn rejects_empty_also_known_as() {
        let doc = doc_with(&[]);
        let err = verify_also_known_as(&doc, &name("example.com/@alice")).unwrap_err();
        assert!(matches!(err, AgentNameError::NotAuthorized { .. }));
    }

    #[test]
    fn rejects_different_local_name() {
        let doc = doc_with(&["https://example.com/@alicia"]);
        assert!(verify_also_known_as(&doc, &name("example.com/@alice")).is_err());
    }

    #[test]
    fn rejects_different_host() {
        let doc = doc_with(&["https://evil.com/@alice"]);
        assert!(verify_also_known_as(&doc, &name("example.com/@alice")).is_err());
    }

    /// Case matters in the local part; `@Alice` must not satisfy `@alice`.
    #[test]
    fn rejects_local_name_case_difference() {
        let doc = doc_with(&["https://example.com/@Alice"]);
        assert!(verify_also_known_as(&doc, &name("example.com/@alice")).is_err());
    }

    /// No prefix matching: a bare name must not satisfy a path-qualified one.
    #[test]
    fn rejects_parent_name_for_path_qualified_request() {
        let doc = doc_with(&["https://firstperson.network/@drummond"]);
        assert!(
            verify_also_known_as(&doc, &name("firstperson.network/@drummond/h2hsummit")).is_err()
        );
    }

    /// …and the reverse: a path-qualified entry must not satisfy the bare name.
    #[test]
    fn rejects_path_qualified_entry_for_parent_request() {
        let doc = doc_with(&["https://firstperson.network/@drummond/h2hsummit"]);
        assert!(verify_also_known_as(&doc, &name("firstperson.network/@drummond")).is_err());
    }

    // --- the community name ---

    #[test]
    fn accepts_community_name_claimed_by_the_document() {
        let doc = doc_with(&["https://example.com/@"]);
        assert!(verify_also_known_as(&doc, &name("example.com/@")).is_ok());
    }

    #[test]
    fn accepts_scheme_less_community_entry() {
        let doc = doc_with(&["example.com/@"]);
        assert!(verify_also_known_as(&doc, &name("https://example.com/@")).is_ok());
    }

    /// The community name is not a prefix of the names under it: holding
    /// `example.com/@` must not let a document answer for `@alice`.
    #[test]
    fn rejects_community_entry_for_a_named_agent_request() {
        let doc = doc_with(&["https://example.com/@"]);
        assert!(verify_also_known_as(&doc, &name("example.com/@alice")).is_err());
    }

    /// …and the reverse: an agent under the domain does not answer for the VTC.
    #[test]
    fn rejects_named_agent_entry_for_a_community_request() {
        let doc = doc_with(&["https://example.com/@alice"]);
        assert!(verify_also_known_as(&doc, &name("example.com/@")).is_err());
    }

    #[test]
    fn rejects_community_name_of_a_different_domain() {
        let doc = doc_with(&["https://evil.com/@"]);
        assert!(verify_also_known_as(&doc, &name("example.com/@")).is_err());
    }

    /// A near-miss that a naive `contains()` would wrongly accept.
    #[test]
    fn rejects_substring_near_miss() {
        let doc = doc_with(&["https://example.com/@alice-evil"]);
        assert!(verify_also_known_as(&doc, &name("example.com/@alice")).is_err());
    }

    #[test]
    fn rejects_different_port() {
        let doc = doc_with(&["https://example.com:8443/@alice"]);
        assert!(verify_also_known_as(&doc, &name("example.com/@alice")).is_err());
    }

    #[test]
    fn error_names_both_sides() {
        let doc = doc_with(&[]);
        let msg = verify_also_known_as(&doc, &name("example.com/@alice"))
            .unwrap_err()
            .to_string();
        assert!(msg.contains("example.com/@alice"));
        assert!(msg.contains("did:webvh:QmScid:example.com"));
    }

    // --- extraction ---

    #[test]
    fn extracts_only_well_formed_agent_names() {
        let doc = doc_with(&[
            "https://example.com/@alice",
            "did:web:other.example",
            "https://example.com/not-an-agent-name",
            "example.com/@bob",
        ]);
        let names: Vec<String> = extract_agent_names(&doc)
            .iter()
            .map(|n| n.as_str().to_string())
            .collect();
        assert_eq!(
            names,
            ["https://example.com/@alice", "https://example.com/@bob"]
        );
    }

    #[test]
    fn extracts_nothing_from_empty_document() {
        assert!(extract_agent_names(&doc_with(&[])).is_empty());
    }
}

//! Convert a `did:webvh` DID document into its wire-compatible `did:web`
//! form.
//!
//! `did:webvh` and `did:web` are wire-compatible by design: a
//! `did:webvh:{scid}:{domain}` DID resolves to the same document as
//! `did:web:{domain}` once the self-certifying identifier (SCID) is
//! dropped and every *self-reference* in the document is rewritten. Only
//! the document's own DID (and DID URLs derived from it — `{did}#frag`,
//! `{did}?query`, `{did}/path`) is rewritten; foreign DIDs, longer DIDs
//! that merely share the prefix, and values that merely embed the DID as a
//! substring (e.g. a `serviceEndpoint` URL) are left verbatim.
//!
//! Two consumers share this logic:
//! - the mediator runtime, which rewrites the DID document it serves at
//!   `/.well-known/did.json` so `did:web` resolvers receive a document
//!   whose `id` (and every key / service self-reference) matches
//!   `did:web:{domain}` (the `did.jsonl` log stream stays verbatim);
//! - the `mediator-setup` wizard, which writes a standalone `did-web.json`
//!   operator artefact via [`webvh_log_to_did_web`].

use serde_json::Value;
use thiserror::Error;

/// Errors raised while rewriting a `did:webvh` document to `did:web`.
#[derive(Debug, Error)]
pub enum DidWebRewriteError {
    /// The supplied identifier is not a `did:webvh` DID.
    #[error("not a did:webvh DID: {0}")]
    NotWebvh(String),
    /// The `did:webvh` identifier has an empty SCID segment.
    #[error("did:webvh DID has an empty SCID: {0}")]
    EmptyScid(String),
    /// The `did:webvh` identifier is missing its domain segment.
    #[error("malformed did:webvh DID (missing domain): {0}")]
    MissingDomain(String),
    /// The `did:webvh` identifier has an empty domain segment.
    #[error("did:webvh DID has an empty domain: {0}")]
    EmptyDomain(String),
    /// The log entry envelope had no `state` (DID document) field.
    #[error("did:webvh log entry has no `state` (DID document)")]
    MissingState,
    /// (De)serialising the DID document failed.
    #[error("DID document JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

/// Map a `did:webvh:{scid}:{domain}[:path…]` identifier to its
/// `did:web:{domain}[:path…]` equivalent by dropping the SCID segment.
/// Path segments (`:`-separated, did:web style) are preserved verbatim.
pub fn webvh_did_to_web(webvh_did: &str) -> Result<String, DidWebRewriteError> {
    let rest = webvh_did
        .strip_prefix("did:webvh:")
        .ok_or_else(|| DidWebRewriteError::NotWebvh(webvh_did.to_string()))?;
    let (scid, domain_and_path) = rest
        .split_once(':')
        .ok_or_else(|| DidWebRewriteError::MissingDomain(webvh_did.to_string()))?;
    if scid.is_empty() {
        return Err(DidWebRewriteError::EmptyScid(webvh_did.to_string()));
    }
    if domain_and_path.is_empty() {
        return Err(DidWebRewriteError::EmptyDomain(webvh_did.to_string()));
    }
    Ok(format!("did:web:{domain_and_path}"))
}

/// Rewrite an already-resolved DID document (a webvh log entry's `state`)
/// from its `did:webvh` identifier into the equivalent `did:web` form,
/// returning `(did:web identifier, rewritten document)`.
///
/// Every string in the document that is a *DID URL of `webvh_did`* — the
/// bare DID, or the DID followed by a `#fragment`, `?query`, or `/path`
/// component — is rewritten to its `did:web` form (`id`, `controller`,
/// `{did}#key-0`, service ids, verification-relationship references …).
/// Strings that merely contain the DID as a substring are left verbatim:
/// a foreign `did:webvh:` DID, a longer DID sharing the prefix
/// (`{did}:tenant`), and a `serviceEndpoint` URL embedding the DID in a
/// query parameter are all untouched.
pub fn rewrite_did_document_to_web(
    state: &Value,
    webvh_did: &str,
) -> Result<(String, Value), DidWebRewriteError> {
    let web_did = webvh_did_to_web(webvh_did)?;
    let mut doc = state.clone();
    rewrite_self_references(&mut doc, webvh_did, &web_did);
    Ok((web_did, doc))
}

/// Recursively walk a JSON value, rewriting every DID-URL self-reference of
/// `webvh_did` (see [`rewrite_did_url`]) to its `web_did` form.
fn rewrite_self_references(value: &mut Value, webvh_did: &str, web_did: &str) {
    match value {
        Value::String(s) => {
            if let Some(rewritten) = rewrite_did_url(s, webvh_did, web_did) {
                *s = rewritten;
            }
        }
        Value::Array(items) => {
            for item in items {
                rewrite_self_references(item, webvh_did, web_did);
            }
        }
        Value::Object(map) => {
            for value in map.values_mut() {
                rewrite_self_references(value, webvh_did, web_did);
            }
        }
        _ => {}
    }
}

/// If `s` is a DID URL of `webvh_did` — exactly the DID, or the DID followed
/// by a DID-URL delimiter (`#`, `?`, `/`) — return it rewritten onto
/// `web_did` with the trailing component preserved. Otherwise (a different
/// DID, a longer DID sharing the prefix such as `{did}:tenant`, or the DID
/// embedded mid-string) return `None` so the value is left verbatim.
fn rewrite_did_url(s: &str, webvh_did: &str, web_did: &str) -> Option<String> {
    let rest = s.strip_prefix(webvh_did)?;
    if rest.is_empty() || rest.starts_with(['#', '?', '/']) {
        Some(format!("{web_did}{rest}"))
    } else {
        None
    }
}

/// Convert a full `did:webvh` log entry (the envelope carrying `state`)
/// into the equivalent `did:web` DID document, returning the `did:web`
/// identifier and the pretty-printed document.
///
/// Used by `mediator-setup` to write the standalone `did-web.json`
/// operator artefact. The runtime, which already holds the extracted
/// `state`, calls [`rewrite_did_document_to_web`] directly.
pub fn webvh_log_to_did_web(
    log_entry_json: &str,
    webvh_did: &str,
) -> Result<(String, String), DidWebRewriteError> {
    let entry: Value = serde_json::from_str(log_entry_json)?;
    let state = entry.get("state").ok_or(DidWebRewriteError::MissingState)?;
    let (web_did, doc) = rewrite_did_document_to_web(state, webvh_did)?;
    let pretty = serde_json::to_string_pretty(&doc)?;
    Ok((web_did, pretty))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn webvh_did_to_web_drops_scid() {
        assert_eq!(
            webvh_did_to_web("did:webvh:QmScId:mediator.example.com").unwrap(),
            "did:web:mediator.example.com"
        );
    }

    #[test]
    fn webvh_did_to_web_preserves_path_segments() {
        assert_eq!(
            webvh_did_to_web("did:webvh:QmScId:example.com:mediators:m1").unwrap(),
            "did:web:example.com:mediators:m1"
        );
    }

    #[test]
    fn webvh_did_to_web_rejects_non_webvh_and_malformed() {
        assert!(matches!(
            webvh_did_to_web("did:web:example.com"),
            Err(DidWebRewriteError::NotWebvh(_))
        ));
        assert!(matches!(
            webvh_did_to_web("did:webvh:QmScId"),
            Err(DidWebRewriteError::MissingDomain(_))
        ));
        assert!(matches!(
            webvh_did_to_web("did:webvh:QmScId:"),
            Err(DidWebRewriteError::EmptyDomain(_))
        ));
        assert!(matches!(
            webvh_did_to_web("did:webvh::example.com"),
            Err(DidWebRewriteError::EmptyScid(_))
        ));
    }

    #[test]
    fn rewrite_document_rewrites_every_self_reference() {
        let webvh_did = "did:webvh:QmScId:mediator.example.com";
        let state = json!({
            "id": webvh_did,
            "controller": webvh_did,
            "verificationMethod": [
                { "id": format!("{webvh_did}#key-0"), "controller": webvh_did, "type": "Multikey" },
                { "id": format!("{webvh_did}#key-1"), "controller": webvh_did, "type": "Multikey" }
            ],
            "service": [
                { "id": format!("{webvh_did}#service"), "type": ["DIDCommMessaging"] }
            ]
        });

        let (web_did, doc) = rewrite_did_document_to_web(&state, webvh_did).unwrap();
        assert_eq!(web_did, "did:web:mediator.example.com");

        let doc_str = serde_json::to_string(&doc).unwrap();
        assert!(!doc_str.contains("did:webvh:"));
        assert_eq!(doc["id"], web_did);
        assert_eq!(doc["controller"], web_did);
        for vm in doc["verificationMethod"].as_array().unwrap() {
            assert!(vm["id"].as_str().unwrap().starts_with("did:web:"));
            assert_eq!(vm["controller"], web_did);
        }
        assert!(
            doc["service"][0]["id"]
                .as_str()
                .unwrap()
                .starts_with("did:web:")
        );
    }

    #[test]
    fn rewrite_leaves_foreign_and_substring_references_verbatim() {
        let webvh_did = "did:webvh:QmScId:mediator.example.com";
        let foreign = "did:webvh:QmOther:org.example.com";
        let sub_did = format!("{webvh_did}:tenant1");
        let state = json!({
            "id": webvh_did,
            // A delegated controller owned by another entity — not ours to rewrite.
            "controller": foreign,
            // A longer DID that merely shares our DID as a prefix.
            "alsoKnownAs": [sub_did],
            "service": [
                {
                    "id": format!("{webvh_did}#relay"),
                    "type": ["DIDCommMessaging"],
                    // The DID embedded inside an endpoint URL's query string.
                    "serviceEndpoint": format!("https://gw.example/resolve?did={webvh_did}")
                }
            ]
        });

        let (web_did, doc) = rewrite_did_document_to_web(&state, webvh_did).unwrap();

        // Our own self-references are rewritten…
        assert_eq!(doc["id"], web_did);
        assert_eq!(doc["service"][0]["id"], format!("{web_did}#relay"));
        // …but foreign DIDs, prefix-sharing DIDs, and embedded substrings are not.
        assert_eq!(doc["controller"], foreign);
        assert_eq!(doc["alsoKnownAs"][0], sub_did);
        assert_eq!(
            doc["service"][0]["serviceEndpoint"],
            format!("https://gw.example/resolve?did={webvh_did}")
        );
    }

    #[test]
    fn log_to_did_web_extracts_state() {
        let webvh_did = "did:webvh:QmScId:example.com";
        let log = json!({
            "versionId": "1-abc",
            "state": { "id": webvh_did }
        })
        .to_string();

        let (web_did, pretty) = webvh_log_to_did_web(&log, webvh_did).unwrap();
        assert_eq!(web_did, "did:web:example.com");
        let doc: Value = serde_json::from_str(&pretty).unwrap();
        assert_eq!(doc["id"], "did:web:example.com");
    }

    #[test]
    fn log_to_did_web_errors_without_state() {
        let err = webvh_log_to_did_web(r#"{"versionId":"1-abc"}"#, "did:webvh:QmScId:example.com")
            .unwrap_err();
        assert!(matches!(err, DidWebRewriteError::MissingState));
        assert!(err.to_string().contains("state"));
    }
}

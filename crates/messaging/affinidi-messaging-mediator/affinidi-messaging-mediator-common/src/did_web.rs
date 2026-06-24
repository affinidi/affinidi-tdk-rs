//! Convert a `did:webvh` DID document into its wire-compatible `did:web`
//! form.
//!
//! `did:webvh` and `did:web` are wire-compatible by design: a
//! `did:webvh:{scid}:{domain}` DID resolves to the same document as
//! `did:web:{domain}` once the self-certifying identifier (SCID) is
//! dropped and every self-reference in the document is rewritten.
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
    let (_scid, domain_and_path) = rest
        .split_once(':')
        .ok_or_else(|| DidWebRewriteError::MissingDomain(webvh_did.to_string()))?;
    if domain_and_path.is_empty() {
        return Err(DidWebRewriteError::EmptyDomain(webvh_did.to_string()));
    }
    Ok(format!("did:web:{domain_and_path}"))
}

/// Rewrite an already-resolved DID document (a webvh log entry's `state`)
/// from its `did:webvh` identifier into the equivalent `did:web` form,
/// returning `(did:web identifier, rewritten document)`.
///
/// In the resolved state the DID always appears in full (`id`,
/// `controller`, `{did}#key-0`, service ids …), so a whole-string swap of
/// the webvh DID for its did:web form rewrites them all without touching
/// unrelated values. `web_did` never contains `webvh_did`, so the
/// replacement can't recurse.
pub fn rewrite_did_document_to_web(
    state: &Value,
    webvh_did: &str,
) -> Result<(String, Value), DidWebRewriteError> {
    let web_did = webvh_did_to_web(webvh_did)?;
    let rewritten = serde_json::to_string(state)?.replace(webvh_did, &web_did);
    let doc: Value = serde_json::from_str(&rewritten)?;
    Ok((web_did, doc))
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

//! Resolving a `did:webs` identifier from its published artifacts.
//!
//! The document a resolver returns is *derived* from the verified key event
//! log, never copied from the published `did.json`. `did.json` is checked
//! against that derivation, and a disagreement is an error — not a choice
//! between two answers.

use affinidi_did_common::Document;
use serde_json::Value;

use tracing::warn;

use crate::aliases::designated_aliases;
use crate::document::document_from_keys;
use crate::errors::DidWebsError;
use crate::identifier::DidWebs;
use crate::kel::Kels;

/// Resolve a `did:webs` identifier from artifacts already fetched.
///
/// `keri_cesr` is required and is the only thing that carries authority.
/// `did_json` is optional: when supplied it is cross-checked against the
/// derived document, and a mismatch fails the resolution.
///
/// # Errors
/// Returns [`DidWebsError`] if the stream cannot be read, the key event log
/// does not verify, or `did.json` disagrees with the verified key state.
pub fn resolve_from_artifacts(
    did: &DidWebs,
    keri_cesr: &[u8],
    did_json: Option<&[u8]>,
) -> Result<Document, DidWebsError> {
    let kels = Kels::parse(keri_cesr)?;
    let state = kels.key_state(did.aid())?;

    // The AID is the identifier the KEL establishes. If the stream verified
    // some *other* identifier's log, resolving would return keys that were
    // never bound to this DID.
    if state.prefix != did.aid() {
        return Err(DidWebsError::Kel(format!(
            "verified key state is for {}, not the AID in the DID ({})",
            state.prefix,
            did.aid(),
        )));
    }

    // Aliases are only ever taken from a verified designated-aliases
    // attestation. A stream carrying one that does not verify yields no
    // aliases and a logged reason, rather than failing the whole resolution:
    // the key material is still sound, and refusing to resolve would make a
    // broken attestation a denial of service on the identifier.
    let designated = designated_aliases(&kels, did.aid())?;
    if let Some(reason) = &designated.rejected {
        warn!("{}: designated aliases not used: {reason}", did.did());
    }

    let document = document_from_keys(did, &state.keys, &designated.aliases)?;

    if let Some(published) = did_json {
        let published: Value = serde_json::from_slice(published)?;
        check_published_document(did, &state.keys, &published)?;
    }

    Ok(document)
}

/// Check a published `did.json` against the verified key state.
///
/// Two things are compared, and only two: the document's `id`, and the public
/// keys it publishes. Everything else a `did.json` may carry — services,
/// `alsoKnownAs` beyond the `did:web` twin — is not derivable from a key event
/// log, so this cannot say anything about it either way. What it can say is
/// that the published document does not name a *different* identifier or
/// publish keys the KEL never authorised.
fn check_published_document(
    did: &DidWebs,
    keys: &[String],
    published: &Value,
) -> Result<(), DidWebsError> {
    let id = published
        .get("id")
        .and_then(Value::as_str)
        .ok_or_else(|| DidWebsError::DocumentMismatch("did.json has no `id`".into()))?;

    // A did:webs document is shared with its did:web twin at the same URL, and
    // the published copy carries the did:web form. Both are the same
    // identifier, so either is acceptable — anything else is not.
    //
    // Compared with percent-encoding normalised: RFC 3986 makes `%3a` and
    // `%3A` equivalent, and real artifacts write the port separator lowercase
    // while the specification writes it uppercase. Comparing the raw strings
    // rejects every published document.
    let twin = did.did_web_twin();
    let id_norm = normalize_percent_encoding(id);
    if id_norm != normalize_percent_encoding(did.did())
        && id_norm != normalize_percent_encoding(&twin)
    {
        return Err(DidWebsError::DocumentMismatch(format!(
            "did.json is for {id:?}, which is neither {:?} nor its did:web twin {twin:?}",
            did.did(),
        )));
    }

    let published_keys = published_key_ids(published);

    // Every key the KEL authorises must be published, and nothing beyond them.
    // A published key the KEL never established is the case that matters: it
    // would otherwise be handed to a caller as though the KEL had authorised it.
    for key in keys {
        if !published_keys.iter().any(|k| k == key) {
            return Err(DidWebsError::DocumentMismatch(format!(
                "did.json does not publish {key:?}, which the verified key state authorises"
            )));
        }
    }
    for published_key in &published_keys {
        if !keys.iter().any(|k| k == published_key) {
            return Err(DidWebsError::DocumentMismatch(format!(
                "did.json publishes {published_key:?}, which the verified key event log \
                 never authorised"
            )));
        }
    }

    Ok(())
}

/// Uppercase the hex digits of every percent-encoded triplet.
///
/// RFC 3986 §6.2.2.1: percent-encoding is case-insensitive, and uppercase is
/// the normalised form. `did:webs` artifacts in the wild write the port
/// separator as `%3a`; the specification writes `%3A`.
fn normalize_percent_encoding(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && bytes[i + 1].is_ascii_hexdigit()
            && bytes[i + 2].is_ascii_hexdigit()
        {
            out.push('%');
            out.push(bytes[i + 1].to_ascii_uppercase() as char);
            out.push(bytes[i + 2].to_ascii_uppercase() as char);
            i += 3;
        } else {
            out.push(bytes[i] as char);
            i += 1;
        }
    }
    out
}

/// The CESR keys a published document names in its verification methods.
///
/// `did:webs` identifies a verification method by the key's own CESR encoding,
/// as both the `kid` of the JWK and the fragment of the method's id, so either
/// gives the key without having to re-encode the JWK to compare it.
fn published_key_ids(published: &Value) -> Vec<String> {
    let Some(methods) = published
        .get("verificationMethod")
        .and_then(Value::as_array)
    else {
        return Vec::new();
    };

    methods
        .iter()
        .filter_map(|vm| {
            vm.get("publicKeyJwk")
                .and_then(|jwk| jwk.get("kid"))
                .and_then(Value::as_str)
                .or_else(|| {
                    vm.get("id")
                        .and_then(Value::as_str)
                        .and_then(|id| id.rsplit('#').next())
                })
                .map(str::to_string)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::normalize_percent_encoding;

    #[test]
    fn percent_encoding_case_is_normalised() {
        assert_eq!(
            normalize_percent_encoding("did:web:host%3a7676:E123"),
            "did:web:host%3A7676:E123",
        );
        // Already normalised, and untouched elsewhere.
        assert_eq!(
            normalize_percent_encoding("did:web:host%3A7676:E123"),
            "did:web:host%3A7676:E123",
        );
        // A bare `%` that is not a valid triplet is left alone rather than
        // eaten, so a malformed id cannot be normalised into a valid one.
        assert_eq!(normalize_percent_encoding("100%"), "100%");
        assert_eq!(normalize_percent_encoding("a%zz"), "a%zz");
    }
}

//! Resolving a `did:webs` identifier from its published artifacts.
//!
//! The document a resolver returns is *derived* from the verified key event
//! stream, never copied from the published `did.json` (§ Read (Resolve)):
//!
//! 1. the whole `keri.cesr` stream verifies — every event, signature,
//!    pre-rotation commitment, delegation and witness receipt;
//! 2. with `versionId`, only events up to that sequence number are used from
//!    there on;
//! 3. a valid, unrevoked designated-aliases attestation authorises the DID
//!    being resolved — without one the stream does not publish this DID, and
//!    resolution fails;
//! 4. the document is derived from that state;
//! 5. the published `did.json`, transformed back from its `did:web` form, must
//!    agree with the derivation, and a disagreement is an error rather than a
//!    choice between two answers.
//!
//! # Comparing the published document
//!
//! The specification requires the derived and published documents to be
//! equal. Implementations differ in what they publish — the reference
//! implementation lists the subject in its own `alsoKnownAs` and omits the
//! top-level `controller` and the `authentication` / `assertionMethod`
//! relationships — so equality here is semantic:
//!
//! * `id`, every verification method, every service and every alias must
//!   match, as sets, with relative and absolute references treated alike and
//!   the subject's alias of itself ignored;
//! * `controller` and each verification relationship must match **when
//!   published**; omitting `controller`, `authentication` or
//!   `assertionMethod` is accepted, because those are derived from the key
//!   state regardless;
//! * any other member is a disagreement, except `@context`.
//!
//! A published document can therefore leave out what the derivation implies,
//! but never add to it or change it.

use affinidi_did_common::Document;
use serde_json::{Map, Value, json};

use crate::aliases::designated_aliases;
use crate::document::{RELATIONSHIPS, derive_document, from_did_web, into_document, same_did};
use crate::errors::DidWebsError;
use crate::identifier::DidWebs;
use crate::kel::Kels;
use crate::services::{delegator_service, role_endpoints, witness_endpoints};

/// A resolved document with the DID document metadata the method defines.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Resolution {
    /// The `did:webs` DID document.
    pub document: Document,
    /// Its metadata.
    pub metadata: DocumentMetadata,
}

/// DID document metadata (§ DID Metadata).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct DocumentMetadata {
    /// The sequence number of the last key event the document reflects.
    pub version_id: u64,
    /// The sequence number of the next key event, when the document was
    /// resolved as of a version that is not the latest.
    pub next_version_id: Option<u64>,
    /// The other `did:webs` identifiers the AID designated for itself.
    pub equivalent_id: Vec<String>,
    /// Whether the identifier has been deactivated: its last rotation
    /// committed to no next keys (§ Deactivate).
    pub deactivated: bool,
}

impl DocumentMetadata {
    /// The metadata as a DID Resolution `didDocumentMetadata` object.
    pub fn to_json(&self) -> Value {
        let mut out = Map::new();
        out.insert("versionId".into(), json!(self.version_id.to_string()));
        if let Some(next) = self.next_version_id {
            out.insert("nextVersionId".into(), json!(next.to_string()));
        }
        if !self.equivalent_id.is_empty() {
            out.insert("equivalentId".into(), json!(self.equivalent_id));
        }
        if self.deactivated {
            out.insert("deactivated".into(), json!(true));
        }
        Value::Object(out)
    }
}

/// What a stream implies for a DID: the document in its `did:webs` form, its
/// metadata, and whether the `did:web` twin is designated (the precondition
/// for publishing or reading the `did:web` form).
pub(crate) struct Derived {
    pub document: Value,
    pub metadata: DocumentMetadata,
    pub twin_designated: bool,
    /// The SAID a `DelegatorOOBI` service of this DID must carry, when the
    /// identifier is delegated.
    pub delegation_seal: Option<String>,
}

/// Resolve a `did:webs` identifier from artifacts already fetched.
///
/// `keri_cesr` is the only thing that carries authority. `did_json` is
/// cross-checked against the derived document, and a mismatch fails the
/// resolution. A conforming resolution needs both (§ Read: a failed fetch of
/// either fails it); `None` is accepted here for verifying a stream offline,
/// and [`crate::WebsResolver`] never passes it.
///
/// # Errors
/// Returns [`DidWebsError`] if the stream cannot be read, the key event log
/// does not verify, the DID is not designated by its AID, or `did.json`
/// disagrees with the verified state.
pub fn resolve_from_artifacts(
    did: &DidWebs,
    keri_cesr: &[u8],
    did_json: Option<&[u8]>,
) -> Result<Document, DidWebsError> {
    resolve_with_metadata(did, keri_cesr, did_json).map(|r| r.document)
}

/// Resolve a `did:webs` identifier from artifacts already fetched, with its DID
/// document metadata. See [`resolve_from_artifacts`].
///
/// # Errors
/// As [`resolve_from_artifacts`].
pub fn resolve_with_metadata(
    did: &DidWebs,
    keri_cesr: &[u8],
    did_json: Option<&[u8]>,
) -> Result<Resolution, DidWebsError> {
    let derived = derive(did, keri_cesr)?;
    let mut document = derived.document.clone();

    if let Some(published) = did_json {
        let published: Value = serde_json::from_slice(published)?;
        let published = from_did_web(&published, did, derived.twin_designated)?;
        check_published(&derived, &published)?;
        carry_delegator_service(&derived, &published, &mut document);
    }

    Ok(Resolution {
        document: into_document(&document, did)?,
        metadata: derived.metadata,
    })
}

/// Derive what `keri_cesr` implies for `did`.
pub(crate) fn derive(did: &DidWebs, keri_cesr: &[u8]) -> Result<Derived, DidWebsError> {
    let aid = did.aid();

    // The whole stream verifies, whatever version is asked for: a log that
    // fails verification after the requested version is still a bad log.
    let full = Kels::parse(keri_cesr)?;
    let current = full.key_state(aid)?;

    // The AID is the identifier the KEL establishes. If the stream verified
    // some *other* identifier's log, resolving would return keys that were
    // never bound to this DID.
    if current.prefix != aid {
        return Err(DidWebsError::Kel(format!(
            "verified key state is for {}, not the AID in the DID ({aid})",
            current.prefix,
        )));
    }

    let sequence_numbers = full.sequence_numbers(aid);
    let latest = sequence_numbers.iter().copied().max().unwrap_or(0);
    let version = did.version_id().unwrap_or(latest);
    let versioned = match did.version_id() {
        // `as_of` refuses a sequence number the log does not reach.
        Some(v) if v != latest => Some(Kels::parse(keri_cesr)?.as_of(aid, v)?),
        _ => None,
    };
    let kels = versioned.as_ref().unwrap_or(&full);
    let state = kels.key_state(aid)?;

    // § Read step 4. A stream that does not designate this DID has not
    // published it here, however well its KEL verifies.
    let designated = designated_aliases(kels, aid)?;
    if !designated.aliases.iter().any(|a| same_did(a, did.did())) {
        let reason = designated
            .rejected
            .map(|r| format!(" ({r})"))
            .unwrap_or_default();
        return Err(DidWebsError::NotDesignated(format!(
            "{}: no valid, unrevoked designated-aliases attestation names it{reason}",
            did.did()
        )));
    }

    let mut aliases: Vec<String> = Vec::new();
    for alias in designated.aliases {
        if !same_did(&alias, did.did()) && !aliases.iter().any(|a| same_did(a, &alias)) {
            aliases.push(alias);
        }
    }
    let twin_designated = aliases.iter().any(|a| same_did(a, &did.did_web_twin()));
    let equivalent_id = aliases
        .iter()
        .filter(|a| a.starts_with("did:webs:"))
        .cloned()
        .collect();

    // § Service Endpoint Event Details: the selected version supplies the
    // witnesses; discovery replies are the latest accepted at resolution time.
    let mut services: Vec<Value> = role_endpoints(&full, aid)?
        .iter()
        .chain(witness_endpoints(&full, &state.backers).iter())
        .map(|e| e.to_service())
        .collect();
    if let Some(delegator) = delegator_service(&full, aid)? {
        services.push(delegator);
    }

    let document = derive_document(did, &state.keys, &state.threshold, &aliases, &services)?;

    Ok(Derived {
        document,
        metadata: DocumentMetadata {
            version_id: version,
            next_version_id: sequence_numbers
                .iter()
                .copied()
                .filter(|sn| *sn > version)
                .min(),
            equivalent_id,
            deactivated: kels.is_deactivated(aid),
        },
        twin_designated,
        delegation_seal: state
            .delegator
            .as_ref()
            .and_then(|_| full.inception_said(aid)),
    })
}

/// Check a published document, in its `did:webs` form, against the derivation.
/// See the module documentation for what equality means here.
fn check_published(derived: &Derived, published: &Value) -> Result<(), DidWebsError> {
    let ours = &derived.document;
    let subject = ours["id"].as_str().unwrap_or_default();
    let mismatch = |what: String| Err(DidWebsError::DocumentMismatch(what));

    let Some(theirs) = published.as_object() else {
        return mismatch("did.json is not a JSON object".into());
    };

    for member in theirs.keys() {
        let known = matches!(
            member.as_str(),
            "@context" | "id" | "controller" | "verificationMethod" | "service" | "alsoKnownAs"
        ) || RELATIONSHIPS.contains(&member.as_str());
        if !known {
            return mismatch(format!(
                "did.json carries {member:?}, which nothing in the key event stream establishes"
            ));
        }
    }

    if let Some(controller) = theirs.get("controller")
        && controller.as_str().is_none_or(|c| !same_did(c, subject))
    {
        return mismatch(format!(
            "did.json names {controller} as controller, not {subject:?}"
        ));
    }

    // Verification methods: exactly the ones derived, field for field.
    let our_methods = keyed(&ours["verificationMethod"], subject);
    let their_methods = keyed(
        theirs.get("verificationMethod").unwrap_or(&Value::Null),
        subject,
    );
    for (id, method) in &their_methods {
        match our_methods.iter().find(|(our_id, _)| our_id == id) {
            None => {
                return mismatch(format!(
                    "did.json publishes {id:?}, which the verified key event log never authorised"
                ));
            }
            Some((_, ours)) if normalized(ours, subject) != normalized(method, subject) => {
                return mismatch(format!(
                    "did.json publishes {id:?} differently from the verified key state"
                ));
            }
            Some(_) => {}
        }
    }
    for (id, _) in &our_methods {
        if !their_methods.iter().any(|(their_id, _)| their_id == id) {
            return mismatch(format!(
                "did.json does not publish {id:?}, which the verified key state authorises"
            ));
        }
    }

    // Verification relationships: equal when published.
    for relationship in RELATIONSHIPS {
        let ours = refs(ours.get(relationship), subject);
        let Some(theirs) = theirs.get(relationship) else {
            if ours.is_empty() || matches!(relationship, "authentication" | "assertionMethod") {
                continue;
            }
            return mismatch(format!("did.json does not publish {relationship}"));
        };
        let theirs = refs(Some(theirs), subject);
        if !same_set(&ours, &theirs) {
            return mismatch(format!(
                "did.json's {relationship} is {theirs:?}, but the verified state implies {ours:?}"
            ));
        }
    }

    // Services: the same set. A `DelegatorOOBI` endpoint is a discovery hint
    // whose URL each implementation forms its own way, so it is matched by id
    // and type only — and its id must be this delegation's seal.
    let service_key = |s: &Value| -> Value {
        if s["type"] == "DelegatorOOBI" {
            json!({"id": s["id"], "type": s["type"]})
        } else {
            normalized(s, subject)
        }
    };
    let our_services: Vec<Value> = as_array(&ours["service"]).iter().map(service_key).collect();
    // When the stream says nowhere where the delegator is, none was derived;
    // a published one may still point at it, under this delegation's seal.
    let optional_delegator = derived
        .delegation_seal
        .as_ref()
        .filter(|_| our_services.iter().all(|s| s["type"] != "DelegatorOOBI"))
        .map(|seal| json!({"id": seal, "type": "DelegatorOOBI"}));
    let their_services: Vec<Value> = as_array(theirs.get("service").unwrap_or(&Value::Null))
        .iter()
        .map(service_key)
        .collect();
    let unexpected = their_services
        .iter()
        .any(|s| !our_services.contains(s) && optional_delegator.as_ref() != Some(s));
    let missing = our_services.iter().any(|s| !their_services.contains(s));
    if unexpected || missing {
        return mismatch("did.json's services differ from those the stream authorises".into());
    }

    // Aliases: the same set, ignoring the subject's alias of itself.
    let aliases = |v: Option<&Value>| -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for alias in as_array(v.unwrap_or(&Value::Null))
            .iter()
            .filter_map(Value::as_str)
        {
            let norm = crate::document::normalize_percent_encoding(alias);
            if !same_did(alias, subject) && !out.contains(&norm) {
                out.push(norm);
            }
        }
        out
    };
    let (our_aliases, their_aliases) = (
        aliases(ours.get("alsoKnownAs")),
        aliases(theirs.get("alsoKnownAs")),
    );
    if !same_set(&our_aliases, &their_aliases) {
        return mismatch(format!(
            "did.json's alsoKnownAs is {their_aliases:?}, but the AID designated {our_aliases:?}"
        ));
    }

    Ok(())
}

/// Use a published `DelegatorOOBI` service when the stream gave nothing to
/// derive one from. [`check_published`] has already required its id to be
/// this delegation's seal; the service is a pointer, never proof of the
/// delegation, which the key event log has already verified.
fn carry_delegator_service(derived: &Derived, published: &Value, document: &mut Value) {
    if derived.delegation_seal.is_none()
        || as_array(&document["service"])
            .iter()
            .any(|s| s["type"] == "DelegatorOOBI")
    {
        return;
    }
    if let Some(delegator) = as_array(published.get("service").unwrap_or(&Value::Null))
        .into_iter()
        .find(|s| s["type"] == "DelegatorOOBI")
        && let Some(Value::Array(services)) = document.get_mut("service")
    {
        services.push(delegator);
    }
}

fn as_array(value: &Value) -> Vec<Value> {
    value.as_array().cloned().unwrap_or_default()
}

/// A reference relative to the subject, whichever form it was written in.
fn relative(reference: &str, subject: &str) -> String {
    let norm = crate::document::normalize_percent_encoding(reference);
    let subject = crate::document::normalize_percent_encoding(subject);
    match norm.strip_prefix(&subject) {
        Some(rest) if rest.starts_with('#') => rest.to_string(),
        _ => norm,
    }
}

/// A document member with every reference made relative to the subject and
/// every subject DID normalised, so two spellings of one document compare
/// equal.
fn normalized(value: &Value, subject: &str) -> Value {
    match value {
        Value::String(s) if same_did(s, subject) => json!(subject),
        Value::String(s) if s.contains('#') => json!(relative(s, subject)),
        Value::Array(items) => Value::Array(items.iter().map(|v| normalized(v, subject)).collect()),
        Value::Object(obj) => Value::Object(
            obj.iter()
                .map(|(k, v)| (k.clone(), normalized(v, subject)))
                .collect(),
        ),
        other => other.clone(),
    }
}

/// Verification methods by relative id.
fn keyed(methods: &Value, subject: &str) -> Vec<(String, Value)> {
    as_array(methods)
        .into_iter()
        .filter_map(|m| {
            let id = relative(m.get("id")?.as_str()?, subject);
            Some((id, m))
        })
        .collect()
}

/// The references of a verification relationship, relative to the subject.
/// An embedded method counts by its id.
fn refs(value: Option<&Value>, subject: &str) -> Vec<String> {
    as_array(value.unwrap_or(&Value::Null))
        .iter()
        .filter_map(|r| r.as_str().or_else(|| r.get("id")?.as_str()))
        .map(|r| relative(r, subject))
        .collect()
}

fn same_set<T: PartialEq>(a: &[T], b: &[T]) -> bool {
    a.iter().all(|x| b.contains(x)) && b.iter().all(|x| a.contains(x))
}

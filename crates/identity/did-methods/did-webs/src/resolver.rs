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
//! * `controller`, each verification relationship and the `did:keri` alias
//!   must match **when published**; omitting `controller`, `authentication`,
//!   `assertionMethod` or `did:keri` is accepted, because those are derived
//!   from the key state regardless;
//! * any other member is a disagreement, except `@context`.
//!
//! A published document can therefore leave out what the derivation implies,
//! but never add to it or change it.

use affinidi_did_common::Document;
use serde_json::{Map, Value, json};

use crate::aliases::designated_aliases;
use crate::designated_services::designated_services;
use crate::document::{
    RELATIONSHIPS, derive_document, derive_key_role_document, from_did_web, into_document,
    same_did, with_key_agreement,
};
use crate::errors::DidWebsError;
use crate::identifier::DidWebs;
use crate::kel::Kels;
use crate::key_agreement::{KeyAgreementKey, converted_key_agreement, designated_key_agreement};
use crate::key_roles::designated_key_roles;
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

impl Resolution {
    /// The document, unless the identifier is deactivated.
    ///
    /// # Errors
    /// Returns [`DidWebsError::Deactivated`] if the metadata says the
    /// identifier is deactivated.
    pub fn into_document(self) -> Result<Document, DidWebsError> {
        if self.metadata.deactivated {
            return Err(DidWebsError::Deactivated(self.document.id.to_string()));
        }
        Ok(self.document)
    }
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
#[derive(Clone)]
pub(crate) struct Derived {
    pub document: Value,
    pub metadata: DocumentMetadata,
    pub twin_designated: bool,
    /// The SAID a `DelegatorOOBI` service of this DID must carry, when the
    /// identifier is delegated.
    pub delegation_seal: Option<String>,
    /// X25519 keys converted from the key state's Ed25519 keys, rendered into
    /// `keyAgreement` after the published document is checked. Empty unless
    /// the AID has never designated key agreement or key roles
    /// (`crate::key_agreement`, *Identifiers that designate none*).
    pub converted_key_agreement: Vec<String>,
    /// Whether the version resolved is itself deactivated: its last
    /// establishment event committed to no next keys. Its document is then
    /// published and returned without keys ([`deactivated_document`]), while
    /// `document` keeps the full derivation for the comparison with a
    /// `did.json` published before this rule.
    pub retired: bool,
}

/// Resolve a `did:webs` identifier from artifacts already fetched.
///
/// `keri_cesr` is the only thing that carries authority. `did_json` is
/// cross-checked against the derived document, and a mismatch fails the
/// resolution. A conforming resolution needs both (§ Read: a failed fetch of
/// either fails it); `None` is accepted here for verifying a stream offline,
/// and [`crate::WebsResolver`] never passes it.
///
/// A deactivated identifier does not resolve to a document here, with or
/// without a `versionId`: this returns the document alone, so its keys would
/// be indistinguishable from current ones. Deactivation is a property of the
/// DID, not of a version. [`resolve_with_metadata`] reports it.
///
/// # Errors
/// Returns [`DidWebsError`] if the stream cannot be read, the key event log
/// does not verify, the DID is not designated by its AID, or `did.json`
/// disagrees with the verified state; [`DidWebsError::Deactivated`] if the
/// whole stream shows the identifier deactivated, whatever version is asked
/// for.
pub fn resolve_from_artifacts(
    did: &DidWebs,
    keri_cesr: &[u8],
    did_json: Option<&[u8]>,
) -> Result<Document, DidWebsError> {
    resolve_with_metadata(did, keri_cesr, did_json)?.into_document()
}

/// Resolve a `did:webs` identifier from artifacts already fetched, with its DID
/// document metadata. See [`resolve_from_artifacts`].
///
/// For a deactivated identifier, `deactivated` is set in the metadata
/// whatever version is resolved: it is a property of the DID, read from the
/// whole stream. The document of the deactivating version (the latest)
/// carries no verification method, verification relationship, key role or
/// service; its last key state committed to no next keys, and its keys are
/// retired with it. A DID URL whose `versionId` names an event before the
/// deactivation resolves the document as it stood then, keys included, for a
/// caller checking a signature made while they were current; the metadata
/// still says `deactivated`.
///
/// For the deactivating version, a published `did.json` may be either the
/// document without keys (what [`crate::update()`] publishes) or the full
/// derivation (what it published before).
///
/// # Errors
/// As [`resolve_from_artifacts`], except that a deactivated identifier is not
/// an error.
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
        if derived.retired {
            let without_keys = Derived {
                document: deactivated_document(&derived.document),
                ..derived.clone()
            };
            check_published(&without_keys, &published)
                .or_else(|_| check_published(&derived, &published))?;
        } else if let Err(e) = check_published(&derived, &published) {
            // The converted keys are not part of the derivation the
            // specification defines, so a document published without them —
            // the reference implementation's — agrees. One published with
            // them agrees too.
            if derived.converted_key_agreement.is_empty() {
                return Err(e);
            }
            let with_converted = Derived {
                document: with_key_agreement(
                    derived.document.clone(),
                    did,
                    &derived.converted_key_agreement,
                )?,
                ..derived.clone()
            };
            check_published(&with_converted, &published).map_err(|_| e)?;
        }
        carry_delegator_service(&derived, &published, &mut document);
    }
    let document = with_key_agreement(document, did, &derived.converted_key_agreement)?;
    let document = if derived.retired {
        deactivated_document(&document)
    } else {
        document
    };

    Ok(Resolution {
        document: into_document(&document, did)?,
        metadata: derived.metadata,
    })
}

/// What a deactivated identifier's document keeps: its subject and aliases.
/// Every verification method, verification relationship, key role and
/// service goes with the keys.
pub(crate) fn deactivated_document(document: &Value) -> Value {
    let mut out = Map::new();
    if let Some(derived) = document.as_object() {
        for member in ["@context", "id", "alsoKnownAs"] {
            if let Some(value) = derived.get(member) {
                out.insert(member.to_string(), value.clone());
            }
        }
    }
    Value::Object(out)
}

/// Derive what `keri_cesr` implies for `did`.
/// Every designation schema this resolver reads, both versions of each.
const IMPLEMENTED: &[&str] = &[
    crate::aliases::DESIGNATED_ALIASES_SCHEMA,
    crate::aliases::DESIGNATED_ALIASES_SCHEMA_V2,
    crate::key_agreement::KEY_AGREEMENT_SCHEMA,
    crate::key_agreement::KEY_AGREEMENT_SCHEMA_V2,
    crate::designated_services::SERVICE_SCHEMA,
    crate::designated_services::SERVICE_SCHEMA_V2,
    crate::key_roles::KEY_ROLE_SCHEMA,
    crate::key_roles::KEY_ROLE_SCHEMA_V2,
];

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
        Some(v) if v != latest => Some(full.view().as_of(aid, v)?),
        _ => None,
    };
    let kels = versioned.as_ref().unwrap_or(&full);
    let state = kels.key_state(aid)?;

    // A critical designation restricts the document (P6). One this resolver
    // does not implement fails resolution: serving the unrestricted document
    // would be serving what the controller withdrew.
    if let Some(schema) = crate::designation::unsupported_critical(kels, aid, IMPLEMENTED)? {
        return Err(DidWebsError::UnsupportedDesignation(schema));
    }

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
    // § Also Known As: "`did:webs` DIDs MUST provide the corresponding
    // `did:keri`", and the specification's example lists it although its
    // attestation does not designate it. It names the same AID by
    // construction, so nothing beyond the verified KEL is needed to assert it.
    if !aliases.iter().any(|a| a == &did.did_keri()) {
        aliases.push(did.did_keri());
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

    // Services of any type, designated by the AID. Anchored in the KEL like
    // its aliases, they follow `versionId`. One whose id KERI's own endpoint
    // data already uses is dropped: an id names one service.
    for service in designated_services(kels, aid)?.services {
        if services.iter().all(|s| s["id"] != service["id"]) {
            services.push(service);
        }
    }

    // Key roles, designated by the AID (a proposed extension; see
    // `crate::key_roles`). Once the AID has designated any, the document is
    // built from role keys alone and the key state's keys are rendered
    // nowhere; the `messaging` role takes the place of key agreement
    // designations.
    let key_roles = designated_key_roles(kels, aid)?;
    if key_roles.issued {
        if let Some(reason) = &key_roles.rejected {
            tracing::warn!(did = did.did(), %reason, "a key role designation binds nothing");
        }
        let document = derive_key_role_document(
            did,
            &key_roles.roles,
            &key_roles.revoked,
            &aliases,
            &services,
        )?;
        return Ok(Derived {
            document,
            metadata: DocumentMetadata {
                version_id: version,
                next_version_id: sequence_numbers
                    .iter()
                    .copied()
                    .filter(|sn| *sn > version)
                    .min(),
                equivalent_id,
                deactivated: full.is_deactivated(aid),
            },
            twin_designated,
            delegation_seal: state
                .delegator
                .as_ref()
                .and_then(|_| full.inception_said(aid)),
            converted_key_agreement: Vec::new(),
            retired: kels.is_deactivated(aid),
        });
    }

    // Key agreement keys, designated by the AID. A key of the current key
    // state is never one: the change authority does not double as an
    // encryption key.
    let designated_ka = designated_key_agreement(kels, aid)?;
    // An AID that designates nothing gets the keys KERI practice converts
    // from its key state. One that ever designated keys chose separate ones,
    // and a deactivated one is addressed by no one.
    let retired = kels.is_deactivated(aid);
    let converted_key_agreement =
        if designated_ka.issued || designated_ka.rejected.is_some() || retired {
            Vec::new()
        } else {
            converted_key_agreement(&state.keys)
        };
    let key_agreement: Vec<String> = designated_ka
        .keys
        .into_iter()
        .filter(|key| {
            let Ok(designated) = KeyAgreementKey::from_cesr(key) else {
                return false;
            };
            !state.keys.iter().any(|k| {
                affinidi_cesr::Matter::from_qb64(k).is_ok_and(|m| m.raw() == designated.raw())
            })
        })
        .collect();

    let document = derive_document(did, &state.keys, &state.threshold, &aliases, &services)?;
    let document = with_key_agreement(document, did, &key_agreement)?;

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
            deactivated: full.is_deactivated(aid),
        },
        twin_designated,
        delegation_seal: state
            .delegator
            .as_ref()
            .and_then(|_| full.inception_said(aid)),
        converted_key_agreement,
        retired,
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
        ) || RELATIONSHIPS.contains(&member.as_str())
            || (member == "keyRoles" && ours.get("keyRoles").is_some());
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

    // Key roles: the same binding, role by role, whenever the AID designates
    // roles. Unlike a relationship it may not be left out: a verifier selects
    // keys by it (VTI-KEY-094).
    if let Some(our_roles) = ours.get("keyRoles").and_then(Value::as_object) {
        let their_roles = theirs.get("keyRoles").and_then(Value::as_object);
        let Some(their_roles) = their_roles else {
            return mismatch("did.json does not publish keyRoles".into());
        };
        let same = our_roles.len() == their_roles.len()
            && our_roles.iter().all(|(role, refs_ours)| {
                their_roles.get(role).is_some_and(|refs_theirs| {
                    same_set(
                        &refs(Some(refs_ours), subject),
                        &refs(Some(refs_theirs), subject),
                    )
                })
            });
        if !same {
            return mismatch("did.json's keyRoles differ from those the AID designated".into());
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
    let (mut our_aliases, their_aliases) = (
        aliases(ours.get("alsoKnownAs")),
        aliases(theirs.get("alsoKnownAs")),
    );
    // The `did:keri` form is implied by the AID; the reference implementation
    // does not publish it, and leaving it out adds nothing.
    let did_keri = format!(
        "did:keri:{}",
        subject.rsplit(':').next().unwrap_or_default()
    );
    if !their_aliases.contains(&did_keri) {
        our_aliases.retain(|a| a != &did_keri);
    }
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

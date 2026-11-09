//! Issuing a designated-aliases attestation.
//!
//! `alsoKnownAs` is not something a `did:webs` document may assert about
//! itself. A resolver takes it only from a credential the identifier **issued**,
//! anchored in its own key event log — see [`crate::aliases`]. Publishing an
//! alias therefore means producing that whole chain:
//!
//! ```text
//! vcp   a credential registry, incepted by this AID
//!  └─ anchored by an interaction event in the key event log
//! iss   an issuance in that registry
//!  └─ anchored by a second interaction event
//! ACDC  the attestation itself, signed by the AID, listing the aliases
//! ```
//!
//! Every link is checked on resolution, so every link has to be built. That is
//! the price of an alias meaning anything: a document that merely claims one is
//! claiming it about itself.

use affinidi_keri::hab::Hab;
use affinidi_keri_core::sad;
use affinidi_keri_core::sad::{SadMap, SadValue};
use affinidi_keri_core::said;
use affinidi_keri_core::serder::Serder;
use affinidi_keri_core::version::SerializationKind;

use crate::aliases::DESIGNATED_ALIASES_SCHEMA;
use crate::designation::Designation;
use crate::endpoints::{fix_version, sign_with_group, timestamp};
use crate::errors::DidWebsError;
use crate::identifier::DidWebs;

/// The identifiers every designated-aliases attestation for `did` carries,
/// followed by `extra`, without repeats.
///
/// * the `did:webs` DID itself — § Read refuses a DID its AID has not
///   designated;
/// * its `did:web` twin — `did.json` is the `did:web` form of the document, and
///   that transformation is only valid when the twin is designated;
/// * `did:keri:<AID>` — § Also Known As: "`did:webs` DIDs MUST provide the
///   corresponding `did:keri`", and an alias appears only if designated.
pub(crate) fn designation(did: &DidWebs, extra: &[String]) -> Vec<String> {
    let mut ids = vec![did.did().to_string(), did.did_web_twin(), did.did_keri()];
    for id in extra {
        if !ids.contains(id) {
            ids.push(id.clone());
        }
    }
    ids
}

/// Revoke a designated-aliases attestation: a `rev` event in its registry,
/// anchored by an interaction event in the key event log.
///
/// An attestation names *the* designated aliases, and a resolver reads every
/// unrevoked one, so replacing a designation means withdrawing the old one —
/// otherwise an alias the controller has since dropped would still be listed.
///
/// # Errors
/// Returns [`DidWebsError::Create`] if the event cannot be built or anchored.
pub(crate) fn revoke(hab: &mut Hab, attestation: &Designation) -> Result<Vec<u8>, DidWebsError> {
    let mut rev = sad!({
        "v": "KERI10JSON000000_",
        "t": "rev",
        "d": "",
        "i": attestation.said,
        "s": "1",
        "ri": attestation.registry,
        "p": attestation.issuance,
        "dt": timestamp(),
    });
    fix_version(&mut rev)?;
    let rev_said = said::compute_said(&mut rev, "d", "E", SerializationKind::Json)
        .map_err(|e| DidWebsError::Create(format!("revocation SAID: {e}")))?;
    let rev = Serder::new(SerializationKind::Json, rev)
        .map_err(|e| DidWebsError::Create(format!("revocation: {e}")))?;

    let anchor = hab
        .interact_event(&[sad!({ "i": attestation.said, "s": "1", "d": rev_said })])
        .map_err(|e| DidWebsError::Create(format!("anchoring the revocation: {e}")))?;

    let mut out = anchor.composed;
    out.extend_from_slice(rev.raw());
    Ok(out)
}

/// The rules block of the designated-aliases attestation.
///
/// Fixed by the credential's schema, and reproduced verbatim so the attestation
/// this crate issues is the same credential the rest of the ecosystem reads.
fn rules() -> SadValue {
    sad!({
        "d": "",
        "aliasDesignation": {
            "l": "The issuer of this ACDC designates the identifiers in the ids field as the only allowed namespaced aliases of the issuer's AID."
        },
        "usageDisclaimer": {
            "l": "This attestation only asserts designated aliases of the controller of the AID, that the AID controlled namespaced alias has been designated by the controller. It does not assert that the controller of this AID has control over the infrastructure or anything else related to the namespace other than the included AID."
        },
        "issuanceDisclaimer": {
            "l": "All information in a valid and non-revoked alias designation assertion is accurate as of the date specified."
        },
        "termsOfUse": {
            "l": "Designated aliases of the AID must only be used in a manner consistent with the expressed intent of the AID controller."
        }
    })
}

/// Issue a designated-aliases attestation for `aliases`.
///
/// Appends two interaction events to the identifier's key event log — the
/// anchors — and returns the CESR bytes for those plus the registry, the
/// issuance and the signed credential.
///
/// # Errors
/// Returns [`DidWebsError::Create`] if any part of the chain cannot be built,
/// signed, or anchored.
pub(crate) fn issue_designated_aliases(
    hab: &mut Hab,
    aid: &str,
    establishment_said: &str,
    aliases: &[String],
) -> Result<Vec<u8>, DidWebsError> {
    if aliases.is_empty() {
        return Err(DidWebsError::Create(
            "a designated-aliases attestation with no aliases designates nothing".into(),
        ));
    }
    issue(
        hab,
        aid,
        establishment_said,
        DESIGNATED_ALIASES_SCHEMA,
        sad!({ "ids": aliases }),
        rules(),
    )
}

/// Issue a key agreement designation for `keys`.
///
/// # Errors
/// Returns [`DidWebsError::Create`] if `keys` is empty or repeats a key, and
/// [`DidWebsError::InvalidKey`] if a key is not publishable or is a key of the
/// current key state — the change authority must not double as an encryption
/// key, and a resolver drops one that does.
pub(crate) fn issue_key_agreement(
    hab: &mut Hab,
    aid: &str,
    establishment_said: &str,
    keys: &[crate::key_agreement::KeyAgreementKey],
) -> Result<Vec<u8>, DidWebsError> {
    if keys.is_empty() {
        return Err(DidWebsError::Create(
            "a key agreement designation with no keys designates nothing".into(),
        ));
    }
    let signing: Vec<Vec<u8>> = hab
        .signers()
        .iter()
        .filter_map(|s| s.verfer().qb64().ok())
        .filter_map(|k| affinidi_cesr::Matter::from_qb64(&k).ok())
        .map(|m| m.raw().to_vec())
        .collect();
    let mut encoded = Vec::with_capacity(keys.len());
    for key in keys {
        key.public_jwk()?;
        if signing.iter().any(|raw| raw.as_slice() == key.raw()) {
            return Err(DidWebsError::InvalidKey(
                "a key of the identifier's key state cannot be designated for key agreement".into(),
            ));
        }
        let qb64 = key.to_cesr()?;
        if encoded.contains(&qb64) {
            return Err(DidWebsError::Create(format!("{qb64} is designated twice")));
        }
        encoded.push(qb64);
    }
    issue(
        hab,
        aid,
        establishment_said,
        crate::key_agreement::KEY_AGREEMENT_SCHEMA,
        sad!({ "keys": encoded }),
        rules_from_schema(crate::key_agreement::KEY_AGREEMENT_SCHEMA_JSON)?,
    )
}

/// Issue a key role designation (see [`crate::key_roles`]).
///
/// `state` is the key state the designation is issued under, and
/// `prior_revoked` every key an earlier key role designation revoked: each is
/// carried forward, so a revocation for compromise is never dropped
/// (VTI-KEY-127).
///
/// # Errors
/// Returns [`DidWebsError::Create`] if no key is bound, a key is bound twice
/// or both bound and revoked, or a compromise time is not RFC 3339, and
/// [`DidWebsError::InvalidKey`] if a key is not one its role binds or is a key
/// of the key state or of its next-key commitment.
pub(crate) fn issue_key_roles(
    hab: &mut Hab,
    aid: &str,
    establishment_said: &str,
    state: &affinidi_keri_core::key_state::KeyState,
    roles: &crate::key_roles::KeyRoles,
    prior_revoked: &[crate::key_roles::RevokedKey],
) -> Result<Vec<u8>, DidWebsError> {
    use crate::key_roles::{RevokedKey, check_role_key, raw_of, revoked_key_jwk, role_key_jwk};

    // Every earlier revocation, then the new ones; the earlier time stands.
    let mut revoked: Vec<RevokedKey> = prior_revoked.to_vec();
    for entry in &roles.revoked {
        chrono::DateTime::parse_from_rfc3339(&entry.compromised_at).map_err(|e| {
            DidWebsError::Create(format!(
                "compromise time {:?} of {} is not RFC 3339: {e}",
                entry.compromised_at, entry.key
            ))
        })?;
        revoked_key_jwk(&entry.key).map_err(DidWebsError::InvalidKey)?;
        if !revoked.iter().any(|r| r.key == entry.key) {
            revoked.push(entry.clone());
        }
    }

    // A designation binding no key is still a statement when it revokes one:
    // the last key of an identifier can be compromised too.
    let encoded = roles.encoded()?;
    if encoded.iter().all(|(_, keys)| keys.is_empty()) && revoked.is_empty() {
        return Err(DidWebsError::Create(
            "a key role designation that binds and revokes no key designates nothing".into(),
        ));
    }
    let mut seen: Vec<Vec<u8>> = Vec::new();
    let mut role_map = SadMap::new();
    for (role, keys) in &encoded {
        if keys.is_empty() {
            continue;
        }
        for key in keys {
            role_key_jwk(*role, key).map_err(DidWebsError::InvalidKey)?;
            check_role_key(key, &state.keys, &state.next_keys, &revoked)
                .map_err(DidWebsError::InvalidKey)?;
            let raw = raw_of(key).ok_or_else(|| DidWebsError::InvalidKey(key.clone()))?;
            if seen.contains(&raw) {
                return Err(DidWebsError::Create(format!(
                    "{key} is bound to more than one role"
                )));
            }
            seen.push(raw);
        }
        role_map.insert(role.name().into(), sad!(keys));
    }

    let mut attributes = SadMap::new();
    attributes.insert("roles".into(), SadValue::Object(role_map));
    if !revoked.is_empty() {
        let entries: Vec<SadValue> = revoked
            .iter()
            .map(|r| sad!({ "key": r.key, "compromisedAt": r.compromised_at }))
            .collect();
        attributes.insert("revoked".into(), SadValue::Array(entries));
    }
    issue(
        hab,
        aid,
        establishment_said,
        crate::key_roles::KEY_ROLE_SCHEMA,
        SadValue::Object(attributes),
        rules_from_schema(crate::key_roles::KEY_ROLE_SCHEMA_JSON)?,
    )
}

/// Issue a service designation for `services`.
///
/// # Errors
/// Returns [`DidWebsError::Create`] if `services` is empty, an entry is not a
/// service a DID document can carry, or two share an `id`.
pub(crate) fn issue_services(
    hab: &mut Hab,
    aid: &str,
    establishment_said: &str,
    services: &[crate::designated_services::DesignatedService],
) -> Result<Vec<u8>, DidWebsError> {
    if services.is_empty() {
        return Err(DidWebsError::Create(
            "a service designation with no services designates nothing".into(),
        ));
    }
    let mut entries: Vec<SadValue> = Vec::with_capacity(services.len());
    for service in services {
        let entry = service.to_sad().map_err(DidWebsError::Create)?;
        if entries.iter().any(|e| e["id"] == entry["id"]) {
            return Err(DidWebsError::Create(format!(
                "service id {} is designated twice",
                service.id
            )));
        }
        entries.push(entry);
    }
    issue(
        hab,
        aid,
        establishment_said,
        crate::designated_services::SERVICE_SCHEMA,
        sad!({ "services": entries }),
        rules_from_schema(crate::designated_services::SERVICE_SCHEMA_JSON)?,
    )
}

/// The rules block a designation of `schema_json` carries: each rule's fixed
/// text, read from the schema itself so the credential and its schema cannot
/// disagree.
///
/// # Errors
/// Returns [`DidWebsError::Create`] if the schema has no rules block.
pub(crate) fn rules_from_schema(schema_json: &str) -> Result<SadValue, DidWebsError> {
    let schema: SadValue = serde_json::from_str(schema_json)?;
    let properties = schema["properties"]["r"]["oneOf"]
        .as_array()
        .and_then(|alternatives| alternatives.iter().find(|a| a["type"] == "object"))
        .and_then(|block| block["properties"].as_object())
        .ok_or_else(|| DidWebsError::Create("schema has no rules block".into()))?;
    let mut rules = SadMap::new();
    rules.insert("d".into(), sad!(""));
    for (name, rule) in properties {
        if let Some(text) = rule["properties"]["l"]["const"].as_str() {
            rules.insert(name.clone(), sad!({ "l": text }));
        }
    }
    Ok(SadValue::Object(rules))
}

/// Issue a designation: a credential of `schema` whose attribute block is
/// `attributes` (to which `d` and `dt` are added), with `rules` as its rules
/// block.
///
/// Appends two interaction events to the identifier's key event log — the
/// anchors — and returns the CESR bytes for those plus the registry, the
/// issuance and the signed credential.
///
/// # Errors
/// Returns [`DidWebsError::Create`] if any part of the chain cannot be built,
/// signed, or anchored.
pub(crate) fn issue(
    hab: &mut Hab,
    aid: &str,
    establishment_said: &str,
    schema: &str,
    attributes: SadValue,
    rules: SadValue,
) -> Result<Vec<u8>, DidWebsError> {
    // 1. The registry. Its identifier is its own SAID, so it is self-addressing
    //    and both `d` and `i` are dummied while it is computed.
    let mut vcp = sad!({
        "v": "KERI10JSON000000_",
        "t": "vcp",
        "d": "",
        "i": "",
        "ii": aid,
        "s": "0",
        "c": ["NB"],
        "bt": "0",
        "b": [],
        "n": nonce(hab)?,
    });
    fix_version(&mut vcp)?;
    let registry = said::compute_said(&mut vcp, "d", "E", SerializationKind::Json)
        .map_err(|e| DidWebsError::Create(format!("registry SAID: {e}")))?;
    let vcp = Serder::new(SerializationKind::Json, vcp)
        .map_err(|e| DidWebsError::Create(format!("registry: {e}")))?;

    // 2. Anchor it. Without this the registry is just a document somebody wrote.
    let anchor_registry = hab
        .interact_event(&[sad!({ "i": registry, "s": "0", "d": registry })])
        .map_err(|e| DidWebsError::Create(format!("anchoring the registry: {e}")))?;

    // 3. The credential.
    let acdc_sad = build_attestation(aid, &registry, schema, attributes, rules)?;
    let acdc_said = acdc_sad["d"]
        .as_str()
        .ok_or_else(|| DidWebsError::Create("attestation has no SAID".into()))?
        .to_string();
    let acdc = Serder::new(SerializationKind::Json, acdc_sad)
        .map_err(|e| DidWebsError::Create(format!("attestation: {e}")))?;

    // 4. The issuance.
    let mut iss = sad!({
        "v": "KERI10JSON000000_",
        "t": "iss",
        "d": "",
        "i": acdc_said,
        "s": "0",
        "ri": registry,
        "dt": timestamp(),
    });
    fix_version(&mut iss)?;
    let iss_said = said::compute_said(&mut iss, "d", "E", SerializationKind::Json)
        .map_err(|e| DidWebsError::Create(format!("issuance SAID: {e}")))?;
    let iss = Serder::new(SerializationKind::Json, iss)
        .map_err(|e| DidWebsError::Create(format!("issuance: {e}")))?;

    // 5. Anchor the issuance too — the registry existing does not say anything
    //    was issued in it.
    let anchor_issuance = hab
        .interact_event(&[sad!({ "i": acdc_said, "s": "0", "d": iss_said })])
        .map_err(|e| DidWebsError::Create(format!("anchoring the issuance: {e}")))?;

    // Key events first, in order, then the transaction events and the
    // credential — the shape a published `keri.cesr` takes.
    let mut out = Vec::new();
    out.extend_from_slice(&anchor_registry.composed);
    out.extend_from_slice(&anchor_issuance.composed);
    out.extend_from_slice(vcp.raw());
    out.extend_from_slice(iss.raw());
    out.extend_from_slice(&sign_with_group(hab, establishment_said, &acdc)?);

    Ok(out)
}

/// Build the attestation, SAIDifying the nested blocks before the whole.
///
/// The attribute and rules blocks carry their own SAIDs, and those are part of
/// the bytes the outer SAID covers — so they have to be computed first, or the
/// credential's identifier would not match its contents.
fn build_attestation(
    aid: &str,
    registry: &str,
    schema: &str,
    content: SadValue,
    mut rules: SadValue,
) -> Result<SadValue, DidWebsError> {
    let mut attributes = SadMap::new();
    attributes.insert("d".into(), sad!(""));
    attributes.insert("dt".into(), sad!(timestamp()));
    if let SadValue::Object(content) = content {
        attributes.extend(content);
    }
    let mut attributes = SadValue::Object(attributes);
    said::compute_said(&mut attributes, "d", "E", SerializationKind::Json)
        .map_err(|e| DidWebsError::Create(format!("attribute SAID: {e}")))?;

    said::compute_said(&mut rules, "d", "E", SerializationKind::Json)
        .map_err(|e| DidWebsError::Create(format!("rules SAID: {e}")))?;

    let mut acdc = sad!({
        "v": "ACDC10JSON000000_",
        "d": "",
        "i": aid,
        "ri": registry,
        "s": schema,
        "a": attributes,
        "r": rules,
    });
    fix_acdc_version(&mut acdc)?;
    said::compute_said(&mut acdc, "d", "E", SerializationKind::Json)
        .map_err(|e| DidWebsError::Create(format!("attestation SAID: {e}")))?;

    Ok(acdc)
}

/// An ACDC declares its length the same way a KERI event does, but under its
/// own protocol tag.
fn fix_acdc_version(sad: &mut SadValue) -> Result<(), DidWebsError> {
    let placeholder = "#".repeat(44);
    let original = sad["d"].clone();
    sad["d"] = sad!(placeholder);
    let len = serde_json::to_vec(sad)?.len();
    sad["v"] = sad!(format!("ACDC10JSON{len:06x}_"));
    sad["d"] = original;
    Ok(())
}

/// A registry nonce, derived from the identifier's own key material and the
/// point its log has reached, so that creating the same identifier twice yields
/// the same registry while each later designation gets a registry of its own.
fn nonce(hab: &Hab) -> Result<String, DidWebsError> {
    let signer = hab
        .signers()
        .first()
        .ok_or_else(|| DidWebsError::Create("identifier has no signing key".into()))?;
    let key = signer
        .verfer()
        .qb64()
        .map_err(|e| DidWebsError::Create(format!("key: {e}")))?;

    let seed = format!("{key}:{}", hab.sn());
    let digest = affinidi_keri_crypto::Diger::from_data("E", seed.as_bytes())
        .and_then(|d| d.qb64())
        .map_err(|e| DidWebsError::Create(format!("nonce: {e}")))?;
    // A salt-coded primitive, as keripy uses for the registry nonce.
    Ok(format!("A{}", &digest[1..]))
}

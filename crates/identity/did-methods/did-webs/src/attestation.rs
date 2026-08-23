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
use affinidi_keri_core::said;
use affinidi_keri_core::serder::Serder;
use affinidi_keri_core::version::SerializationKind;
use serde_json::{Value, json};

use crate::aliases::DESIGNATED_ALIASES_SCHEMA;
use crate::endpoints::{fix_version, sign_with_group, timestamp};
use crate::errors::DidWebsError;

/// The rules block of the designated-aliases attestation.
///
/// Fixed by the credential's schema, and reproduced verbatim so the attestation
/// this crate issues is the same credential the rest of the ecosystem reads.
fn rules() -> Value {
    json!({
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

    // 1. The registry. Its identifier is its own SAID, so it is self-addressing
    //    and both `d` and `i` are dummied while it is computed.
    let mut vcp = json!({
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
        .interact_event(&[json!({ "i": registry, "s": "0", "d": registry })])
        .map_err(|e| DidWebsError::Create(format!("anchoring the registry: {e}")))?;

    // 3. The credential.
    let acdc_sad = build_attestation(aid, &registry, aliases)?;
    let acdc_said = acdc_sad["d"]
        .as_str()
        .ok_or_else(|| DidWebsError::Create("attestation has no SAID".into()))?
        .to_string();
    let acdc = Serder::new(SerializationKind::Json, acdc_sad)
        .map_err(|e| DidWebsError::Create(format!("attestation: {e}")))?;

    // 4. The issuance.
    let mut iss = json!({
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
        .interact_event(&[json!({ "i": acdc_said, "s": "0", "d": iss_said })])
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
fn build_attestation(aid: &str, registry: &str, aliases: &[String]) -> Result<Value, DidWebsError> {
    let mut attributes = json!({
        "d": "",
        "dt": timestamp(),
        "ids": aliases,
    });
    said::compute_said(&mut attributes, "d", "E", SerializationKind::Json)
        .map_err(|e| DidWebsError::Create(format!("attribute SAID: {e}")))?;

    let mut rules = rules();
    said::compute_said(&mut rules, "d", "E", SerializationKind::Json)
        .map_err(|e| DidWebsError::Create(format!("rules SAID: {e}")))?;

    let mut acdc = json!({
        "v": "ACDC10JSON000000_",
        "d": "",
        "i": aid,
        "ri": registry,
        "s": DESIGNATED_ALIASES_SCHEMA,
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
fn fix_acdc_version(sad: &mut Value) -> Result<(), DidWebsError> {
    let placeholder = "#".repeat(44);
    let original = sad["d"].clone();
    sad["d"] = json!(placeholder);
    let len = serde_json::to_vec(sad)?.len();
    sad["v"] = json!(format!("ACDC10JSON{len:06x}_"));
    sad["d"] = original;
    Ok(())
}

/// A registry nonce, derived from the identifier's own key material so that
/// creating the same identifier twice yields the same registry.
fn nonce(hab: &Hab) -> Result<String, DidWebsError> {
    let signer = hab
        .signers()
        .first()
        .ok_or_else(|| DidWebsError::Create("identifier has no signing key".into()))?;
    let key = signer
        .verfer()
        .qb64()
        .map_err(|e| DidWebsError::Create(format!("key: {e}")))?;

    let digest = affinidi_keri_crypto::Diger::from_data("E", key.as_bytes())
        .and_then(|d| d.qb64())
        .map_err(|e| DidWebsError::Create(format!("nonce: {e}")))?;
    // A salt-coded primitive, as keripy uses for the registry nonce.
    Ok(format!("A{}", &digest[1..]))
}

//! Designated aliases: the verified source of `alsoKnownAs`.
//!
//! `did:webs` does not let a DID document simply assert its own aliases. An
//! alias is only real if the AID **issued a credential saying so**, and that
//! credential is anchored in the AID's own key event log. The chain is:
//!
//! ```text
//! KEL ixn ──anchors──▶ vcp   the credential registry, incepted by this AID
//! KEL ixn ──anchors──▶ iss   an issuance in that registry
//!                       │
//!                       └──▶ ACDC   whose `a.ids` are the designated aliases,
//!                                   signed by the AID's key state
//! ```
//!
//! Every link is checked. A break anywhere yields no aliases from that
//! attestation rather than a partially-trusted list: an alias nobody authorised
//! is exactly the claim an attacker wants a resolver to repeat.
//!
//! An identifier may hold several attestations; the designated aliases are
//! every identifier in every one that verifies and has not been revoked, as
//! the reference implementation reads them. A revocation counts once the
//! revocation event is anchored in the key event log — so a document resolved
//! as of an earlier version still carries the aliases designated then.
//!
//! *Placement note:* transaction event logs are a KERI concept, not a
//! `did:webs` one, so the `vcp`/`iss`/`rev` handling here belongs in
//! `affinidi-keri-core` once something other than designated aliases needs it.
//! It lives here while `did:webs` is the only consumer.

use crate::errors::DidWebsError;
use crate::kel::Kels;

/// The aliases an AID has designated, and how far verification got.
#[derive(Debug, Clone, Default)]
pub struct DesignatedAliases {
    /// Aliases whose full chain verified.
    pub aliases: Vec<String>,
    /// Why no aliases were produced, when a stream carried an attestation that
    /// did not verify.
    ///
    /// A stream with no attestation at all is not a failure — most `did:webs`
    /// identifiers designate nothing — so this stays `None` in that case.
    pub rejected: Option<String>,
}

/// The ACDC schema SAID for the designated-aliases attestation.
///
/// Fixed by the `did:webs` specification. Checking it is what stops an
/// unrelated credential the AID happens to have issued from being read as an
/// alias designation.
pub const DESIGNATED_ALIASES_SCHEMA: &str = "EN6Oh5XSD5_q2Hgu-aqpdfbVepdpYpFlgz6zvJL5b_r5";

/// Collect the aliases `aid` has designated, verifying the whole chain.
///
/// Returns an empty list when the stream carries no designated-aliases
/// attestation, which is the common case.
///
/// # Errors
/// Returns [`DidWebsError::Kel`] only if `aid`'s own key event log does not
/// verify. An attestation that fails to verify is reported through
/// [`DesignatedAliases::rejected`], not as an error, so a broken attestation
/// does not make an otherwise valid DID unresolvable.
pub fn designated_aliases(kels: &Kels, aid: &str) -> Result<DesignatedAliases, DidWebsError> {
    let mut designated = DesignatedAliases::default();
    for attestation in attestations(kels, aid, &mut designated.rejected)? {
        for alias in attestation.aliases {
            if !designated.aliases.contains(&alias) {
                designated.aliases.push(alias);
            }
        }
    }
    Ok(designated)
}

/// A designated-aliases attestation that verified and stands unrevoked.
#[derive(Debug, Clone)]
// Everything but `aliases` is what `update` needs to revoke one.
#[cfg_attr(not(feature = "create"), allow(dead_code))]
pub(crate) struct Attestation {
    /// The attestation's SAID.
    pub said: String,
    /// The registry it was issued in.
    pub registry: String,
    /// The SAID of its issuance event, which a revocation names as prior.
    pub issuance: String,
    /// The identifiers it designates.
    pub aliases: Vec<String>,
}

/// Every designated-aliases attestation `aid` issued that verifies and has not
/// been revoked. The first reason one did not verify is kept in `rejected`.
///
/// # Errors
/// Returns [`DidWebsError::Kel`] only if `aid`'s own key event log does not
/// verify.
pub(crate) fn attestations(
    kels: &Kels,
    aid: &str,
    rejected: &mut Option<String>,
) -> Result<Vec<Attestation>, DidWebsError> {
    // Fails loudly: everything below is meaningless without a verified KEL.
    kels.key_state(aid)?;

    let mut out = Vec::new();
    for acdc in kels.messages_with_ilk_none() {
        let sad = acdc.serder.sad();
        if sad.get("s").and_then(|v| v.as_str()) != Some(DESIGNATED_ALIASES_SCHEMA) {
            continue;
        }
        if sad.get("i").and_then(|v| v.as_str()) != Some(aid) {
            continue;
        }
        match verify_attestation(kels, aid, acdc) {
            Ok(Some(attestation)) => out.push(attestation),
            // Revoked: verified, and withdrawn by its issuer.
            Ok(None) => {}
            Err(e) => {
                rejected.get_or_insert(e);
            }
        }
    }
    Ok(out)
}

/// Verify one designated-aliases attestation end to end.
///
/// `Ok(None)` for an attestation that verifies but has been revoked.
fn verify_attestation(
    kels: &Kels,
    aid: &str,
    acdc: &affinidi_keri_core::parser::ParsedMessage,
) -> Result<Option<Attestation>, String> {
    let sad = acdc.serder.sad();
    let acdc_said = acdc
        .serder
        .said()
        .map_err(|e| format!("attestation has no SAID: {e}"))?;

    // 1. The attestation is signed by the AID, under a key state from its KEL.
    verify_signed_by(kels, aid, acdc)?;

    // 2. It names a registry.
    let registry = sad
        .get("ri")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "attestation names no registry (`ri`)".to_string())?;

    // 3. That registry was incepted by this AID, and the inception is anchored
    //    in the AID's key event log.
    verify_registry(kels, aid, registry)?;

    // 4. The attestation was issued in that registry, and the issuance is
    //    anchored in the key event log.
    let issuance = verify_issued(kels, aid, registry, &acdc_said)?;

    // 5. It has not been revoked.
    if is_revoked(kels, aid, &acdc_said)? {
        return Ok(None);
    }

    // 6. Only then are its aliases worth reading.
    let ids = sad
        .get("a")
        .and_then(|a| a.get("ids"))
        .and_then(|ids| ids.as_array())
        .ok_or_else(|| "attestation carries no `a.ids` list".to_string())?;

    Ok(Some(Attestation {
        said: acdc_said,
        registry: registry.to_string(),
        issuance,
        aliases: ids
            .iter()
            .filter_map(|v| v.as_str())
            .map(str::to_string)
            .collect(),
    }))
}

/// The attestation must carry a transferable indexed signature group from the
/// AID, and those signatures must verify against the AID's key state.
fn verify_signed_by(
    kels: &Kels,
    aid: &str,
    acdc: &affinidi_keri_core::parser::ParsedMessage,
) -> Result<(), String> {
    let group = acdc
        .trans_idx_sig_groups()
        .iter()
        .find(|g| g.prefix == aid)
        .ok_or_else(|| format!("attestation carries no signature group from {aid}"))?;

    // Verified against the key state at the establishment event the signature
    // group names, not the current one — otherwise a rotation would silently
    // withdraw an attestation the identifier never revoked — and against that
    // key state's signing threshold, so one key of a multi-key identifier
    // cannot designate aliases on its own.
    kels.verify_signature_group(aid, acdc.serder.raw(), group)
        .map_err(|e| format!("the attestation signature does not verify: {e}"))?;

    Ok(())
}

/// The registry inception must exist, name this AID as issuer, and be anchored
/// in the AID's key event log.
fn verify_registry(kels: &Kels, aid: &str, registry: &str) -> Result<(), String> {
    let vcp = kels
        .message_by_said(registry)
        .ok_or_else(|| format!("registry {registry} has no inception event in the stream"))?;

    if vcp.serder.ilk().ok().as_deref() != Some("vcp") {
        return Err(format!("{registry} is not a registry inception event"));
    }

    // `ii` is the registry's issuer. Without this check, an AID could point at
    // somebody else's registry and inherit its credentials.
    if vcp.serder.sad().get("ii").and_then(|v| v.as_str()) != Some(aid) {
        return Err(format!("registry {registry} was not incepted by {aid}"));
    }

    let anchored = kels
        .anchors_seal(aid, registry, 0, registry)
        .map_err(|e| format!("cannot check the registry anchor: {e}"))?;
    if !anchored {
        return Err(format!(
            "{aid}'s key event log does not anchor the inception of registry {registry}"
        ));
    }

    Ok(())
}

/// The issuance event must exist, belong to the registry, and be anchored.
fn verify_issued(
    kels: &Kels,
    aid: &str,
    registry: &str,
    acdc_said: &str,
) -> Result<String, String> {
    let iss = kels
        .messages_with_ilk("iss")
        .find(|m| m.serder.sad().get("i").and_then(|v| v.as_str()) == Some(acdc_said))
        .ok_or_else(|| format!("no issuance event for attestation {acdc_said}"))?;

    if iss.serder.sad().get("ri").and_then(|v| v.as_str()) != Some(registry) {
        return Err(format!(
            "attestation {acdc_said} was issued in a different registry than it names"
        ));
    }

    let iss_said = iss
        .serder
        .said()
        .map_err(|e| format!("issuance event has no SAID: {e}"))?;

    let anchored = kels
        .anchors_seal(aid, acdc_said, 0, &iss_said)
        .map_err(|e| format!("cannot check the issuance anchor: {e}"))?;
    if !anchored {
        return Err(format!(
            "{aid}'s key event log does not anchor the issuance of {acdc_said}"
        ));
    }

    Ok(iss_said)
}

/// Whether a revocation of the attestation is anchored in the AID's key event
/// log.
///
/// A revocation, like the issuance it withdraws, is the AID's act only once its
/// KEL anchors it. Requiring the anchor is also what makes historical
/// resolution right: a document resolved as of a version before the
/// revocation was anchored still carries the aliases.
fn is_revoked(kels: &Kels, aid: &str, acdc_said: &str) -> Result<bool, String> {
    for ilk in ["rev", "brv"] {
        for rev in kels
            .messages_with_ilk(ilk)
            .filter(|m| m.serder.sad().get("i").and_then(|v| v.as_str()) == Some(acdc_said))
        {
            let Ok(rev_said) = rev.serder.said() else {
                continue;
            };
            let sn = rev
                .serder
                .sad()
                .get("s")
                .and_then(|v| v.as_str())
                .and_then(|s| u64::from_str_radix(s, 16).ok())
                .unwrap_or(1);
            if kels
                .anchors_seal(aid, acdc_said, sn, &rev_said)
                .map_err(|e| format!("cannot check the revocation anchor: {e}"))?
            {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

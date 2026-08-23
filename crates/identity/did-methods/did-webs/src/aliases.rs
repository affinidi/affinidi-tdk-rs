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
//! Every link is checked. A break anywhere yields no aliases rather than a
//! partially-trusted list: an alias nobody authorised is exactly the claim an
//! attacker wants a resolver to repeat.
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
    // Fails loudly: everything below is meaningless without a verified KEL.
    kels.key_state(aid)?;

    let mut rejected = None;

    for acdc in kels.messages_with_ilk_none() {
        let sad = acdc.serder.sad();

        if sad.get("s").and_then(|v| v.as_str()) != Some(DESIGNATED_ALIASES_SCHEMA) {
            continue;
        }
        if sad.get("i").and_then(|v| v.as_str()) != Some(aid) {
            continue;
        }

        match verify_attestation(kels, aid, acdc) {
            Ok(aliases) => {
                return Ok(DesignatedAliases {
                    aliases,
                    rejected: None,
                });
            }
            Err(e) => rejected = Some(e),
        }
    }

    Ok(DesignatedAliases {
        aliases: Vec::new(),
        rejected,
    })
}

/// Verify one designated-aliases attestation end to end.
fn verify_attestation(
    kels: &Kels,
    aid: &str,
    acdc: &affinidi_keri_core::parser::ParsedMessage,
) -> Result<Vec<String>, String> {
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
    verify_issued(kels, aid, registry, &acdc_said)?;

    // 5. It has not been revoked.
    verify_not_revoked(kels, &acdc_said)?;

    // 6. Only then are its aliases worth reading.
    let ids = sad
        .get("a")
        .and_then(|a| a.get("ids"))
        .and_then(|ids| ids.as_array())
        .ok_or_else(|| "attestation carries no `a.ids` list".to_string())?;

    Ok(ids
        .iter()
        .filter_map(|v| v.as_str())
        .map(str::to_string)
        .collect())
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
    // withdraw an attestation the identifier never revoked.
    let state = kels
        .key_state_at(aid, &group.said)
        .map_err(|e| format!("cannot check the attestation signature: {e}"))?;

    let verfers: Vec<affinidi_keri_crypto::Verfer> = state
        .keys
        .iter()
        .map(|k| affinidi_keri_crypto::Verfer::from_qb64(k))
        .collect::<Result<_, _>>()
        .map_err(|e| format!("key state has an unusable key: {e}"))?;

    let mut valid = 0usize;
    for sig in &group.sigs {
        let Some(verfer) = verfers.get(sig.index()) else {
            continue;
        };
        if verfer
            .verify(acdc.serder.raw(), sig.raw())
            .map_err(|e| format!("signature check failed: {e}"))?
        {
            valid += 1;
        }
    }

    if valid == 0 {
        return Err(format!(
            "no signature on the attestation verifies against {aid}'s key state"
        ));
    }

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
fn verify_issued(kels: &Kels, aid: &str, registry: &str, acdc_said: &str) -> Result<(), String> {
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

    Ok(())
}

/// A revocation anywhere in the stream withdraws the attestation.
///
/// Revocations are not required to be anchored for this check: a *claimed*
/// revocation is reason enough to stop repeating the aliases, and treating an
/// unanchored revocation as invalid would let a stream suppress one by
/// malforming it.
fn verify_not_revoked(kels: &Kels, acdc_said: &str) -> Result<(), String> {
    for ilk in ["rev", "brv"] {
        let revoked = kels
            .messages_with_ilk(ilk)
            .any(|m| m.serder.sad().get("i").and_then(|v| v.as_str()) == Some(acdc_said));
        if revoked {
            return Err(format!("attestation {acdc_said} has been revoked"));
        }
    }
    Ok(())
}

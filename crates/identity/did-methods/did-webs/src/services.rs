//! Service endpoints, derived from signed KERI endpoint authorisations.
//!
//! A `did:webs` document does not get to list whatever endpoints it likes, any
//! more than it gets to assert its own aliases. An endpoint appears only when
//! two signed `rpy` messages agree:
//!
//! ```text
//! /end/role/add   signed by THIS AID    "I authorise <eid> in role <role>"
//! /loc/scheme     signed by <eid>       "I am reachable at <url> over <scheme>"
//! ```
//!
//! Both halves are required. The first without the second is an authorisation
//! pointing nowhere; the second without the first is a stranger volunteering to
//! act on someone's behalf. Neither is published.
//!
//! `/end/role/cut` withdraws an authorisation. Where the same subject is
//! addressed more than once, KERI's BADA rule picks the reply that stands: the
//! one signed under the **later establishment event**, and between replies
//! signed under the same one, the later `dt`. Ordering by `dt` alone would let
//! a key that has since been rotated out — the compromised key rotation exists
//! to retire — sign a reply dated far in the future and win every comparison
//! after it.

use std::collections::BTreeMap;

use affinidi_keri_core::parser::{Attachment, ParsedMessage};
use affinidi_keri_crypto::Verfer;
use chrono::{DateTime, FixedOffset};
use serde_json::Value;

use crate::errors::DidWebsError;
use crate::kel::Kels;

/// A service endpoint authorised by an AID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceEndpoint {
    /// The authorised identifier.
    pub eid: String,
    /// The role it was authorised in — `agent`, `controller`, `witness`,
    /// `mailbox`, and so on. Not an enumeration: KERI does not fix the set,
    /// and rejecting an unknown role would drop endpoints we simply have not
    /// heard of.
    pub role: String,
    /// Scheme to URL, e.g. `http` -> `http://example.com:5642`.
    pub urls: BTreeMap<String, String>,
}

impl ServiceEndpoint {
    /// The document-relative id, matching the reference implementation's
    /// `#<eid>/<role>` form.
    pub fn id(&self) -> String {
        format!("#{}/{}", self.eid, self.role)
    }
}

/// Where a reply stands in BADA order.
///
/// The sequence number of the establishment event whose keys signed it, then
/// its `dt`. A non-transferable signer's key never changes, so its replies all
/// share sequence number 0 and are ordered by `dt` alone.
type Seniority = (u64, DateTime<FixedOffset>);

/// One `/end/role/*` authorisation, kept with its seniority so a later reply
/// can supersede it.
struct RoleRecord {
    added: bool,
    seniority: Seniority,
}

/// Collect the service endpoints `aid` has authorised.
///
/// # Errors
/// Returns [`DidWebsError::Kel`] if `aid`'s own key event log does not verify.
/// An authorisation that fails to verify is skipped, not fatal — one malformed
/// reply must not cost an identifier its other endpoints.
pub fn service_endpoints(kels: &Kels, aid: &str) -> Result<Vec<ServiceEndpoint>, DidWebsError> {
    // Fails loudly: an authorisation signed by an unverified AID means nothing.
    kels.key_state(aid)?;

    let mut roles: BTreeMap<(String, String), RoleRecord> = BTreeMap::new();

    for rpy in kels.messages_with_ilk("rpy") {
        let sad = rpy.serder.sad();
        let route = sad.get("r").and_then(Value::as_str).unwrap_or_default();
        let added = match route {
            "/end/role/add" => true,
            "/end/role/cut" => false,
            _ => continue,
        };

        let attrs = sad.get("a");
        let (Some(cid), Some(role), Some(eid)) = (
            attrs.and_then(|a| a.get("cid")).and_then(Value::as_str),
            attrs.and_then(|a| a.get("role")).and_then(Value::as_str),
            attrs.and_then(|a| a.get("eid")).and_then(Value::as_str),
        ) else {
            continue;
        };

        // Only this AID's own authorisations. Without this check, anyone
        // could authorise endpoints on anyone's behalf by putting a reply in
        // the stream.
        if cid != aid {
            continue;
        }
        let Some(seniority) = reply_seniority(kels, rpy, aid) else {
            continue;
        };
        let key = (role.to_string(), eid.to_string());

        // A `cut` junior to the `add` it tries to withdraw does not take
        // effect, and neither does a replay of an older `add`. Equal seniority
        // is not newer, as in keripy.
        match roles.get(&key) {
            Some(existing) if existing.seniority >= seniority => {}
            _ => {
                roles.insert(key, RoleRecord { added, seniority });
            }
        }
    }

    let mut endpoints = Vec::new();
    for ((role, eid), record) in roles {
        if !record.added {
            continue;
        }
        let urls = location_schemes(kels, &eid);
        if urls.is_empty() {
            // Authorised, but it never said where it is. Publishing a service
            // with no endpoint would be worse than publishing none.
            continue;
        }
        endpoints.push(ServiceEndpoint { eid, role, urls });
    }

    Ok(endpoints)
}

/// The verified location schemes `eid` has published for itself.
fn location_schemes(kels: &Kels, eid: &str) -> BTreeMap<String, String> {
    let mut latest: BTreeMap<String, (Seniority, String)> = BTreeMap::new();

    for rpy in kels.messages_with_ilk("rpy") {
        let sad = rpy.serder.sad();
        if sad.get("r").and_then(Value::as_str) != Some("/loc/scheme") {
            continue;
        }

        let attrs = sad.get("a");
        let (Some(subject), Some(scheme), Some(url)) = (
            attrs.and_then(|a| a.get("eid")).and_then(Value::as_str),
            attrs.and_then(|a| a.get("scheme")).and_then(Value::as_str),
            attrs.and_then(|a| a.get("url")).and_then(Value::as_str),
        ) else {
            continue;
        };

        if subject != eid {
            continue;
        }
        // The endpoint has to say this about *itself*. A third party asserting
        // where someone else can be reached is a redirection, not a location.
        let Some(seniority) = reply_seniority(kels, rpy, eid) else {
            continue;
        };
        match latest.get(scheme) {
            Some((existing, _)) if *existing >= seniority => {}
            _ => {
                latest.insert(scheme.to_string(), (seniority, url.to_string()));
            }
        }
    }

    latest
        .into_iter()
        .map(|(scheme, (_, url))| (scheme, url))
        .collect()
}

/// Verify that `msg` is signed by `signer`, and say where it stands in BADA
/// order. `None` if it is not signed by `signer`, or its `dt` is not a
/// timestamp — a reply that cannot be ordered cannot supersede anything.
///
/// Two shapes, because KERI identifiers come in two kinds:
///
/// * a **transferable** identifier signs with indexed signatures in a
///   transferable signature group, checked against the key state at the
///   establishment event the group names — which must meet that key state's
///   signing threshold, not merely include one good signature;
/// * a **non-transferable** identifier — a witness, typically — has its public
///   key *as* its prefix, so a receipt couple can be checked directly.
fn reply_seniority(kels: &Kels, msg: &ParsedMessage, signer: &str) -> Option<Seniority> {
    let dt = msg.serder.sad().get("dt").and_then(Value::as_str)?;
    let dt = DateTime::parse_from_rfc3339(dt).ok()?;

    // Transferable: indexed signatures against verified key state. The group
    // names the establishment event whose keys signed; using the *current*
    // state instead would make every rotation invalidate every authorisation
    // the identifier had ever given.
    if let Some(group) = msg
        .trans_idx_sig_groups()
        .iter()
        .find(|g| g.prefix == signer)
    {
        return kels
            .verify_signature_group(signer, msg.serder.raw(), group)
            .ok()
            .map(|state| (state.sn, dt));
    }

    // Non-transferable: the prefix is the key.
    for att in &msg.attachments {
        let Attachment::ReceiptCouples(couples) = att else {
            continue;
        };
        for (prefix, sig) in couples {
            if prefix != signer {
                continue;
            }
            let Ok(verfer) = Verfer::from_qb64(prefix) else {
                continue;
            };
            if verfer.verify(msg.serder.raw(), sig).unwrap_or(false) {
                return Some((0, dt));
            }
        }
    }

    None
}

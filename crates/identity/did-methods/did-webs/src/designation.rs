//! Designations: credentials an AID issues to itself to say something about its
//! own DID document.
//!
//! A `did:webs` document does not get to assert anything the key event stream
//! does not establish. Where the specification lets the controller add to it —
//! designated aliases (§ Designated Aliases), and in this crate key agreement
//! keys, services and key roles (see [`crate::key_agreement`],
//! [`crate::designated_services`](mod@crate::designated_services) and
//! [`crate::key_roles`]) — the addition is an ACDC the AID issued to itself,
//! whose registry its own key event log anchors.
//!
//! Both ACDC versions are read, by `affinidi_keri_core::registry`:
//!
//! ```text
//! 1.x  KEL ixn ──anchors──▶ vcp, iss, rev   a TEL; the ACDC names it with `ri`
//!                                            and carries the AID's signature
//! 2.x  KEL ixn ──anchors──▶ rip, bup …      a registry; the ACDC names it with
//!                                            `rd`, and is issued when the latest
//!                                            non-vacuous update discloses it
//! ```
//!
//! Every link is checked. A credential that does not verify yields nothing and
//! is reported in `rejected`. A fault that makes the registry meaningless —
//! above all a registry event the KEL anchors that the stream leaves out, which
//! would let a host withhold a revocation — fails resolution (P5 of
//! `did-webs-keri-v2.md` in OpenVTC/verifiable-trust-infrastructure).
//!
//! Each designation has a v1 and a v2 schema (P4). A reader asks for both.

use affinidi_keri_core::registry::{self, Status};
use affinidi_keri_core::sad::SadValue;

use crate::errors::DidWebsError;
use crate::kel::Kels;

/// A designation that verified.
#[derive(Debug, Clone)]
// Everything but `attributes` is what `update` needs to revoke one.
#[cfg_attr(not(feature = "create"), allow(dead_code))]
pub(crate) struct Designation {
    /// The credential's SAID.
    pub said: String,
    /// The ACDC protocol major version: 1 or 2.
    pub version: u8,
    /// The registry it was issued in (`ri` in 1.x, `rd` in 2.x).
    pub registry: String,
    /// The registry event that decided its status: in 1.x its issuance, which
    /// a revocation names as prior.
    pub event: String,
    /// Its attribute block, `a`.
    pub attributes: SadValue,
}

/// Every credential of one of `schemas` that `aid` issued to itself, verified,
/// and not revoked. The first reason one did not verify is kept in `rejected`.
///
/// # Errors
/// Returns [`DidWebsError::Kel`] if `aid`'s key event log does not verify, and
/// [`DidWebsError::Registry`] if a registry is broken or the stream leaves out
/// a registry event the KEL anchors.
pub(crate) fn designations(
    kels: &Kels,
    aid: &str,
    schemas: &[&str],
    rejected: &mut Option<String>,
) -> Result<Vec<Designation>, DidWebsError> {
    Ok(issued_designations(kels, aid, schemas, rejected)?
        .into_iter()
        .filter(|(_, withdrawn)| !withdrawn)
        .map(|(designation, _)| designation)
        .collect())
}

/// Every credential of one of `schemas` that `aid` issued to itself and that
/// verifies, each with whether its issuer has since revoked it.
///
/// A withdrawn designation still says what its issuer stated while it stood;
/// a reader that must not forget a statement — a key revoked for compromise
/// stays revoked — reads these.
///
/// # Errors
/// As [`designations`].
pub(crate) fn issued_designations(
    kels: &Kels,
    aid: &str,
    schemas: &[&str],
    rejected: &mut Option<String>,
) -> Result<Vec<(Designation, bool)>, DidWebsError> {
    // Fails loudly: nothing below means anything without a verified KEL.
    // `issuer_log` verifies too (to the limit, then in full), but this gate
    // does not depend on it; `key_state` is cached, so it costs nothing.
    kels.key_state(aid)?;
    let log = kels.issuer_log(aid)?;
    let mut out = Vec::new();
    for schema in schemas {
        let found = registry::designations(kels.messages(), &log, schema)
            .map_err(|e| DidWebsError::Registry(e.to_string()))?;
        if let Some((said, reason)) = found.rejected.into_iter().next() {
            rejected.get_or_insert(format!("designation {said}: {reason}"));
        }
        for credential in found.credentials {
            let Some(attributes) = credential.sad.get("a").filter(|a| a.is_object()).cloned()
            else {
                rejected.get_or_insert(format!(
                    "designation {} carries no attribute block",
                    credential.said
                ));
                continue;
            };
            out.push((
                Designation {
                    said: credential.said,
                    version: credential.version,
                    registry: credential.registry,
                    event: credential.event,
                    attributes,
                },
                credential.status == Status::Revoked,
            ));
        }
    }
    Ok(out)
}

/// The schema of the first standing designation `aid` issued that is marked
/// `critical` and whose schema is not in `implemented`, if any.
///
/// A critical designation restricts what the key state alone would put in the
/// document (P6). A resolver that does not implement one must fail rather than
/// serve the unrestricted document, whatever `did.json` says: a host that
/// publishes the key-state derivation would otherwise pass every comparison.
///
/// Only a designation that verifies and stands counts, so a credential a host
/// adds to the stream cannot make a DID unresolvable.
///
/// # Errors
/// As [`designations`].
pub(crate) fn unsupported_critical(
    kels: &Kels,
    aid: &str,
    implemented: &[&str],
) -> Result<Option<String>, DidWebsError> {
    let mut schemas: Vec<String> = Vec::new();
    for msg in kels.messages() {
        let is_acdc = msg
            .serder
            .version
            .as_ref()
            .is_some_and(|v| v.protocol == "ACDC");
        let sad = msg.serder.sad();
        if !is_acdc || sad.get("i").and_then(|v| v.as_str()) != Some(aid) {
            continue;
        }
        // A registry event is an ACDC message too; only credentials name a
        // schema.
        let schema = match sad.get("s") {
            Some(SadValue::String(s)) => s.clone(),
            Some(s) => match s.get("$id").and_then(|v| v.as_str()) {
                Some(id) => id.to_string(),
                None => continue,
            },
            None => continue,
        };
        if !implemented.contains(&schema.as_str()) && !schemas.contains(&schema) {
            schemas.push(schema);
        }
    }

    for schema in schemas {
        let mut ignored = None;
        let standing = designations(kels, aid, &[schema.as_str()], &mut ignored)?;
        if standing
            .iter()
            .any(|d| d.attributes.get("critical") == Some(&SadValue::Bool(true)))
        {
            return Ok(Some(schema));
        }
    }
    Ok(None)
}

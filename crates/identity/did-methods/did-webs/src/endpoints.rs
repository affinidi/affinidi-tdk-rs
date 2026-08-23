//! Composing the signed replies that authorise a service endpoint.
//!
//! A service is not something a `did:webs` document may simply claim. The
//! resolver derives services from two signed `rpy` messages that have to agree
//! (see [`crate::services`]), so creating one means producing both:
//!
//! ```text
//! /end/role/add   signed by the AID    "I authorise <eid> in role <role>"
//! /loc/scheme     signed by <eid>      "I am reachable at <url> over <scheme>"
//! ```
//!
//! When the endpoint is the identifier itself, one key signs both. When it is
//! somebody else — a separate agent or mailbox — the second message can only be
//! signed by *their* key, which this crate does not hold, so those must arrive
//! pre-signed.

use affinidi_cesr::Counter;
use affinidi_keri::hab::Hab;
use affinidi_keri_core::said;
use affinidi_keri_core::serder::Serder;
use affinidi_keri_core::version::SerializationKind;
use serde_json::{Value, json};

use crate::create::SelfEndpoint;
use crate::errors::DidWebsError;

/// Build the `/end/role/add` and `/loc/scheme` replies for endpoints the
/// identifier designates for itself, signed and ready to append to the stream.
///
/// # Errors
/// Returns [`DidWebsError::Create`] if a reply cannot be built or signed.
pub(crate) fn self_designated_replies(
    hab: &Hab,
    aid: &str,
    establishment_said: &str,
    services: &[SelfEndpoint],
) -> Result<Vec<u8>, DidWebsError> {
    let mut out = Vec::new();

    for service in services {
        if service.urls.is_empty() {
            return Err(DidWebsError::Create(format!(
                "service role {:?} has no URLs; an endpoint with nowhere to \
                 reach it would be dropped on resolution",
                service.role,
            )));
        }

        let authorise = reply(
            "/end/role/add",
            json!({ "cid": aid, "role": service.role, "eid": aid }),
        )?;
        out.extend_from_slice(&sign_reply(hab, establishment_said, &authorise)?);

        for (scheme, url) in &service.urls {
            let location = reply(
                "/loc/scheme",
                json!({ "eid": aid, "scheme": scheme, "url": url }),
            )?;
            out.extend_from_slice(&sign_reply(hab, establishment_said, &location)?);
        }
    }

    Ok(out)
}

/// A `rpy` message with its SAID computed.
fn reply(route: &str, attrs: Value) -> Result<Serder, DidWebsError> {
    let mut sad = json!({
        "v": "KERI10JSON000000_",
        "t": "rpy",
        "d": "",
        "dt": timestamp(),
        "r": route,
        "a": attrs,
    });

    fix_version(&mut sad)?;
    said::compute_said(&mut sad, "d", "E", SerializationKind::Json)
        .map_err(|e| DidWebsError::Create(format!("could not compute reply SAID: {e}")))?;
    Serder::new(SerializationKind::Json, sad)
        .map_err(|e| DidWebsError::Create(format!("could not serialize reply: {e}")))
}

/// Attach a transferable indexed signature group, which is how a transferable
/// identifier signs something that is not part of its own key event log.
fn sign_reply(
    hab: &Hab,
    establishment_said: &str,
    serder: &Serder,
) -> Result<Vec<u8>, DidWebsError> {
    let signer = hab
        .signers()
        .first()
        .ok_or_else(|| DidWebsError::Create("identifier has no signing key".into()))?;
    let signature = signer
        .sign_indexed(serder.raw(), 0, true)
        .and_then(|s| s.qb64())
        .map_err(|e| DidWebsError::Create(format!("could not sign reply: {e}")))?;

    let inner = Counter::new("-A", 1)
        .and_then(|c| c.qb64())
        .map_err(|e| DidWebsError::Create(format!("counter: {e}")))?;
    let outer = Counter::new("-F", 1)
        .and_then(|c| c.qb64())
        .map_err(|e| DidWebsError::Create(format!("counter: {e}")))?;

    // prefix + sequence number + establishment SAID, then the signatures.
    let mut out = serder.raw().to_vec();
    out.extend_from_slice(outer.as_bytes());
    out.extend_from_slice(hab.prefix().as_bytes());
    out.extend_from_slice(sequence_number_qb64(hab.sn()).as_bytes());
    // The group names the establishment event whose key state authorises the
    // signature — not simply the latest event, which may be an interaction.
    out.extend_from_slice(establishment_said.as_bytes());
    out.extend_from_slice(inner.as_bytes());
    out.extend_from_slice(signature.as_bytes());
    Ok(out)
}

/// A CESR number primitive: `0A` plus 16 base64 characters.
fn sequence_number_qb64(sn: u64) -> String {
    let mut raw = [0u8; 16];
    raw[8..].copy_from_slice(&sn.to_be_bytes());
    let matter = affinidi_cesr::Matter::new("0A", raw.to_vec()).expect("0A takes 16 raw bytes");
    matter.qb64().expect("0A always encodes")
}

/// Fix the `v` size before computing the SAID, so the SAID covers the bytes the
/// message is actually serialized as.
fn fix_version(sad: &mut Value) -> Result<(), DidWebsError> {
    let placeholder = "#".repeat(44);
    let original = sad["d"].clone();
    sad["d"] = json!(placeholder);
    let len = serde_json::to_vec(sad)?.len();
    sad["v"] = json!(format!("KERI10JSON{len:06x}_"));
    sad["d"] = original;
    Ok(())
}

/// An ISO-8601 timestamp in the form KERI reply messages use.
///
/// Replies supersede one another by `dt`, so this has to move forward between
/// events that address the same subject.
fn timestamp() -> String {
    chrono::Utc::now()
        .format("%Y-%m-%dT%H:%M:%S%.6f+00:00")
        .to_string()
}

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

use crate::signing::{Controller, Establishment};
use affinidi_keri::ProtocolVersion;
use affinidi_keri_core::sad;
use affinidi_keri_core::sad::SadValue;
use affinidi_keri_core::said;
use affinidi_keri_core::serder::Serder;
use affinidi_keri_core::version::SerializationKind;

use crate::create::SelfEndpoint;
use crate::errors::DidWebsError;

/// Build the `/end/role/add` and `/loc/scheme` replies for endpoints the
/// identifier designates for itself, signed and ready to append to the stream.
///
/// # Errors
/// Returns [`DidWebsError::Create`] if a reply cannot be built or signed.
pub(crate) fn self_designated_replies(
    hab: &dyn Controller,
    aid: &str,
    establishment: &Establishment,
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
            hab,
            "/end/role/add",
            sad!({ "cid": aid, "role": service.role, "eid": aid }),
        )?;
        out.extend_from_slice(&sign_with_group(hab, establishment, &authorise)?);

        for (scheme, url) in &service.urls {
            let location = reply(
                hab,
                "/loc/scheme",
                sad!({ "eid": aid, "scheme": scheme, "url": url }),
            )?;
            out.extend_from_slice(&sign_with_group(hab, establishment, &location)?);
        }
    }

    Ok(out)
}

/// A `rpy` message with its SAID computed, in the identifier's version. A 2.x
/// reply names its sender in `i`, which 1.x has no field for.
fn reply(hab: &dyn Controller, route: &str, attrs: SadValue) -> Result<Serder, DidWebsError> {
    let version = hab.version();
    let mut sad = match version {
        ProtocolVersion::V1 => sad!({
            "v": "",
            "t": "rpy",
            "d": "",
            "dt": timestamp(),
            "r": route,
            "a": attrs,
        }),
        _ => sad!({
            "v": "",
            "t": "rpy",
            "d": "",
            "i": hab.prefix(),
            "dt": timestamp(),
            "r": route,
            "a": attrs,
        }),
    };

    fix_version_as(&mut sad, version)?;
    said::compute_said(&mut sad, "d", "E", SerializationKind::Json)
        .map_err(|e| DidWebsError::Create(format!("could not compute reply SAID: {e}")))?;
    Serder::new(SerializationKind::Json, sad)
        .map_err(|e| DidWebsError::Create(format!("could not serialize reply: {e}")))
}

/// Endorse `serder` by the identifier: one transferable indexed signature
/// group, naming the establishment event whose key state signs, in the
/// counter table of `serder`'s own version.
pub(crate) fn sign_with_group(
    hab: &dyn Controller,
    establishment: &Establishment,
    serder: &Serder,
) -> Result<Vec<u8>, DidWebsError> {
    // Enough current keys to meet the signing threshold, each at its own
    // index: a resolver holds the group to that threshold.
    let signatures = hab
        .sign_current(serder.raw())?
        .iter()
        .map(|s| affinidi_keri_crypto::Siger::from_qb64(s))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| DidWebsError::Create(format!("signature: {e}")))?;
    if signatures.is_empty() {
        return Err(DidWebsError::Create("identifier has no signing key".into()));
    }
    affinidi_keri_core::composer::compose_endorsed(
        serder,
        hab.prefix(),
        establishment.sn,
        &establishment.said,
        &signatures,
    )
    .map_err(|e| DidWebsError::Create(format!("endorsement: {e}")))
}

/// Size a KERI 1.x event's version string to its serialized length.
pub(crate) fn fix_version(sad: &mut SadValue) -> Result<(), DidWebsError> {
    fix_version_as(sad, ProtocolVersion::V1)
}

/// Size an event's version string, in `version`, to its serialized length.
pub(crate) fn fix_version_as(
    sad: &mut SadValue,
    version: ProtocolVersion,
) -> Result<(), DidWebsError> {
    use affinidi_keri_core::version::Version;
    let at = |size: usize| {
        match version {
            ProtocolVersion::V1 => Version::default_v1(SerializationKind::Json, size),
            _ => Version::default_v2(SerializationKind::Json, size),
        }
        .to_version_string()
    };
    let placeholder = "#".repeat(44);
    let original = sad["d"].clone();
    sad["d"] = sad!(placeholder);
    sad["v"] = sad!(at(0));
    let len = serde_json::to_vec(sad)?.len();
    sad["v"] = sad!(at(len));
    sad["d"] = original;
    Ok(())
}

/// An ISO-8601 timestamp in the form KERI reply messages use.
///
/// Replies supersede one another by `dt`, so this has to move forward between
/// events that address the same subject.
pub(crate) fn timestamp() -> String {
    chrono::Utc::now()
        .format("%Y-%m-%dT%H:%M:%S%.6f+00:00")
        .to_string()
}

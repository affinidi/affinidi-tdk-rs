//! Key roles, designated by the AID.
//!
//! **A proposed extension to the `did:webs` specification**, built as a proof
//! of concept. A resolver that does not implement it derives a different
//! document for an identifier that uses it — the key state's keys where this
//! one renders role keys — and so refuses the published `did.json` as not
//! matching. That interoperability gap is what adopting the extension in the
//! specification closes; until then, only resolvers built on this crate
//! resolve such an identifier.
//!
//! # The problem
//!
//! A `did:webs` document derived from key state alone places every key of the
//! current key state in both `authentication` and `assertionMethod`. Those keys
//! are the identifier's change authority. A verifier that needs to know which
//! key may sign what — the Verifiable Trust Infrastructure's key roles
//! (VTI-KEY-070 to VTI-KEY-096) — cannot tell them apart, and the change
//! authority ends up as a signing key for everything (VTI-KEY-173).
//!
//! # The mechanism
//!
//! A key role designation is an ACDC of schema [`KEY_ROLE_SCHEMA`] the AID
//! issues to itself and anchors in its KEL, like the other designations in
//! this crate. Its `a.roles` binds keys to roles:
//!
//! | Role | Signs or is used for | Rendered in |
//! |---|---|---|
//! | `attestation` | attestation artefacts | `assertionMethod` |
//! | `operational` | operational material | `authentication` |
//! | `messaging` | key agreement; signs nothing | `keyAgreement` |
//!
//! Once an identifier has issued one, its document is a key-role document for
//! the life of the identity:
//!
//! * the verification methods are the role keys of the designation that
//!   stands, each in its role's relationship and no other, and a top-level
//!   `keyRoles` maps each role to them;
//! * the key state's keys, and the `ConditionalProof2022` that states their
//!   threshold, are rendered nowhere — the KEL alone states the update
//!   authority;
//! * key agreement designations no longer apply: the `messaging` role governs.
//!
//! # Rotation and revocation
//!
//! Only one key role designation stands: issuing one revokes the last. A
//! planned rotation of a role key is a new designation without it, and the key
//! leaves the document. A revocation for compromise is a new designation that
//! lists the key in `a.revoked` with its compromise time. A revoked key stays
//! in the document's `verificationMethod`, carrying `revoked`, in no
//! relationship and not in `keyRoles`.
//!
//! A revocation is never forgotten. The resolver reads the `revoked` entries
//! of **every** key role designation the AID has issued, standing or since
//! replaced: a compromise statement stays true after the designation that made
//! it is replaced, so a later designation that leaves an entry out does not
//! un-revoke the key. Where two designations give one key different times, the
//! earlier stands. The issuer carries every earlier entry forward anyway, so
//! the standing designation states them all.
//!
//! # Failing closed
//!
//! A standing designation that does not verify as a whole — a key of the
//! current key state or of the next-key commitment, a key under two roles or
//! listed and revoked at once, a key the role cannot use — binds nothing, and
//! neither do two standing at once. The document then lists no role key at
//! all, keeps its revoked keys, and never falls back to the key state's keys.
//! A role name the reader does not recognise is ignored (VTI-KEY-074).

use affinidi_cesr::Matter;
use affinidi_keri_core::SadValue;
use chrono::{DateTime, FixedOffset};
use serde_json::Value;

use crate::designation::issued_designations;
use crate::errors::DidWebsError;
use crate::kel::Kels;
use crate::key_agreement::KeyAgreementKey;

/// The ACDC schema SAID of a key role designation.
///
/// The schema is `schemas/key-role-designation.json` in this crate; a test
/// recomputes its SAID.
pub const KEY_ROLE_SCHEMA: &str = "EPulJFl5SEb8qb3ca5teXHRGiWmTsTkylGTrS2vB4ZQx";

/// The key role designation schema document.
pub const KEY_ROLE_SCHEMA_JSON: &str = include_str!("../schemas/key-role-designation.json");

/// A registered key role.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum KeyRole {
    /// Signs attestation artefacts; rendered in `assertionMethod`.
    Attestation,
    /// Signs the identifier's operational material; rendered in
    /// `authentication`.
    Operational,
    /// Key agreement for encrypted transports, signing nothing; rendered in
    /// `keyAgreement`.
    Messaging,
}

impl KeyRole {
    /// Every registered role, in the order a document lists them.
    pub const ALL: [KeyRole; 3] = [Self::Attestation, Self::Operational, Self::Messaging];

    /// The role's name, as `a.roles` and `keyRoles` spell it.
    pub fn name(self) -> &'static str {
        match self {
            Self::Attestation => "attestation",
            Self::Operational => "operational",
            Self::Messaging => "messaging",
        }
    }

    /// The registered role a name spells, if any.
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|r| r.name() == name)
    }

    /// The one verification relationship the role's keys appear in.
    pub fn relationship(self) -> &'static str {
        match self {
            Self::Attestation => "assertionMethod",
            Self::Operational => "authentication",
            Self::Messaging => "keyAgreement",
        }
    }
}

/// A public key that signs: the kind an `attestation` or `operational` role
/// binds.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum VerificationKey {
    /// An Ed25519 public key.
    Ed25519([u8; 32]),
    /// A NIST P-256 public key, SEC1 compressed (33 bytes).
    P256(Vec<u8>),
    /// A secp256k1 public key, SEC1 compressed (33 bytes).
    Secp256k1(Vec<u8>),
}

impl VerificationKey {
    /// The key's CESR encoding, transferable form.
    ///
    /// # Errors
    /// Returns [`DidWebsError::InvalidKey`] if the key has the wrong length.
    pub fn to_cesr(&self) -> Result<String, DidWebsError> {
        let (code, raw) = match self {
            Self::Ed25519(raw) => ("D", raw.to_vec()),
            Self::P256(raw) => ("1AAJ", raw.clone()),
            Self::Secp256k1(raw) => ("1AAB", raw.clone()),
        };
        Matter::new(code, raw)
            .and_then(|m| m.qb64())
            .map_err(|e| DidWebsError::InvalidKey(format!("cannot encode {self:?}: {e}")))
    }

    /// Read a key from its CESR encoding.
    ///
    /// # Errors
    /// Returns [`DidWebsError::InvalidKey`] if it is not a CESR verification
    /// key of a supported curve.
    pub fn from_cesr(qb64: &str) -> Result<Self, DidWebsError> {
        let matter = Matter::from_qb64(qb64).map_err(|e| {
            DidWebsError::InvalidKey(format!("{qb64:?} is not a CESR primitive: {e}"))
        })?;
        let raw = matter.raw().to_vec();
        match matter.code() {
            "B" | "D" => raw
                .try_into()
                .map(Self::Ed25519)
                .map_err(|_| DidWebsError::InvalidKey(format!("{qb64:?} is not 32 bytes"))),
            "1AAI" | "1AAJ" => Ok(Self::P256(raw)),
            "1AAA" | "1AAB" => Ok(Self::Secp256k1(raw)),
            other => Err(DidWebsError::InvalidKey(format!(
                "{qb64:?} uses CESR code {other:?}, which is not a verification key"
            ))),
        }
    }
}

/// A key revoked for compromise, with the time from which it is to be treated
/// as compromised (VTI-KEY-121).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RevokedKey {
    /// The CESR-encoded public key.
    pub key: String,
    /// The compromise time, RFC 3339.
    pub compromised_at: String,
}

impl RevokedKey {
    /// A key revoked for compromise from `compromised_at` (RFC 3339).
    pub fn new(key: impl Into<String>, compromised_at: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            compromised_at: compromised_at.into(),
        }
    }
}

/// The keys an identifier binds to roles, to designate.
#[derive(Debug, Clone, Default, PartialEq)]
#[non_exhaustive]
pub struct KeyRoles {
    /// Keys that sign attestation artefacts.
    pub attestation: Vec<VerificationKey>,
    /// Keys that sign operational material.
    pub operational: Vec<VerificationKey>,
    /// Key agreement keys.
    pub messaging: Vec<KeyAgreementKey>,
    /// Keys revoked for compromise. Every earlier revocation is carried
    /// forward on issuance whether listed here or not.
    pub revoked: Vec<RevokedKey>,
}

impl KeyRoles {
    /// No keys.
    pub fn new() -> Self {
        Self::default()
    }

    /// Bind a key to `attestation`.
    pub fn with_attestation(mut self, key: VerificationKey) -> Self {
        self.attestation.push(key);
        self
    }

    /// Bind a key to `operational`.
    pub fn with_operational(mut self, key: VerificationKey) -> Self {
        self.operational.push(key);
        self
    }

    /// Bind a key to `messaging`.
    pub fn with_messaging(mut self, key: KeyAgreementKey) -> Self {
        self.messaging.push(key);
        self
    }

    /// Revoke a key for compromise.
    pub fn with_revoked(mut self, revoked: RevokedKey) -> Self {
        self.revoked.push(revoked);
        self
    }

    /// The role keys, CESR-encoded, in document order.
    ///
    /// # Errors
    /// Returns [`DidWebsError::InvalidKey`] if a key cannot be encoded.
    #[cfg(feature = "create")]
    pub(crate) fn encoded(&self) -> Result<Vec<(KeyRole, Vec<String>)>, DidWebsError> {
        let signing = |keys: &[VerificationKey]| -> Result<Vec<String>, DidWebsError> {
            keys.iter().map(VerificationKey::to_cesr).collect()
        };
        Ok(vec![
            (KeyRole::Attestation, signing(&self.attestation)?),
            (KeyRole::Operational, signing(&self.operational)?),
            (
                KeyRole::Messaging,
                self.messaging
                    .iter()
                    .map(KeyAgreementKey::to_cesr)
                    .collect::<Result<_, _>>()?,
            ),
        ])
    }

    /// The binding a standing designation states, read back into keys.
    ///
    /// # Errors
    /// Returns [`DidWebsError::InvalidKey`] if a key is not the kind its role
    /// binds.
    #[cfg(feature = "create")]
    pub(crate) fn from_standing(
        roles: &[(KeyRole, Vec<String>)],
        revoked: &[RevokedKey],
    ) -> Result<Self, DidWebsError> {
        let mut out = Self {
            revoked: revoked.to_vec(),
            ..Self::default()
        };
        for (role, keys) in roles {
            for key in keys {
                match role {
                    KeyRole::Attestation => out.attestation.push(VerificationKey::from_cesr(key)?),
                    KeyRole::Operational => out.operational.push(VerificationKey::from_cesr(key)?),
                    KeyRole::Messaging => out.messaging.push(KeyAgreementKey::from_cesr(key)?),
                }
            }
        }
        Ok(out)
    }
}

/// The public JWK of a key bound to `role`, with its CESR encoding as `kid`.
///
/// # Errors
/// Returns why the key is not one the role can bind.
pub(crate) fn role_key_jwk(role: KeyRole, qb64: &str) -> Result<Value, String> {
    match role {
        KeyRole::Attestation | KeyRole::Operational => {
            VerificationKey::from_cesr(qb64).map_err(|e| e.to_string())?;
            crate::document::jwk_from_cesr_key(qb64).map_err(|e| e.to_string())
        }
        KeyRole::Messaging => KeyAgreementKey::from_cesr(qb64)
            .and_then(|k| k.public_jwk())
            .map_err(|e| e.to_string()),
    }
}

/// The public JWK of a revoked key, whichever kind it was.
pub(crate) fn revoked_key_jwk(qb64: &str) -> Result<Value, String> {
    role_key_jwk(KeyRole::Operational, qb64).or_else(|_| role_key_jwk(KeyRole::Messaging, qb64))
}

/// What resolution read from an AID's key role designations.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct DesignatedKeyRoles {
    /// Whether the AID has issued any key role designation that verifies. When
    /// it has, its document is a key-role document, whether or not one stands.
    pub issued: bool,
    /// The binding of the designation that stands, role by role in document
    /// order — empty when none stands or the one that stands did not verify.
    pub roles: Vec<(KeyRole, Vec<String>)>,
    /// Every key revoked for compromise, across every key role designation the
    /// AID has issued.
    pub revoked: Vec<RevokedKey>,
    /// Why a designation bound nothing, when one did not verify.
    pub rejected: Option<String>,
}

/// Read the key roles `aid` has designated.
///
/// # Errors
/// Returns [`DidWebsError::Kel`] only if `aid`'s own key event log does not
/// verify.
pub fn designated_key_roles(kels: &Kels, aid: &str) -> Result<DesignatedKeyRoles, DidWebsError> {
    let state = kels.key_state(aid)?;
    let mut out = DesignatedKeyRoles::default();
    let issued = issued_designations(kels, aid, KEY_ROLE_SCHEMA, &mut out.rejected)?;
    out.issued = !issued.is_empty();

    // Every revocation ever stated, the earliest time for a key.
    let mut revoked: Vec<(RevokedKey, DateTime<FixedOffset>)> = Vec::new();
    for (designation, _) in &issued {
        match read_revoked(&designation.attributes) {
            Ok(entries) => {
                for (entry, at) in entries {
                    match revoked.iter_mut().find(|(r, _)| r.key == entry.key) {
                        Some(existing) if at < existing.1 => *existing = (entry, at),
                        Some(_) => {}
                        None => revoked.push((entry, at)),
                    }
                }
            }
            Err(e) => {
                out.rejected.get_or_insert(e);
            }
        }
    }
    out.revoked = revoked.into_iter().map(|(r, _)| r).collect();

    let standing: Vec<_> = issued.iter().filter(|(_, withdrawn)| !withdrawn).collect();
    match standing.as_slice() {
        [] => {}
        [(designation, _)] => {
            match read_roles(
                &designation.attributes,
                &state.keys,
                &state.next_keys,
                &out.revoked,
            ) {
                Ok(roles) => out.roles = roles,
                Err(e) => {
                    out.rejected.get_or_insert(e);
                }
            }
        }
        _ => {
            out.rejected
                .get_or_insert_with(|| "more than one key role designation stands".to_string());
        }
    }
    Ok(out)
}

/// The revocations a designation states.
fn read_revoked(attributes: &SadValue) -> Result<Vec<(RevokedKey, DateTime<FixedOffset>)>, String> {
    let Some(entries) = attributes.get("revoked") else {
        return Ok(Vec::new());
    };
    let entries = entries
        .as_array()
        .ok_or_else(|| "`a.revoked` is not a list".to_string())?;
    entries
        .iter()
        .map(|entry| {
            let key = entry
                .get("key")
                .and_then(SadValue::as_str)
                .ok_or_else(|| "a revoked entry names no key".to_string())?;
            revoked_key_jwk(key).map_err(|e| format!("revoked key {key}: {e}"))?;
            let at = entry
                .get("compromisedAt")
                .and_then(SadValue::as_str)
                .ok_or_else(|| format!("revoked key {key} has no compromise time"))?;
            let parsed = DateTime::parse_from_rfc3339(at)
                .map_err(|e| format!("revoked key {key}: compromise time {at:?}: {e}"))?;
            Ok((RevokedKey::new(key, at), parsed))
        })
        .collect()
}

/// The binding the standing designation states, checked as a whole.
fn read_roles(
    attributes: &SadValue,
    keys_in_state: &[String],
    next_keys: &[String],
    revoked: &[RevokedKey],
) -> Result<Vec<(KeyRole, Vec<String>)>, String> {
    let roles = attributes
        .get("roles")
        .and_then(SadValue::as_object)
        .ok_or_else(|| "key role designation carries no `a.roles`".to_string())?;

    let mut seen: Vec<Vec<u8>> = Vec::new();
    let mut out = Vec::new();
    for role in KeyRole::ALL {
        // A role the reader does not recognise is skipped by never being
        // asked for (VTI-KEY-074).
        let Some(keys) = roles.get(role.name()) else {
            continue;
        };
        let keys = keys
            .as_array()
            .filter(|k| !k.is_empty())
            .ok_or_else(|| format!("role {} lists no keys", role.name()))?;
        let mut listed = Vec::with_capacity(keys.len());
        for key in keys {
            let qb64 = key
                .as_str()
                .ok_or_else(|| format!("a {} key is not a string", role.name()))?;
            role_key_jwk(role, qb64).map_err(|e| format!("{} key {qb64}: {e}", role.name()))?;
            check_role_key(qb64, keys_in_state, next_keys, revoked)?;
            let raw = raw_of(qb64).ok_or_else(|| format!("{qb64} is not a CESR primitive"))?;
            if seen.contains(&raw) {
                return Err(format!("{qb64} is bound to more than one role"));
            }
            seen.push(raw);
            listed.push(qb64.to_string());
        }
        out.push((role, listed));
    }
    Ok(out)
}

/// A role key is never a key of the key state, nor one the key state has
/// committed to rotate to, nor a revoked key (VTI-KEY-071, VTI-KEY-093,
/// VTI-KEY-123).
pub(crate) fn check_role_key(
    qb64: &str,
    keys_in_state: &[String],
    next_keys: &[String],
    revoked: &[RevokedKey],
) -> Result<(), String> {
    let raw = raw_of(qb64).ok_or_else(|| format!("{qb64} is not a CESR primitive"))?;
    if keys_in_state
        .iter()
        .any(|k| raw_of(k).as_deref() == Some(raw.as_slice()))
    {
        return Err(format!("{qb64} is a key of the identifier's key state"));
    }
    let committed = affinidi_keri_crypto::Diger::from_data("E", qb64.as_bytes())
        .and_then(|d| d.qb64())
        .is_ok_and(|digest| next_keys.contains(&digest));
    if committed {
        return Err(format!(
            "{qb64} is a key the identifier's key state has committed to rotate to"
        ));
    }
    if revoked
        .iter()
        .any(|r| raw_of(&r.key).as_deref() == Some(raw.as_slice()))
    {
        return Err(format!("{qb64} is revoked for compromise"));
    }
    Ok(())
}

/// The raw bytes of a CESR primitive, for comparing a key across encodings.
pub(crate) fn raw_of(qb64: &str) -> Option<Vec<u8>> {
    Matter::from_qb64(qb64).ok().map(|m| m.raw().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_verification_key_round_trips_through_cesr() {
        let key = VerificationKey::Ed25519([3u8; 32]);
        let qb64 = key.to_cesr().expect("encodes");
        assert!(qb64.starts_with('D'), "{qb64}");
        assert_eq!(VerificationKey::from_cesr(&qb64).expect("decodes"), key);
    }

    #[test]
    fn roles_render_in_one_relationship_each() {
        assert_eq!(KeyRole::Attestation.relationship(), "assertionMethod");
        assert_eq!(KeyRole::Operational.relationship(), "authentication");
        assert_eq!(KeyRole::Messaging.relationship(), "keyAgreement");
        assert_eq!(KeyRole::from_name("update"), None);
    }

    fn ed(seed: u8) -> String {
        VerificationKey::Ed25519([seed; 32])
            .to_cesr()
            .expect("cesr")
    }

    fn attributes(roles: serde_json::Value) -> SadValue {
        SadValue::from_json_value(&serde_json::json!({ "d": "", "dt": "", "roles": roles }))
    }

    #[test]
    fn a_designation_binding_a_key_of_the_key_state_binds_nothing() {
        let kel_key = ed(1);
        let err = read_roles(
            &attributes(serde_json::json!({ "attestation": [kel_key.clone()] })),
            &[kel_key],
            &[],
            &[],
        )
        .expect_err("the change authority is no role key");
        assert!(err.contains("key state"), "{err}");
    }

    #[test]
    fn a_designation_binding_a_committed_next_key_binds_nothing() {
        let next = ed(2);
        let digest = affinidi_keri_crypto::Diger::from_data("E", next.as_bytes())
            .and_then(|d| d.qb64())
            .expect("digest");
        let err = read_roles(
            &attributes(serde_json::json!({ "operational": [next] })),
            &[],
            &[digest],
            &[],
        )
        .expect_err("a key the KEL will rotate to is no role key");
        assert!(err.contains("committed"), "{err}");
    }

    #[test]
    fn a_key_under_two_roles_or_both_bound_and_revoked_binds_nothing() {
        let key = ed(3);
        assert!(
            read_roles(
                &attributes(serde_json::json!({ "attestation": [key.clone()], "operational": [key.clone()] })),
                &[],
                &[],
                &[],
            )
            .is_err()
        );
        assert!(
            read_roles(
                &attributes(serde_json::json!({ "attestation": [key.clone()] })),
                &[],
                &[],
                &[RevokedKey::new(key, "2026-01-01T00:00:00Z")],
            )
            .is_err()
        );
    }

    #[test]
    fn an_unknown_role_is_ignored() {
        let roles = read_roles(
            &attributes(serde_json::json!({ "attestation": [ed(4)], "futureRole": [ed(5)] })),
            &[],
            &[],
            &[],
        )
        .expect("binds");
        assert_eq!(roles, vec![(KeyRole::Attestation, vec![ed(4)])]);
    }

    #[test]
    fn a_messaging_key_cannot_sign_and_a_signing_key_cannot_agree() {
        let x25519 = KeyAgreementKey::X25519([4u8; 32]).to_cesr().expect("cesr");
        let ed25519 = VerificationKey::Ed25519([4u8; 32]).to_cesr().expect("cesr");
        assert!(role_key_jwk(KeyRole::Attestation, &x25519).is_err());
        assert!(role_key_jwk(KeyRole::Messaging, &ed25519).is_err());
        assert!(role_key_jwk(KeyRole::Messaging, &x25519).is_ok());
    }
}

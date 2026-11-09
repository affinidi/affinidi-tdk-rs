//! Key agreement keys, designated by the AID.
//!
//! A `did:webs` document derived from key state alone has no `keyAgreement`:
//! the KEL's keys are signing keys, and they are the identifier's change
//! authority. The specification permits other verification relationships
//! ("MAY also include other verification relationship properties") and, among
//! the ways it lists to establish key agreement, names an ACDC anchored in the
//! KEL "the best mechanism" (Implementors Guide, § Key Agreement). This module
//! is that mechanism: a designation of schema
//! [`KEY_AGREEMENT_SCHEMA`] whose `a.keys` are CESR-encoded public keys.
//!
//! The keys are separate from the key state on purpose. Converting the
//! identifier's Ed25519 signing key to X25519 — the other way the guide lists —
//! would make the key that controls the identifier an encryption key, and an
//! encryption key could never change without rotating the identifier. A
//! designated key is replaced by revoking its designation and issuing another,
//! with no rotation. A designated key equal to a key of the current key state
//! is dropped on resolution for the same reason.
//!
//! # Identifiers that designate none
//!
//! Most KERI identifiers designate nothing: KERI practice, and the reference
//! implementation's DIDComm support, encrypt to the X25519 key converted from
//! each Ed25519 key of the current key state. [`converted_key_agreement`]
//! computes those keys, and resolution renders them into `keyAgreement`
//! (`crate::resolver`) — but only for an AID that has never issued a key
//! agreement or key role designation. An AID that has issued one chose separate
//! keys, and a revoked designation is not a return to conversion: such an AID
//! has no key agreement until it designates another.
//!
//! | Key | CESR code | `publicKeyJwk` |
//! |---|---|---|
//! | X25519 | `C` | `OKP` / `X25519` |
//! | NIST P-256, compressed | `1AAJ` | `EC` / `P-256` |
//! | secp256k1, compressed | `1AAB` | `EC` / `secp256k1` |
//!
//! A P-256 or secp256k1 point is checked to be on its curve before it is
//! published.

use affinidi_cesr::Matter;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Value, json};

use crate::designation::issued_designations;
use crate::errors::DidWebsError;
use crate::kel::Kels;

/// The ACDC schema SAID of a key agreement designation.
///
/// The schema is `schemas/key-agreement-designation.json` in this crate; a
/// test recomputes its SAID.
pub const KEY_AGREEMENT_SCHEMA: &str = "EJZrf6N4vbhA1hQIujWiIiQmNi455EGS3iXdhxLSwvAi";

/// The key agreement designation schema document.
pub const KEY_AGREEMENT_SCHEMA_JSON: &str =
    include_str!("../schemas/key-agreement-designation.json");

/// A public key designated for key agreement.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum KeyAgreementKey {
    /// An X25519 public key.
    X25519([u8; 32]),
    /// A NIST P-256 public key, SEC1 compressed (33 bytes).
    P256(Vec<u8>),
    /// A secp256k1 public key, SEC1 compressed (33 bytes).
    Secp256k1(Vec<u8>),
}

impl KeyAgreementKey {
    /// The key's CESR encoding: its identity in the designation and the
    /// fragment of its verification method id.
    ///
    /// # Errors
    /// Returns [`DidWebsError::InvalidKey`] if the key has the wrong length.
    pub fn to_cesr(&self) -> Result<String, DidWebsError> {
        let (code, raw) = match self {
            Self::X25519(raw) => ("C", raw.to_vec()),
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
    /// Returns [`DidWebsError::InvalidKey`] if it is not a CESR primitive or not
    /// a key type usable for key agreement.
    pub fn from_cesr(qb64: &str) -> Result<Self, DidWebsError> {
        let matter = Matter::from_qb64(qb64).map_err(|e| {
            DidWebsError::InvalidKey(format!("{qb64:?} is not a CESR primitive: {e}"))
        })?;
        let raw = matter.raw().to_vec();
        match matter.code() {
            "C" => raw
                .try_into()
                .map(Self::X25519)
                .map_err(|_| DidWebsError::InvalidKey(format!("{qb64:?} is not 32 bytes"))),
            "1AAI" | "1AAJ" => Ok(Self::P256(raw)),
            "1AAA" | "1AAB" => Ok(Self::Secp256k1(raw)),
            other => Err(DidWebsError::InvalidKey(format!(
                "{qb64:?} uses CESR code {other:?}, which is not a key agreement key type"
            ))),
        }
    }

    /// The raw public key, for comparing keys across encodings.
    pub fn raw(&self) -> &[u8] {
        match self {
            Self::X25519(raw) => raw,
            Self::P256(raw) | Self::Secp256k1(raw) => raw,
        }
    }

    /// The key as a public JWK, with its CESR encoding as `kid`.
    ///
    /// # Errors
    /// Returns [`DidWebsError::InvalidKey`] if an EC point is not on its curve.
    pub fn public_jwk(&self) -> Result<Value, DidWebsError> {
        let mut jwk = match self {
            Self::X25519(raw) => json!({
                "kty": "OKP",
                "crv": "X25519",
                "x": URL_SAFE_NO_PAD.encode(raw),
            }),
            Self::P256(raw) => {
                serde_json::to_value(affinidi_crypto::p256::public_jwk(raw).map_err(not_a_key)?)?
            }
            Self::Secp256k1(raw) => serde_json::to_value(
                affinidi_crypto::secp256k1::public_jwk(raw).map_err(not_a_key)?,
            )?,
        };
        // A public JWK serializes its absent private part as `"d": null`.
        if let Some(obj) = jwk.as_object_mut() {
            obj.retain(|_, v| !v.is_null());
        }
        jwk["kid"] = json!(self.to_cesr()?);
        Ok(jwk)
    }
}

fn not_a_key(e: impl std::fmt::Display) -> DidWebsError {
    DidWebsError::InvalidKey(format!("not a valid public key: {e}"))
}

/// The key agreement keys an AID has designated, and how far verification got.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct DesignatedKeys {
    /// The designated keys, CESR-encoded, from every designation that verified
    /// and stands unrevoked.
    pub keys: Vec<String>,
    /// Why a designation the stream carried produced no keys, when one did not
    /// verify.
    pub rejected: Option<String>,
    /// Whether the AID has issued any key agreement designation that verifies,
    /// standing or since revoked.
    pub issued: bool,
}

/// Collect the key agreement keys `aid` has designated.
///
/// A designation naming a key that is not a usable key agreement key yields
/// nothing: it is not the credential the schema describes.
///
/// # Errors
/// Returns [`DidWebsError::Kel`] only if `aid`'s own key event log does not
/// verify.
pub fn designated_key_agreement(kels: &Kels, aid: &str) -> Result<DesignatedKeys, DidWebsError> {
    let mut out = DesignatedKeys::default();
    let issued = issued_designations(kels, aid, KEY_AGREEMENT_SCHEMA, &mut out.rejected)?;
    out.issued = !issued.is_empty();
    let standing = issued
        .into_iter()
        .filter(|(_, withdrawn)| !withdrawn)
        .map(|(designation, _)| designation);
    for designation in standing {
        match read_keys(&designation.attributes) {
            Ok(keys) => {
                for key in keys {
                    if !out.keys.contains(&key) {
                        out.keys.push(key);
                    }
                }
            }
            Err(e) => {
                out.rejected.get_or_insert(e);
            }
        }
    }
    Ok(out)
}

/// The X25519 keys converted from the Ed25519 keys of a key state, CESR-encoded
/// (`C`), in key-state order.
///
/// This is the conversion KERI practice uses for an AID that designates no key
/// agreement keys (see the module documentation). A key that is not Ed25519
/// (`D`, or `B` non-transferable), does not decode to a curve point, or is of
/// small order converts to nothing: Diffie-Hellman with a small-order point
/// yields a value an attacker can predict.
pub fn converted_key_agreement(state_keys: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for key in state_keys {
        let Ok(matter) = Matter::from_qb64(key) else {
            continue;
        };
        if !matches!(matter.code(), "D" | "B") {
            continue;
        }
        let Ok(raw) = <[u8; 32]>::try_from(matter.raw()) else {
            continue;
        };
        let Ok(verifying) = ed25519_dalek::VerifyingKey::from_bytes(&raw) else {
            continue;
        };
        if verifying.is_weak() {
            continue;
        }
        let converted = KeyAgreementKey::X25519(verifying.to_montgomery().to_bytes());
        if let Ok(qb64) = converted.to_cesr()
            && !out.contains(&qb64)
        {
            out.push(qb64);
        }
    }
    out
}

fn read_keys(attributes: &affinidi_keri_core::SadValue) -> Result<Vec<String>, String> {
    let keys = attributes
        .get("keys")
        .and_then(|v| v.as_array())
        .filter(|keys| !keys.is_empty())
        .ok_or_else(|| "key agreement designation carries no `a.keys`".to_string())?;
    keys.iter()
        .map(|k| {
            let qb64 = k
                .as_str()
                .ok_or_else(|| "a designated key is not a string".to_string())?;
            let key = KeyAgreementKey::from_cesr(qb64).map_err(|e| e.to_string())?;
            // Decompressing an EC point checks it is on the curve.
            key.public_jwk().map_err(|e| e.to_string())?;
            Ok(qb64.to_string())
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_x25519_key_round_trips_through_cesr() {
        let key = KeyAgreementKey::X25519([7u8; 32]);
        let qb64 = key.to_cesr().expect("encodes");
        assert!(qb64.starts_with('C'), "{qb64}");
        assert_eq!(KeyAgreementKey::from_cesr(&qb64).expect("decodes"), key);

        let jwk = key.public_jwk().expect("jwk");
        assert_eq!(jwk["kty"], "OKP");
        assert_eq!(jwk["crv"], "X25519");
        assert_eq!(jwk["kid"], qb64);
    }

    #[test]
    fn an_ed25519_state_key_converts_to_its_x25519_key() {
        // RFC 8032 test 1's public key; its Montgomery form is what
        // `crypto_sign_pk_to_box_pk` (libsodium, which keripy uses) returns.
        let ed = hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        let state_key = Matter::new("D", ed).expect("matter").qb64().expect("qb64");
        // libsodium's answer, computed independently with PyNaCl.
        let x: [u8; 32] = hex("d85e07ec22b0ad881537c2f44d662d1a143cf830c57aca4305d85c7a90f6b62e")
            .try_into()
            .unwrap();

        let converted = converted_key_agreement(&[state_key.clone(), state_key]);
        assert_eq!(converted.len(), 1, "one key converts once");
        assert_eq!(
            KeyAgreementKey::from_cesr(&converted[0]).expect("decodes"),
            KeyAgreementKey::X25519(x)
        );
    }

    #[test]
    fn a_key_that_is_not_ed25519_or_is_weak_converts_to_nothing() {
        // The identity point (small order), as an Ed25519 key.
        let mut identity = vec![0u8; 32];
        identity[0] = 1;
        let weak = Matter::new("D", identity).unwrap().qb64().unwrap();
        // An X25519 key is already one, and a secp256k1 key has no conversion.
        let x = KeyAgreementKey::X25519([9u8; 32]).to_cesr().unwrap();
        assert!(converted_key_agreement(&[weak, x, "not cesr".into()]).is_empty());
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn a_p256_point_off_the_curve_is_refused() {
        let mut raw = vec![0x02];
        raw.extend([0xffu8; 32]);
        assert!(KeyAgreementKey::P256(raw).public_jwk().is_err());
    }

    #[test]
    fn a_signing_key_code_that_is_not_a_key_agreement_type_is_refused() {
        // An Ed25519 verification key ("D") cannot do Diffie-Hellman as it is.
        assert!(
            KeyAgreementKey::from_cesr("DHr0-I-mMN7h6cLMOTRJkkfPuMd0vgQPrOk4Y3edaHjr").is_err()
        );
    }
}

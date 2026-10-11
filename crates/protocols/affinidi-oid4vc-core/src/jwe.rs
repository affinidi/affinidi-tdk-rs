//! Compact JWE with `ECDH-ES` direct key agreement — the encrypted
//! authorization response of OpenID4VP 1.0 (`response_mode=direct_post.jwt`).
//!
//! A verifier publishes a fresh P-256 public key in the request object's
//! `client_metadata.jwks` and names the `enc` values it accepts; the wallet
//! answers with a compact JWE whose CEK comes from `ECDH-ES` between that key
//! and an ephemeral key of its own (`epk`). OpenID4VP 1.0 and HAIP use `A128GCM`
//! and `A256GCM`; swiyu requires `A256GCM`. Nothing else is accepted here.
//!
//! The allow-list is the caller's, per call: an `enc` the caller did not pass is
//! refused before any key agreement, whatever the header says. `alg` is always
//! `ECDH-ES` (direct — no key wrap, so the encrypted-key segment is empty), and a
//! header that asks for compression (`zip`) or marks anything critical (`crit`)
//! is refused rather than half-understood.
//!
//! The decryption key is held as its raw scalar so a verifier can keep it
//! between issuing a request and receiving the response — encrypted at rest,
//! and deleted when the exchange closes. It is zeroized on drop and never
//! printed.

use affinidi_crypto::jose::ecdh::{derive_key_es, derive_key_es_recipient};
use affinidi_crypto::jose::gcm;
use affinidi_crypto::jose::key_agreement::{
    Curve, EphemeralKeyPair, PrivateKeyAgreement, PublicKeyAgreement,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Map, Value, json};
use zeroize::Zeroizing;

/// The JWE `alg` this module implements: `ECDH-ES` direct key agreement.
pub const ALG_ECDH_ES: &str = "ECDH-ES";

/// A content-encryption algorithm (`enc`) this module implements.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ContentEncryption {
    /// `A128GCM`.
    A128Gcm,
    /// `A256GCM`.
    A256Gcm,
}

impl ContentEncryption {
    /// The JOSE identifier.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::A128Gcm => "A128GCM",
            Self::A256Gcm => "A256GCM",
        }
    }

    /// Parse a JOSE identifier this module implements.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "A128GCM" => Some(Self::A128Gcm),
            "A256GCM" => Some(Self::A256Gcm),
            _ => None,
        }
    }

    fn key_bits(&self) -> u32 {
        match self {
            Self::A128Gcm => 128,
            Self::A256Gcm => 256,
        }
    }

    fn seal(
        &self,
        plaintext: &[u8],
        cek: &[u8],
        iv: &[u8],
        aad: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), JweError> {
        match self {
            Self::A128Gcm => gcm::encrypt_a128(plaintext, cek, iv, aad),
            Self::A256Gcm => gcm::encrypt_a256(plaintext, cek, iv, aad),
        }
        .map_err(|e| JweError::Crypto(e.to_string()))
    }

    fn open(
        &self,
        ciphertext: &[u8],
        cek: &[u8],
        iv: &[u8],
        aad: &[u8],
        tag: &[u8],
    ) -> Result<Vec<u8>, JweError> {
        match self {
            Self::A128Gcm => gcm::decrypt_a128(ciphertext, cek, iv, aad, tag),
            Self::A256Gcm => gcm::decrypt_a256(ciphertext, cek, iv, aad, tag),
        }
        .map_err(|_| JweError::Decryption)
    }
}

/// Why a JWE could not be built or opened.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum JweError {
    /// Not a compact JWE, or a segment is not valid base64url / JSON.
    #[error("malformed JWE: {0}")]
    Malformed(String),
    /// The header names an algorithm, encryption or feature this caller does
    /// not accept.
    #[error("unsupported JWE: {0}")]
    Unsupported(String),
    /// The header's `kid` names a different key than the one decrypting.
    #[error("the JWE is addressed to key {found:?}, not {expected:?}")]
    WrongKey {
        /// The `kid` the decrypting key carries.
        expected: String,
        /// The `kid` the header names.
        found: String,
    },
    /// The tag did not verify: wrong key, or altered ciphertext, IV, header or
    /// tag. Deliberately one variant, so a refusal says nothing about which.
    #[error("the JWE did not decrypt")]
    Decryption,
    /// A key or primitive failed.
    #[error("crypto error: {0}")]
    Crypto(String),
}

/// A P-256 key a verifier decrypts `ECDH-ES` responses with.
///
/// One per exchange: generate it with the request, publish
/// [`public_jwk`](Self::public_jwk) in `client_metadata.jwks`, and drop it when
/// the exchange closes.
pub struct EcdhEsDecryptionKey {
    kid: String,
    scalar: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for EcdhEsDecryptionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EcdhEsDecryptionKey")
            .field("kid", &self.kid)
            .field("scalar", &"<redacted>")
            .finish()
    }
}

impl EcdhEsDecryptionKey {
    /// A fresh random P-256 key, identified by `kid` in its JWK.
    pub fn generate(kid: impl Into<String>) -> Self {
        let kp = affinidi_crypto::p256::generate_random();
        Self {
            kid: kid.into(),
            scalar: Zeroizing::new(kp.private_bytes.clone()),
        }
    }

    /// Rebuild a key from the scalar [`scalar_bytes`](Self::scalar_bytes)
    /// returned, e.g. after holding it encrypted in a session store.
    pub fn from_scalar(kid: impl Into<String>, scalar: &[u8]) -> Result<Self, JweError> {
        PrivateKeyAgreement::from_raw_bytes(Curve::P256, scalar)
            .map_err(|e| JweError::Crypto(e.to_string()))?;
        Ok(Self {
            kid: kid.into(),
            scalar: Zeroizing::new(scalar.to_vec()),
        })
    }

    /// The key's `kid`.
    pub fn kid(&self) -> &str {
        &self.kid
    }

    /// The private scalar, for a caller that must persist the key between
    /// request and response. Treat it as the secret it is.
    pub fn scalar_bytes(&self) -> &[u8] {
        &self.scalar
    }

    /// The public JWK to publish in `client_metadata.jwks`: `kty`, `crv`, `x`,
    /// `y`, `kid`, `use: "enc"` and `alg: "ECDH-ES"`.
    pub fn public_jwk(&self) -> Result<Value, JweError> {
        let mut jwk = self.private()?.public_key().to_jwk();
        if let Some(obj) = jwk.as_object_mut() {
            obj.insert("kid".into(), json!(self.kid));
            obj.insert("use".into(), json!("enc"));
            obj.insert("alg".into(), json!(ALG_ECDH_ES));
        }
        Ok(jwk)
    }

    fn private(&self) -> Result<PrivateKeyAgreement, JweError> {
        PrivateKeyAgreement::from_raw_bytes(Curve::P256, &self.scalar)
            .map_err(|e| JweError::Crypto(e.to_string()))
    }
}

/// An opened JWE: its protected header and the plaintext.
#[derive(Debug)]
pub struct DecryptedJwe {
    /// The protected header, as received.
    pub header: Map<String, Value>,
    /// The decrypted payload.
    pub plaintext: Vec<u8>,
}

/// Decrypt a compact JWE made with `ECDH-ES` to `key`, accepting only the
/// `enc` values in `allowed_enc`.
///
/// Refused before any key agreement: an `alg` other than `ECDH-ES`, an `enc`
/// not in `allowed_enc`, a `zip` or `crit` header, a non-empty encrypted-key
/// segment, a `kid` naming another key, or an `epk` not on P-256.
pub fn decrypt_compact(
    jwe: &str,
    key: &EcdhEsDecryptionKey,
    allowed_enc: &[ContentEncryption],
) -> Result<DecryptedJwe, JweError> {
    let mut parts = jwe.split('.');
    let (Some(header_b64), Some(encrypted_key), Some(iv), Some(ct), Some(tag), None) = (
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
    ) else {
        return Err(JweError::Malformed(
            "a compact JWE has five dot-separated segments".into(),
        ));
    };

    let header: Map<String, Value> = serde_json::from_slice(&b64(header_b64, "header")?)
        .map_err(|e| JweError::Malformed(format!("header is not a JSON object: {e}")))?;

    let alg = str_member(&header, "alg")?;
    if alg != ALG_ECDH_ES {
        return Err(JweError::Unsupported(format!(
            "alg {alg:?}; only {ALG_ECDH_ES} (direct) is accepted"
        )));
    }
    let enc_name = str_member(&header, "enc")?;
    let enc = ContentEncryption::parse(enc_name)
        .filter(|e| allowed_enc.contains(e))
        .ok_or_else(|| JweError::Unsupported(format!("enc {enc_name:?} is not accepted")))?;
    if header.contains_key("zip") {
        return Err(JweError::Unsupported(
            "compressed (zip) content is not accepted".into(),
        ));
    }
    if header.contains_key("crit") {
        return Err(JweError::Unsupported(
            "a critical (crit) header is not accepted".into(),
        ));
    }
    if !encrypted_key.is_empty() {
        return Err(JweError::Malformed(
            "ECDH-ES direct carries no encrypted key".into(),
        ));
    }
    if let Some(kid) = header.get("kid") {
        let kid = kid
            .as_str()
            .ok_or_else(|| JweError::Malformed("kid is not a string".into()))?;
        if kid != key.kid {
            return Err(JweError::WrongKey {
                expected: key.kid.clone(),
                found: kid.to_string(),
            });
        }
    }

    let epk_jwk = header
        .get("epk")
        .ok_or_else(|| JweError::Malformed("header has no epk".into()))?;
    let epk = PublicKeyAgreement::from_jwk(epk_jwk)
        .map_err(|e| JweError::Malformed(format!("epk is not a usable key: {e}")))?;
    if epk.curve() != Curve::P256 {
        return Err(JweError::Unsupported(format!(
            "epk is on {}, not P-256",
            epk.curve().jwk_crv()
        )));
    }
    let apu = optional_b64(&header, "apu")?;
    let apv = optional_b64(&header, "apv")?;

    let cek = Zeroizing::new(
        derive_key_es_recipient(
            &key.private()?,
            &epk,
            enc.as_str().as_bytes(),
            &apu,
            &apv,
            enc.key_bits(),
        )
        .map_err(|e| JweError::Crypto(e.to_string()))?,
    );

    let plaintext = enc.open(
        &b64(ct, "ciphertext")?,
        &cek,
        &b64(iv, "iv")?,
        header_b64.as_bytes(),
        &b64(tag, "tag")?,
    )?;
    Ok(DecryptedJwe { header, plaintext })
}

/// Encrypt `plaintext` to `recipient_jwk` (a P-256 public JWK) with `ECDH-ES`
/// and `enc` — the wallet's side, and what tests use to exercise
/// [`decrypt_compact`]. The recipient's `kid`, when its JWK has one, is copied
/// into the header; `apu` / `apv` go in base64url when non-empty.
pub fn encrypt_compact(
    plaintext: &[u8],
    recipient_jwk: &Value,
    enc: ContentEncryption,
    apu: &[u8],
    apv: &[u8],
) -> Result<String, JweError> {
    let recipient = PublicKeyAgreement::from_jwk(recipient_jwk)
        .map_err(|e| JweError::Malformed(format!("recipient key is not usable: {e}")))?;
    if recipient.curve() != Curve::P256 {
        return Err(JweError::Unsupported(
            "the recipient key must be P-256".into(),
        ));
    }
    let ephemeral = EphemeralKeyPair::generate(Curve::P256);

    let mut header = Map::new();
    header.insert("alg".into(), json!(ALG_ECDH_ES));
    header.insert("enc".into(), json!(enc.as_str()));
    if let Some(kid) = recipient_jwk.get("kid").and_then(Value::as_str) {
        header.insert("kid".into(), json!(kid));
    }
    header.insert("epk".into(), ephemeral.public.to_jwk());
    if !apu.is_empty() {
        header.insert("apu".into(), json!(URL_SAFE_NO_PAD.encode(apu)));
    }
    if !apv.is_empty() {
        header.insert("apv".into(), json!(URL_SAFE_NO_PAD.encode(apv)));
    }
    let header_b64 = URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(&header).map_err(|e| JweError::Malformed(e.to_string()))?);

    let cek = Zeroizing::new(
        derive_key_es(
            &ephemeral.private,
            &recipient,
            enc.as_str().as_bytes(),
            apu,
            apv,
            enc.key_bits(),
        )
        .map_err(|e| JweError::Crypto(e.to_string()))?,
    );
    let iv = gcm::generate_iv();
    let (ct, tag) = enc.seal(plaintext, &cek, &iv, header_b64.as_bytes())?;
    Ok(format!(
        "{header_b64}..{}.{}.{}",
        URL_SAFE_NO_PAD.encode(iv),
        URL_SAFE_NO_PAD.encode(ct),
        URL_SAFE_NO_PAD.encode(tag)
    ))
}

fn b64(segment: &str, what: &str) -> Result<Vec<u8>, JweError> {
    URL_SAFE_NO_PAD
        .decode(segment)
        .map_err(|e| JweError::Malformed(format!("{what} is not base64url: {e}")))
}

fn str_member<'a>(header: &'a Map<String, Value>, name: &str) -> Result<&'a str, JweError> {
    header
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| JweError::Malformed(format!("header has no string {name}")))
}

fn optional_b64(header: &Map<String, Value>, name: &str) -> Result<Vec<u8>, JweError> {
    match header.get(name) {
        None => Ok(Vec::new()),
        Some(Value::String(s)) => b64(s, name),
        Some(_) => Err(JweError::Malformed(format!("{name} is not a string"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BOTH: &[ContentEncryption] = &[ContentEncryption::A128Gcm, ContentEncryption::A256Gcm];

    #[test]
    fn round_trips_for_each_enc() {
        let key = EcdhEsDecryptionKey::generate("resp-1");
        let jwk = key.public_jwk().unwrap();
        assert_eq!(jwk["use"], "enc");
        assert_eq!(jwk["alg"], "ECDH-ES");
        assert_eq!(jwk["crv"], "P-256");
        for enc in BOTH {
            let jwe = encrypt_compact(b"{\"vp_token\":{}}", &jwk, *enc, b"", b"nonce-1").unwrap();
            let opened = decrypt_compact(&jwe, &key, BOTH).unwrap();
            assert_eq!(opened.plaintext, b"{\"vp_token\":{}}");
            assert_eq!(opened.header["enc"], enc.as_str());
            assert_eq!(opened.header["kid"], "resp-1");
        }
    }

    /// A key kept as its scalar (in a session store, say) and rebuilt decrypts
    /// what was sent to the original.
    #[test]
    fn a_key_rebuilt_from_its_scalar_still_decrypts() {
        let key = EcdhEsDecryptionKey::generate("k");
        let jwe = encrypt_compact(
            b"hi",
            &key.public_jwk().unwrap(),
            ContentEncryption::A256Gcm,
            b"",
            b"",
        )
        .unwrap();
        let rebuilt = EcdhEsDecryptionKey::from_scalar("k", key.scalar_bytes()).unwrap();
        assert_eq!(
            decrypt_compact(&jwe, &rebuilt, BOTH).unwrap().plaintext,
            b"hi"
        );
    }

    #[test]
    fn an_enc_the_caller_did_not_allow_is_refused() {
        let key = EcdhEsDecryptionKey::generate("k");
        let jwe = encrypt_compact(
            b"x",
            &key.public_jwk().unwrap(),
            ContentEncryption::A128Gcm,
            b"",
            b"",
        )
        .unwrap();
        let err = decrypt_compact(&jwe, &key, &[ContentEncryption::A256Gcm]).unwrap_err();
        assert!(matches!(err, JweError::Unsupported(_)), "{err}");
    }

    #[test]
    fn another_keys_response_does_not_decrypt() {
        let key = EcdhEsDecryptionKey::generate("k");
        let other = EcdhEsDecryptionKey::generate("k");
        let jwe = encrypt_compact(
            b"x",
            &other.public_jwk().unwrap(),
            ContentEncryption::A256Gcm,
            b"",
            b"",
        )
        .unwrap();
        assert!(matches!(
            decrypt_compact(&jwe, &key, BOTH).unwrap_err(),
            JweError::Decryption
        ));
    }

    #[test]
    fn a_kid_naming_another_key_is_refused() {
        let key = EcdhEsDecryptionKey::generate("mine");
        let other = EcdhEsDecryptionKey::generate("theirs");
        let jwe = encrypt_compact(
            b"x",
            &other.public_jwk().unwrap(),
            ContentEncryption::A256Gcm,
            b"",
            b"",
        )
        .unwrap();
        assert!(matches!(
            decrypt_compact(&jwe, &key, BOTH).unwrap_err(),
            JweError::WrongKey { .. }
        ));
    }

    /// Re-encode the header of `jwe` after `edit`, keeping the other segments.
    fn with_header(jwe: &str, edit: impl FnOnce(&mut Map<String, Value>)) -> String {
        let mut parts: Vec<String> = jwe.split('.').map(str::to_string).collect();
        let mut header: Map<String, Value> =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(&parts[0]).unwrap()).unwrap();
        edit(&mut header);
        parts[0] = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
        parts.join(".")
    }

    #[test]
    fn alg_zip_crit_and_an_encrypted_key_are_refused() {
        let key = EcdhEsDecryptionKey::generate("k");
        let jwe = encrypt_compact(
            b"x",
            &key.public_jwk().unwrap(),
            ContentEncryption::A256Gcm,
            b"",
            b"",
        )
        .unwrap();

        let wrapped = with_header(&jwe, |h| {
            h.insert("alg".into(), json!("ECDH-ES+A256KW"));
        });
        assert!(matches!(
            decrypt_compact(&wrapped, &key, BOTH).unwrap_err(),
            JweError::Unsupported(_)
        ));
        let zipped = with_header(&jwe, |h| {
            h.insert("zip".into(), json!("DEF"));
        });
        assert!(matches!(
            decrypt_compact(&zipped, &key, BOTH).unwrap_err(),
            JweError::Unsupported(_)
        ));
        let critical = with_header(&jwe, |h| {
            h.insert("crit".into(), json!(["x"]));
        });
        assert!(matches!(
            decrypt_compact(&critical, &key, BOTH).unwrap_err(),
            JweError::Unsupported(_)
        ));

        let mut parts: Vec<&str> = jwe.split('.').collect();
        parts[1] = "AAAA";
        assert!(matches!(
            decrypt_compact(&parts.join("."), &key, BOTH).unwrap_err(),
            JweError::Malformed(_)
        ));
    }

    /// The protected header is the AAD: changing a member the checks above let
    /// through (`apv`) breaks the tag rather than slipping past.
    #[test]
    fn an_altered_header_breaks_the_tag() {
        let key = EcdhEsDecryptionKey::generate("k");
        let jwe = encrypt_compact(
            b"x",
            &key.public_jwk().unwrap(),
            ContentEncryption::A256Gcm,
            b"",
            b"nonce-1",
        )
        .unwrap();
        let altered = with_header(&jwe, |h| {
            h.insert("apv".into(), json!(URL_SAFE_NO_PAD.encode(b"nonce-2")));
        });
        assert!(matches!(
            decrypt_compact(&altered, &key, BOTH).unwrap_err(),
            JweError::Decryption
        ));
    }

    #[test]
    fn debug_never_prints_the_scalar() {
        let key = EcdhEsDecryptionKey::generate("k");
        let printed = format!("{key:?}");
        assert!(printed.contains("<redacted>"), "{printed}");
        assert!(!printed.contains(&format!("{:?}", key.scalar_bytes())));
    }
}

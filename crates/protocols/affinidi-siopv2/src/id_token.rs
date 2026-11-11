/*!
 * Self-Issued ID Token per SIOPv2 spec.
 *
 * The critical invariant: `iss == sub` — this signals the token is self-issued.
 *
 * # Subject Types
 *
 * - **JWK Thumbprint**: `sub` = base64url(SHA-256(canonical_jwk)),
 *   `sub_jwk` claim MUST be present
 * - **DID**: `sub` = DID string (e.g., "did:key:z6Mk..."),
 *   `sub_jwk` MUST NOT be present
 */

use affinidi_oid4vc_core::eddsa::EdDsaVerifier;
use affinidi_oid4vc_core::es256::Es256Verifier;
use affinidi_oid4vc_core::jwt::{
    Audience, JwtSigner, JwtVerifier, decode_compact_jws_unverified,
    decode_compact_jws_verified_with_algs, encode_compact_jws,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::error::{Result, SiopError};

/// A Self-Issued ID Token's claims per SIOPv2.
///
/// This is the payload only. [`sign`](Self::sign) produces the compact JWS a
/// wallet sends; a relying party checks a received token with
/// [`verify_id_token`], which verifies the signature before it checks the
/// claims.
///
/// The `iss` and `sub` claims MUST be identical, signaling self-issuance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelfIssuedIdToken {
    /// Issuer — MUST equal `sub` for self-issued tokens.
    pub iss: String,
    /// Subject — JWK Thumbprint URI or DID.
    pub sub: String,
    /// Audience — MUST contain the RP's `client_id`. A single string or an
    /// array (RFC 7519 §4.1.3).
    pub aud: Audience,
    /// Expiration time (Unix timestamp).
    pub exp: i64,
    /// Issued-at time (Unix timestamp).
    pub iat: i64,
    /// Nonce from the authorization request (replay protection).
    pub nonce: String,
    /// Public key for JWK Thumbprint subjects. MUST NOT be present for DID subjects.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub_jwk: Option<Value>,
    /// Time of authentication (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_time: Option<i64>,
    /// Authentication context class reference (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acr: Option<String>,
    /// Authentication methods references (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amr: Option<Vec<String>>,
    /// Additional claims (name, email, etc. — self-attested).
    #[serde(flatten)]
    pub additional_claims: serde_json::Map<String, Value>,
}

/// What a relying party expects of a received ID Token.
#[derive(Debug, Clone)]
pub struct IdTokenExpectations<'a> {
    /// The JWS algorithms accepted (e.g. the `id_token_signing_alg_values_supported`
    /// the RP advertised). Only `ES256` and `EdDSA` can be verified against a
    /// `sub_jwk`; an empty list rejects every token.
    pub allowed_algs: &'a [&'a str],
    /// The RP's `client_id`; `aud` must contain it.
    pub client_id: &'a str,
    /// The nonce the RP sent in the authorization request.
    pub nonce: &'a str,
    /// The current time (Unix seconds).
    pub now: i64,
    /// Clock skew tolerated on `exp` and `iat`, in seconds.
    pub leeway_seconds: i64,
}

impl<'a> IdTokenExpectations<'a> {
    /// Expectations at the system clock's current time with 60 seconds of leeway.
    pub fn new(allowed_algs: &'a [&'a str], client_id: &'a str, nonce: &'a str) -> Self {
        Self {
            allowed_algs,
            client_id,
            nonce,
            now: Utc::now().timestamp(),
            leeway_seconds: 60,
        }
    }
}

/// Resolves the verification key for a DID subject's ID Token.
///
/// `kid` is the JWS header `kid`, already checked to be a DID URL under the
/// token's `sub`. An implementation resolves the DID, finds that verification
/// method, checks it is authorised for `authentication`, and returns a
/// verifier for its key that matches `alg`.
pub trait DidKeyResolver {
    /// A verifier for the key `kid` names, for algorithm `alg`.
    fn resolve(&self, kid: &str, alg: &str) -> Result<Box<dyn JwtVerifier>>;
}

/// Verify a received Self-Issued ID Token (compact JWS) and return its claims.
///
/// 1. The header `alg` must be in `expected.allowed_algs` (and is never `none`).
/// 2. The signature is verified:
///    - JWK Thumbprint subject: with the key in `sub_jwk` (`ES256` for an EC
///      P-256 key, `EdDSA` for an Ed25519 key);
///    - DID subject: the header `kid` must be a DID URL under `sub`, and the
///      key comes from `did_resolver`. Without a resolver a DID subject is
///      rejected.
/// 3. The verified claims pass [`SelfIssuedIdToken::validate_claims`],
///    which includes `sub` matching the thumbprint of `sub_jwk`.
///
/// Not checked: `nbf`, a maximum token lifetime (`exp - iat`), and the
/// header `typ`. Callers that need them must check them on the returned
/// claims and header.
pub fn verify_id_token(
    jwt: &str,
    expected: &IdTokenExpectations<'_>,
    did_resolver: Option<&dyn DidKeyResolver>,
) -> Result<SelfIssuedIdToken> {
    let (header, unverified_payload) = decode_compact_jws_unverified(jwt)
        .map_err(|e| SiopError::InvalidIdToken(format!("malformed JWS: {e}")))?;
    let alg = header
        .get("alg")
        .and_then(Value::as_str)
        .ok_or_else(|| SiopError::InvalidIdToken("missing alg in JWS header".into()))?;
    if !expected.allowed_algs.contains(&alg) {
        return Err(SiopError::InvalidIdToken(format!(
            "JWS alg \"{alg}\" is not in the allowed set {:?}",
            expected.allowed_algs
        )));
    }
    let sub = unverified_payload
        .get("sub")
        .and_then(Value::as_str)
        .ok_or_else(|| SiopError::InvalidIdToken("missing sub".into()))?;

    let verifier: Box<dyn JwtVerifier> = if sub.starts_with("did:") {
        let kid = header
            .get("kid")
            .and_then(Value::as_str)
            .ok_or_else(|| SiopError::InvalidIdToken("DID subject requires a kid".into()))?;
        if !kid_is_under_did(kid, sub) {
            return Err(SiopError::InvalidIdToken(format!(
                "kid {kid} is not a verification method of {sub}"
            )));
        }
        let resolver = did_resolver.ok_or_else(|| {
            SiopError::InvalidIdToken("no DID key resolver for a DID subject".into())
        })?;
        resolver.resolve(kid, alg)?
    } else {
        let jwk = unverified_payload
            .get("sub_jwk")
            .ok_or_else(|| SiopError::InvalidIdToken("sub_jwk required".into()))?;
        verifier_for_jwk(jwk, alg)?
    };

    let (_, payload) =
        decode_compact_jws_verified_with_algs(jwt, verifier.as_ref(), expected.allowed_algs)
            .map_err(|e| SiopError::SignatureInvalid(e.to_string()))?;
    let token: SelfIssuedIdToken = serde_json::from_value(payload)?;
    token.validate_claims(expected)?;
    Ok(token)
}

fn kid_is_under_did(kid: &str, did: &str) -> bool {
    kid.strip_prefix(did)
        .and_then(|rest| rest.strip_prefix('#'))
        .is_some_and(|fragment| !fragment.is_empty())
}

fn verifier_for_jwk(jwk: &Value, alg: &str) -> Result<Box<dyn JwtVerifier>> {
    let kty = jwk.get("kty").and_then(Value::as_str);
    let crv = jwk.get("crv").and_then(Value::as_str);
    let unusable = |reason: String| SiopError::InvalidIdToken(format!("sub_jwk: {reason}"));
    match (alg, kty, crv) {
        ("ES256", Some("EC"), Some("P-256")) => {
            for coordinate in ["x", "y"] {
                let length = jwk
                    .get(coordinate)
                    .and_then(Value::as_str)
                    .and_then(|encoded| URL_SAFE_NO_PAD.decode(encoded).ok())
                    .map(|bytes| bytes.len());
                if length != Some(32) {
                    return Err(unusable(format!(
                        "P-256 coordinate {coordinate} must be 32 bytes"
                    )));
                }
            }
            Ok(Box::new(
                Es256Verifier::from_jwk(jwk).map_err(|e| unusable(e.to_string()))?,
            ))
        }
        ("EdDSA", Some("OKP"), Some("Ed25519")) => Ok(Box::new(
            EdDsaVerifier::from_jwk(jwk).map_err(|e| unusable(e.to_string()))?,
        )),
        _ => Err(unusable(format!(
            "alg {alg} with kty {kty:?} / crv {crv:?} is not supported"
        ))),
    }
}

impl SelfIssuedIdToken {
    /// Whether this is a DID-based subject (vs JWK Thumbprint).
    pub fn is_did_subject(&self) -> bool {
        self.sub.starts_with("did:")
    }

    /// Whether this is a JWK Thumbprint subject.
    pub fn is_jwk_thumbprint_subject(&self) -> bool {
        self.sub_jwk.is_some()
    }

    /// Sign the claims as a compact JWS (the `id_token` a wallet returns).
    ///
    /// For a DID subject the signer must carry a `kid` that is a DID URL
    /// under `sub`, so the relying party can find the key. For a JWK
    /// Thumbprint subject the signer's key must be the one in `sub_jwk`.
    pub fn sign(&self, signer: &dyn JwtSigner) -> Result<String> {
        let kid = signer.key_id();
        if self.is_did_subject() && !kid.is_some_and(|kid| kid_is_under_did(kid, &self.sub)) {
            return Err(SiopError::InvalidIdToken(
                "a DID subject's signer needs a kid naming a verification method of that DID"
                    .into(),
            ));
        }
        let mut header = json!({ "alg": signer.algorithm(), "typ": "JWT" });
        if let Some(kid) = kid {
            header["kid"] = json!(kid);
        }
        let payload = serde_json::to_value(self)?;
        encode_compact_jws(&header, &payload, signer)
            .map_err(|e| SiopError::InvalidIdToken(format!("signing failed: {e}")))
    }

    /// Check the token's claims. **Does not verify any signature**: use
    /// [`verify_id_token`] on the received JWS, which calls this after the
    /// signature verifies. Claims taken from an unverified JWT prove nothing,
    /// since anyone can produce a `sub_jwk` and a matching `sub`.
    ///
    /// Checks:
    /// 1. `iss == sub` (self-issued invariant)
    /// 2. `aud` contains `expected.client_id`
    /// 3. `nonce` equals `expected.nonce`
    /// 4. `exp` has not passed and `iat` is not in the future (both with
    ///    `expected.leeway_seconds`)
    /// 5. `sub_jwk` is absent for a DID subject; otherwise present, and `sub`
    ///    is its JWK Thumbprint
    ///
    /// Not checked: `nbf` and a maximum token lifetime (`exp - iat`).
    pub fn validate_claims(&self, expected: &IdTokenExpectations<'_>) -> Result<()> {
        if self.iss != self.sub {
            return Err(SiopError::IssSubMismatch);
        }

        if !self.aud.contains(expected.client_id) {
            return Err(SiopError::AudienceMismatch {
                expected: expected.client_id.to_string(),
                actual: self.aud.iter().collect::<Vec<_>>().join(" "),
            });
        }

        if self.nonce != expected.nonce {
            return Err(SiopError::NonceMismatch);
        }

        if expected.now > self.exp.saturating_add(expected.leeway_seconds) {
            return Err(SiopError::Expired);
        }
        if self.iat > expected.now.saturating_add(expected.leeway_seconds) {
            return Err(SiopError::InvalidIdToken("iat is in the future".into()));
        }

        if self.is_did_subject() {
            if self.sub_jwk.is_some() {
                return Err(SiopError::InvalidIdToken(
                    "sub_jwk must not be present for DID subjects".into(),
                ));
            }
        } else if let Some(ref jwk) = self.sub_jwk {
            let thumbprint = affinidi_oid4vc_core::compute_jwk_thumbprint(jwk)
                .ok_or_else(|| SiopError::InvalidIdToken("cannot compute JWK Thumbprint".into()))?;
            if self.sub != thumbprint {
                return Err(SiopError::ThumbprintMismatch);
            }
        } else {
            return Err(SiopError::InvalidIdToken(
                "sub_jwk required for non-DID subjects".into(),
            ));
        }

        Ok(())
    }
}

/// Builder for constructing `SelfIssuedIdToken` instances.
pub struct IdTokenBuilder {
    aud: String,
    nonce: String,
    sub: Option<String>,
    sub_jwk: Option<Value>,
    exp_seconds: i64,
    additional_claims: serde_json::Map<String, Value>,
}

impl IdTokenBuilder {
    /// Create a new builder with required fields.
    ///
    /// * `client_id` — The RP's client identifier (becomes `aud`)
    /// * `nonce` — The nonce from the authorization request
    pub fn new(client_id: impl Into<String>, nonce: impl Into<String>) -> Self {
        Self {
            aud: client_id.into(),
            nonce: nonce.into(),
            sub: None,
            sub_jwk: None,
            exp_seconds: 300, // 5 minutes default
            additional_claims: serde_json::Map::new(),
        }
    }

    /// Set the subject as a JWK Thumbprint.
    ///
    /// Computes the thumbprint and sets both `sub` and `sub_jwk`.
    pub fn with_jwk_thumbprint(mut self, jwk: Value) -> Result<Self> {
        let thumbprint = affinidi_oid4vc_core::compute_jwk_thumbprint(&jwk).ok_or_else(|| {
            SiopError::InvalidIdToken("cannot compute JWK Thumbprint from provided key".into())
        })?;
        self.sub = Some(thumbprint);
        self.sub_jwk = Some(jwk);
        Ok(self)
    }

    /// Set the subject as a DID.
    pub fn with_did(mut self, did: impl Into<String>) -> Self {
        self.sub = Some(did.into());
        self.sub_jwk = None;
        self
    }

    /// Set the expiration time in seconds from now.
    pub fn expires_in(mut self, seconds: i64) -> Self {
        self.exp_seconds = seconds;
        self
    }

    /// Add a self-attested claim (name, email, etc.).
    pub fn claim(mut self, key: impl Into<String>, value: Value) -> Self {
        self.additional_claims.insert(key.into(), value);
        self
    }

    /// Build the ID Token's claims. Call [`SelfIssuedIdToken::sign`] to get
    /// the JWS to send.
    pub fn build(self) -> Result<SelfIssuedIdToken> {
        let sub = self.sub.ok_or_else(|| {
            SiopError::InvalidIdToken(
                "subject must be set (via with_did or with_jwk_thumbprint)".into(),
            )
        })?;

        let now = Utc::now().timestamp();

        Ok(SelfIssuedIdToken {
            iss: sub.clone(), // iss == sub
            sub,
            aud: Audience::One(self.aud),
            exp: now + self.exp_seconds,
            iat: now,
            nonce: self.nonce,
            sub_jwk: self.sub_jwk,
            auth_time: Some(now),
            acr: None,
            amr: None,
            additional_claims: self.additional_claims,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use affinidi_oid4vc_core::eddsa::EdDsaSigner;
    use affinidi_oid4vc_core::es256::Es256Signer;
    use serde_json::json;

    const ALGS: &[&str] = &["ES256", "EdDSA"];
    const DID: &str = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";

    fn expect<'a>(client_id: &'a str, nonce: &'a str) -> IdTokenExpectations<'a> {
        IdTokenExpectations::new(ALGS, client_id, nonce)
    }

    fn test_jwk() -> Value {
        json!({
            "kty": "EC",
            "crv": "P-256",
            "x": "TCAER19Zvu3OHF4j4W4vfSVoHIP1ILilDls7vCeGemc",
            "y": "ZxjiWWbZMQGHVWKVQ4hbSIirsVfuecCE6t4jT9F2HZQ"
        })
    }

    fn did_token(client_id: &str, nonce: &str) -> SelfIssuedIdToken {
        IdTokenBuilder::new(client_id, nonce)
            .with_did(DID)
            .build()
            .unwrap()
    }

    fn signed_thumbprint_token(signer: &dyn JwtSigner, jwk: Value) -> String {
        IdTokenBuilder::new("rp", "n")
            .with_jwk_thumbprint(jwk)
            .unwrap()
            .build()
            .unwrap()
            .sign(signer)
            .unwrap()
    }

    struct FixedKey(Value);

    impl DidKeyResolver for FixedKey {
        fn resolve(&self, kid: &str, alg: &str) -> Result<Box<dyn JwtVerifier>> {
            assert!(kid.starts_with(DID));
            verifier_for_jwk(&self.0, alg)
        }
    }

    #[test]
    fn build_jwk_thumbprint_token() {
        let token = IdTokenBuilder::new("https://rp.example.com", "nonce123")
            .with_jwk_thumbprint(test_jwk())
            .unwrap()
            .expires_in(600)
            .build()
            .unwrap();

        assert_eq!(token.iss, token.sub);
        assert!(token.aud.contains("https://rp.example.com"));
        assert_eq!(token.nonce, "nonce123");
        assert!(token.is_jwk_thumbprint_subject());
        assert!(!token.is_did_subject());
    }

    #[test]
    fn es256_thumbprint_token_signs_and_verifies() {
        let signer = Es256Signer::generate();
        let jwt = signed_thumbprint_token(&signer, signer.public_key_jwk());
        let token = verify_id_token(&jwt, &expect("rp", "n"), None).unwrap();
        assert!(token.is_jwk_thumbprint_subject());
    }

    #[test]
    fn eddsa_thumbprint_token_signs_and_verifies() {
        let signer = EdDsaSigner::generate();
        let jwt = signed_thumbprint_token(&signer, signer.public_key_jwk());
        assert!(verify_id_token(&jwt, &expect("rp", "n"), None).is_ok());
    }

    #[test]
    fn token_signed_by_another_key_than_sub_jwk_is_rejected() {
        let holder = Es256Signer::generate();
        let other = Es256Signer::generate();
        let jwt = signed_thumbprint_token(&other, holder.public_key_jwk());
        assert!(matches!(
            verify_id_token(&jwt, &expect("rp", "n"), None),
            Err(SiopError::SignatureInvalid(_))
        ));
    }

    #[test]
    fn claims_without_a_valid_signature_are_rejected() {
        let signer = Es256Signer::generate();
        let jwt = signed_thumbprint_token(&signer, signer.public_key_jwk());
        let mut parts: Vec<&str> = jwt.split('.').collect();
        let unsigned = format!("{}.{}.", parts[0], parts[1]);
        assert!(verify_id_token(&unsigned, &expect("rp", "n"), None).is_err());

        let none_header = URL_SAFE_NO_PAD.encode(br#"{"alg":"none"}"#);
        parts[0] = &none_header;
        assert!(verify_id_token(&parts.join("."), &expect("rp", "n"), None).is_err());
    }

    #[test]
    fn disallowed_alg_is_rejected() {
        let signer = EdDsaSigner::generate();
        let jwt = signed_thumbprint_token(&signer, signer.public_key_jwk());
        let only_es256 = IdTokenExpectations::new(&["ES256"], "rp", "n");
        assert!(verify_id_token(&jwt, &only_es256, None).is_err());
    }

    #[test]
    fn alg_must_match_the_sub_jwk_key_type() {
        let signer = EdDsaSigner::generate();
        let jwt = signed_thumbprint_token(&signer, test_jwk());
        assert!(verify_id_token(&jwt, &expect("rp", "n"), None).is_err());
    }

    #[test]
    fn did_token_verifies_with_resolved_key() {
        let signer = EdDsaSigner::generate().with_kid(format!("{DID}#key-1"));
        let jwt = did_token("rp", "n").sign(&signer).unwrap();
        let resolver = FixedKey(signer.public_key_jwk());
        assert!(verify_id_token(&jwt, &expect("rp", "n"), Some(&resolver)).is_ok());
    }

    #[test]
    fn did_token_without_resolver_is_rejected() {
        let signer = EdDsaSigner::generate().with_kid(format!("{DID}#key-1"));
        let jwt = did_token("rp", "n").sign(&signer).unwrap();
        assert!(verify_id_token(&jwt, &expect("rp", "n"), None).is_err());
    }

    #[test]
    fn did_token_signer_needs_kid_under_the_did() {
        let token = did_token("rp", "n");
        assert!(token.sign(&EdDsaSigner::generate()).is_err());
        let foreign = EdDsaSigner::generate().with_kid("did:key:zOther#key-1");
        assert!(token.sign(&foreign).is_err());
    }

    #[test]
    fn did_token_with_wrong_resolved_key_is_rejected() {
        let signer = EdDsaSigner::generate().with_kid(format!("{DID}#key-1"));
        let jwt = did_token("rp", "n").sign(&signer).unwrap();
        let resolver = FixedKey(EdDsaSigner::generate().public_key_jwk());
        assert!(verify_id_token(&jwt, &expect("rp", "n"), Some(&resolver)).is_err());
    }

    #[test]
    fn kid_under_did_requires_a_fragment() {
        assert!(kid_is_under_did("did:key:abc#k1", "did:key:abc"));
        assert!(!kid_is_under_did("did:key:abc", "did:key:abc"));
        assert!(!kid_is_under_did("did:key:abcd#k1", "did:key:abc"));
        assert!(!kid_is_under_did("did:key:abc#", "did:key:abc"));
    }

    #[test]
    fn validate_claims_iss_sub_mismatch_fails() {
        let mut token = did_token("rp", "n");
        token.iss = "different".into();
        assert!(matches!(
            token.validate_claims(&expect("rp", "n")),
            Err(SiopError::IssSubMismatch)
        ));
    }

    #[test]
    fn validate_claims_wrong_audience_fails() {
        assert!(matches!(
            did_token("correct-rp", "n").validate_claims(&expect("wrong-rp", "n")),
            Err(SiopError::AudienceMismatch { .. })
        ));
    }

    #[test]
    fn array_audience_is_accepted() {
        let mut claims = serde_json::to_value(did_token("rp", "n")).unwrap();
        claims["aud"] = json!(["other", "rp"]);
        let token: SelfIssuedIdToken = serde_json::from_value(claims).unwrap();
        assert!(token.validate_claims(&expect("rp", "n")).is_ok());
    }

    #[test]
    fn validate_claims_wrong_nonce_fails() {
        assert!(matches!(
            did_token("rp", "correct").validate_claims(&expect("rp", "wrong")),
            Err(SiopError::NonceMismatch)
        ));
    }

    #[test]
    fn validate_claims_expiry_and_iat_use_given_time_and_leeway() {
        let token = did_token("rp", "n");
        let mut at = expect("rp", "n");
        at.leeway_seconds = 30;

        at.now = token.exp + 20;
        assert!(token.validate_claims(&at).is_ok());
        at.now = token.exp + 31;
        assert!(matches!(
            token.validate_claims(&at),
            Err(SiopError::Expired)
        ));

        at.now = token.iat - 31;
        assert!(token.validate_claims(&at).is_err());
    }

    #[test]
    fn validate_claims_did_with_sub_jwk_fails() {
        let mut token = did_token("rp", "n");
        token.sub_jwk = Some(test_jwk());
        assert!(token.validate_claims(&expect("rp", "n")).is_err());
    }

    #[test]
    fn token_serialization_roundtrip() {
        let token = IdTokenBuilder::new("rp", "n")
            .with_did("did:key:abc")
            .claim("name", json!("Alice"))
            .build()
            .unwrap();

        let json = serde_json::to_string(&token).unwrap();
        let parsed: SelfIssuedIdToken = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.sub, token.sub);
        assert_eq!(parsed.aud, Audience::One("rp".into()));
        assert_eq!(parsed.additional_claims["name"], "Alice");
    }

    #[test]
    fn build_without_subject_fails() {
        assert!(IdTokenBuilder::new("rp", "n").build().is_err());
    }

    fn sign_claims(claims: &Value, header: &Value, signer: &dyn JwtSigner) -> String {
        encode_compact_jws(header, claims, signer).unwrap()
    }

    #[test]
    fn signed_token_whose_sub_is_not_the_sub_jwk_thumbprint_is_rejected() {
        let signer = Es256Signer::generate();
        let mut claims = serde_json::to_value(
            IdTokenBuilder::new("rp", "n")
                .with_jwk_thumbprint(signer.public_key_jwk())
                .unwrap()
                .build()
                .unwrap(),
        )
        .unwrap();
        let other_thumbprint = affinidi_oid4vc_core::compute_jwk_thumbprint(&test_jwk()).unwrap();
        claims["sub"] = json!(other_thumbprint);
        claims["iss"] = json!(other_thumbprint);
        let jwt = sign_claims(&claims, &json!({ "alg": "ES256" }), &signer);
        assert!(matches!(
            verify_id_token(&jwt, &expect("rp", "n"), None),
            Err(SiopError::ThumbprintMismatch)
        ));
    }

    #[test]
    fn kid_naming_another_did_is_rejected() {
        let signer = EdDsaSigner::generate();
        let claims = serde_json::to_value(did_token("rp", "n")).unwrap();
        let header = json!({ "alg": "EdDSA", "kid": "did:key:zOther#key-1" });
        let jwt = sign_claims(&claims, &header, &signer);
        let resolver = FixedKey(signer.public_key_jwk());
        assert!(matches!(
            verify_id_token(&jwt, &expect("rp", "n"), Some(&resolver)),
            Err(SiopError::InvalidIdToken(_))
        ));
    }

    #[test]
    fn es256_sub_jwk_coordinates_must_be_32_bytes() {
        let signer = Es256Signer::generate();
        let jwk = signer.public_key_jwk();
        let x = URL_SAFE_NO_PAD.decode(jwk["x"].as_str().unwrap()).unwrap();
        let y = URL_SAFE_NO_PAD.decode(jwk["y"].as_str().unwrap()).unwrap();
        let mut long_x = x.clone();
        long_x.push(y[0]);
        let shifted = json!({
            "kty": "EC",
            "crv": "P-256",
            "x": URL_SAFE_NO_PAD.encode(&long_x),
            "y": URL_SAFE_NO_PAD.encode(&y[1..]),
        });
        assert_ne!(
            affinidi_oid4vc_core::compute_jwk_thumbprint(&shifted),
            affinidi_oid4vc_core::compute_jwk_thumbprint(&jwk)
        );

        let jwt = signed_thumbprint_token(&signer, shifted);
        assert!(matches!(
            verify_id_token(&jwt, &expect("rp", "n"), None),
            Err(SiopError::InvalidIdToken(_))
        ));
    }
}

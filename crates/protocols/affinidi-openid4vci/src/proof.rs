/*!
 * OpenID4VCI key-binding proof (proof-of-possession).
 *
 * The credential endpoint requires the wallet to prove control of the key the
 * issued credential will be bound to (OpenID4VCI §8.2.1, `proof_type: "jwt"`,
 * `typ: "openid4vci-proof+jwt"`). This module is the build + verify pair for
 * that proof — the piece every issuer/wallet otherwise hand-rolls, and the
 * security-critical one.
 *
 * It is deliberately **crypto-agnostic**: signing and signature verification go
 * through the [`JwtSigner`] / [`JwtVerifier`] traits from `affinidi-oid4vc-core`
 * (use [`affinidi_oid4vc_core::eddsa`] / [`affinidi_oid4vc_core::es256`], or
 * your own impl). **DID resolution stays with the caller** — [`KeyProof::parse`]
 * surfaces the claimed key identifier (`kid` / `jwk`) so the consumer resolves
 * it to a verifying key with their own DID stack, then calls
 * [`KeyProof::verify`].
 *
 * ```no_run
 * # use affinidi_openid4vci::proof::{KeyProof, ProofPolicy};
 * # use affinidi_oid4vc_core::jwt::JwtVerifier;
 * # fn resolve(_kid: Option<&str>) -> Box<dyn JwtVerifier> { unimplemented!() }
 * # fn demo(jwt: &str, issuer_id: &str, c_nonce: &str, now: i64) -> Result<(), Box<dyn std::error::Error>> {
 * let proof = KeyProof::parse(jwt)?;                 // structural decode, no crypto
 * let verifier = resolve(proof.kid());               // caller resolves kid -> key
 * let claims = proof.verify(&*verifier, &ProofPolicy {
 *     audience: issuer_id,
 *     nonce: Some(c_nonce),                          // bind to the issued c_nonce
 *     now,
 *     max_age_secs: 300,
 * })?;                                               // sig + aud + nonce + freshness
 * // `proof.kid()` is now a cryptographically-proven holder identifier.
 * # let _ = claims; Ok(())
 * # }
 * ```
 */

use affinidi_oid4vc_core::jwt::{
    self, Audience, JwtError, JwtSigner, JwtVerifier, decode_compact_jws_unverified,
};
use serde_json::Value;

use crate::error::{Oid4vciError, Result};

/// The required `typ` header value of an OpenID4VCI key-binding proof JWT
/// (OpenID4VCI §8.2.1.1).
pub const KEY_PROOF_TYP: &str = "openid4vci-proof+jwt";

/// Default tolerance, in seconds, for a proof `iat` slightly ahead of the
/// verifier's clock (wallet clock drift).
pub const IAT_FUTURE_LEEWAY_SECS: i64 = 60;

/// The claims carried by a key-binding proof JWT (OpenID4VCI §8.2.1.1).
#[derive(Debug, Clone)]
pub struct KeyProofClaims {
    /// `iss` — the client identifier. OPTIONAL, and omitted in the
    /// pre-authorized-code flow.
    pub iss: Option<String>,
    /// `aud` — the Credential Issuer Identifier. REQUIRED.
    pub aud: Audience,
    /// `iat` — when the proof was created (seconds since the Unix epoch).
    pub iat: i64,
    /// `nonce` — the issuer-supplied `c_nonce` the proof commits to, binding it
    /// to one issuance. Present whenever the issuer provided a nonce.
    pub nonce: Option<String>,
}

/// A parsed, **not-yet-cryptographically-verified** key-binding proof.
///
/// [`KeyProof::parse`] does the structural work (decode, `typ`/`alg` checks,
/// surface the claimed key id + typed claims) but performs **no** signature or
/// freshness check — call [`KeyProof::verify`] (or
/// [`verify_signature`](Self::verify_signature) + [`verify_claims`](Self::verify_claims))
/// with a verifier resolved from [`kid`](Self::kid) / [`jwk`](Self::jwk).
#[derive(Debug, Clone)]
pub struct KeyProof {
    jwt: String,
    alg: String,
    kid: Option<String>,
    jwk: Option<Value>,
    claims: KeyProofClaims,
}

impl KeyProof {
    /// Parse and structurally validate a key-binding proof JWT.
    ///
    /// Checks the compact-JWS shape, that `typ` is [`KEY_PROOF_TYP`], that `alg`
    /// is present and not `none`, that the header identifies the key (`kid` or
    /// `jwk`), and that the required claims (`aud`, `iat`) are present and typed.
    /// Does **not** verify the signature — see [`verify`](Self::verify).
    pub fn parse(jwt: &str) -> Result<Self> {
        let (header, payload) = decode_compact_jws_unverified(jwt).map_err(jwt_err)?;

        match header.get("typ").and_then(Value::as_str) {
            Some(t) if t == KEY_PROOF_TYP => {}
            other => {
                return Err(Oid4vciError::InvalidProof(format!(
                    "proof `typ` must be `{KEY_PROOF_TYP}` (got {other:?})"
                )));
            }
        }

        let alg = header
            .get("alg")
            .and_then(Value::as_str)
            .filter(|a| !a.eq_ignore_ascii_case("none"))
            .ok_or_else(|| {
                Oid4vciError::InvalidProof("proof header missing `alg` (or `alg=none`)".into())
            })?
            .to_string();

        let kid = header
            .get("kid")
            .and_then(Value::as_str)
            .map(str::to_string);
        let jwk = header.get("jwk").filter(|v| v.is_object()).cloned();
        if kid.is_none() && jwk.is_none() {
            return Err(Oid4vciError::InvalidProof(
                "proof header must identify the holder key via `kid` or `jwk`".into(),
            ));
        }

        let aud_value = payload
            .get("aud")
            .cloned()
            .ok_or_else(|| Oid4vciError::InvalidProof("proof missing `aud`".into()))?;
        let aud: Audience = serde_json::from_value(aud_value)
            .map_err(|e| Oid4vciError::InvalidProof(format!("invalid `aud`: {e}")))?;
        let iat = payload
            .get("iat")
            .and_then(Value::as_i64)
            .ok_or_else(|| Oid4vciError::InvalidProof("proof missing numeric `iat`".into()))?;
        let iss = payload
            .get("iss")
            .and_then(Value::as_str)
            .map(str::to_string);
        let nonce = payload
            .get("nonce")
            .and_then(Value::as_str)
            .map(str::to_string);

        Ok(Self {
            jwt: jwt.to_string(),
            alg,
            kid,
            jwk,
            claims: KeyProofClaims {
                iss,
                aud,
                iat,
                nonce,
            },
        })
    }

    /// The JWS `alg` of the proof (e.g. `EdDSA`, `ES256`).
    pub fn algorithm(&self) -> &str {
        &self.alg
    }

    /// The `kid` header — the holder's key identifier (typically a DID URL).
    /// The caller resolves this to a verifying key.
    pub fn kid(&self) -> Option<&str> {
        self.kid.as_deref()
    }

    /// The inline `jwk` header, if the proof identifies its key that way.
    ///
    /// **Security:** a `jwk`-identified proof only proves possession of *some*
    /// key — the one in the header. It does **not** establish that the key is
    /// the holder's. An issuer MUST independently bind this `jwk` to the
    /// credential's intended subject (e.g. require it to match the subject's
    /// DID / `kid`) before trusting it; otherwise an attacker proves possession
    /// of a key they just minted. Prefer [`kid`](Self::kid) resolution.
    pub fn jwk(&self) -> Option<&Value> {
        self.jwk.as_ref()
    }

    /// The parsed claims (audience, issued-at, nonce, …).
    pub fn claims(&self) -> &KeyProofClaims {
        &self.claims
    }

    /// Verify the proof's signature with a caller-resolved verifier.
    ///
    /// **Caller contract (load-bearing):** the `verifier` MUST wrap the key
    /// named by this proof's own [`kid`](Self::kid) / [`jwk`](Self::jwk) —
    /// resolve that identifier (e.g. DID → key) and confirm the resolved key's
    /// algorithm matches [`algorithm`](Self::algorithm). Resolving a verifier
    /// from anywhere else, or picking one by `alg` rather than by key, defeats
    /// the proof: this crate is crypto-agnostic by design and cannot police the
    /// key↔proof binding for you. (`alg=none` and empty signatures are still
    /// rejected here regardless.)
    pub fn verify_signature(&self, verifier: &dyn JwtVerifier) -> Result<()> {
        jwt::decode_compact_jws_verified(&self.jwt, verifier)
            .map(|_| ())
            .map_err(jwt_err)
    }

    /// Verify the bound claims against `policy`: `aud` names the expected
    /// issuer, the `c_nonce` (if the issuer issued one) matches, and `iat` is
    /// fresh (within `max_age_secs` in the past and [`IAT_FUTURE_LEEWAY_SECS`]
    /// in the future).
    pub fn verify_claims(&self, policy: &ProofPolicy<'_>) -> Result<()> {
        if !self.claims.aud.contains(policy.audience) {
            return Err(Oid4vciError::InvalidProof(format!(
                "proof `aud` does not name this issuer ({})",
                policy.audience
            )));
        }
        // Nonce binding (OpenID4VCI §8.2.1.1): when the issuer issued a
        // `c_nonce`, the proof must echo exactly it — this is what stops a
        // captured proof being replayed within the freshness window. When the
        // issuer issued no nonce, there is nothing to bind.
        if let Some(expected) = policy.nonce
            && self.claims.nonce.as_deref() != Some(expected)
        {
            return Err(Oid4vciError::InvalidProof(
                "proof `nonce` does not match the issued c_nonce".into(),
            ));
        }
        if self.claims.iat > policy.now + IAT_FUTURE_LEEWAY_SECS {
            return Err(Oid4vciError::InvalidProof(
                "proof `iat` is in the future".into(),
            ));
        }
        if policy.now - self.claims.iat > policy.max_age_secs {
            return Err(Oid4vciError::InvalidProof(format!(
                "proof is stale (older than {}s)",
                policy.max_age_secs
            )));
        }
        Ok(())
    }

    /// Verify the signature **and** the bound claims, returning the proven
    /// claims. The convenience composition of [`verify_signature`](Self::verify_signature)
    /// then [`verify_claims`](Self::verify_claims) — see those for the caller
    /// contract and the checks performed.
    pub fn verify(
        &self,
        verifier: &dyn JwtVerifier,
        policy: &ProofPolicy<'_>,
    ) -> Result<&KeyProofClaims> {
        self.verify_signature(verifier)?;
        self.verify_claims(policy)?;
        Ok(&self.claims)
    }
}

/// What a verifier requires of a key-binding proof's claims.
///
/// A named-field struct (rather than positional args) on purpose: this is a
/// security-sensitive call, and `nonce` in particular is easy to forget — here
/// you must state it explicitly (`None` = the issuer issued no `c_nonce`).
#[derive(Debug, Clone)]
pub struct ProofPolicy<'a> {
    /// The Credential Issuer Identifier the proof's `aud` must name.
    pub audience: &'a str,
    /// The `c_nonce` the issuer issued for this request, if any. `Some` →
    /// the proof's `nonce` must equal it; `None` → no nonce binding required.
    pub nonce: Option<&'a str>,
    /// Current time, in seconds since the Unix epoch.
    pub now: i64,
    /// Maximum accepted proof age in seconds (`now - iat`).
    pub max_age_secs: i64,
}

/// Build a key-binding proof JWT (wallet side).
///
/// Assembles the `openid4vci-proof+jwt` header (`typ` + the signer's `alg` and
/// `kid`) and the claims (`aud`, `iat`, optional `nonce` / `iss`), then signs
/// with `signer`. The signer **must** expose a [`key_id`](JwtSigner::key_id)
/// (the holder's DID URL) — an OpenID4VCI proof must identify its key; build a
/// `jwk`-identified proof with [`encode_compact_jws`](jwt::encode_compact_jws)
/// directly if you need that form.
pub fn build_key_proof_jwt(
    signer: &dyn JwtSigner,
    audience: &str,
    nonce: Option<&str>,
    iat: i64,
) -> Result<String> {
    let kid = signer.key_id().ok_or_else(|| {
        Oid4vciError::InvalidProof(
            "signer has no key_id; a key-binding proof must identify the holder key (kid)".into(),
        )
    })?;
    let header = serde_json::json!({
        "typ": KEY_PROOF_TYP,
        "alg": signer.algorithm(),
        "kid": kid,
    });
    let mut payload = serde_json::json!({ "aud": audience, "iat": iat });
    if let Some(n) = nonce {
        payload["nonce"] = Value::String(n.to_string());
    }
    jwt::encode_compact_jws(&header, &payload, signer).map_err(jwt_err)
}

/// Map a JWT-layer error onto the crate's `InvalidProof`.
fn jwt_err(e: JwtError) -> Oid4vciError {
    Oid4vciError::InvalidProof(e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use affinidi_oid4vc_core::eddsa::{EdDsaSigner, EdDsaVerifier};

    const ISSUER: &str = "https://issuer.example";
    const NOW: i64 = 1_700_000_000;

    fn signer(seed: u8, kid: &str) -> EdDsaSigner {
        EdDsaSigner::from_bytes(&[seed; 32]).unwrap().with_kid(kid)
    }

    /// A policy with no nonce requirement, anchored at `now`.
    fn policy(audience: &str, now: i64) -> ProofPolicy<'_> {
        ProofPolicy {
            audience,
            nonce: None,
            now,
            max_age_secs: 300,
        }
    }

    #[test]
    fn build_then_verify_roundtrip() {
        let s = signer(7, "did:key:zHolder#0");
        let v = EdDsaVerifier::from_bytes(&s.public_key_bytes()).unwrap();

        let jwt = build_key_proof_jwt(&s, ISSUER, Some("c-nonce-1"), NOW).unwrap();
        let proof = KeyProof::parse(&jwt).unwrap();

        assert_eq!(proof.algorithm(), "EdDSA");
        assert_eq!(proof.kid(), Some("did:key:zHolder#0"));
        assert_eq!(proof.claims().nonce.as_deref(), Some("c-nonce-1"));

        let claims = proof
            .verify(
                &v,
                &ProofPolicy {
                    audience: ISSUER,
                    nonce: Some("c-nonce-1"),
                    now: NOW + 5,
                    max_age_secs: 300,
                },
            )
            .unwrap();
        assert!(claims.aud.contains(ISSUER));
    }

    #[test]
    fn verify_rejects_wrong_audience() {
        let s = signer(8, "did:key:zH#0");
        let v = EdDsaVerifier::from_bytes(&s.public_key_bytes()).unwrap();
        let jwt = build_key_proof_jwt(&s, ISSUER, None, NOW).unwrap();
        let proof = KeyProof::parse(&jwt).unwrap();
        let err = proof
            .verify(&v, &policy("https://other.example", NOW))
            .unwrap_err();
        assert!(
            matches!(&err, Oid4vciError::InvalidProof(m) if m.contains("aud")),
            "{err:?}"
        );
    }

    #[test]
    fn verify_rejects_mismatched_or_missing_nonce() {
        let s = signer(20, "did:key:zH#0");
        // Issuer expects "n-issued"; proof carries the wrong nonce.
        let jwt = build_key_proof_jwt(&s, ISSUER, Some("n-wrong"), NOW).unwrap();
        let proof = KeyProof::parse(&jwt).unwrap();
        let pol = ProofPolicy {
            audience: ISSUER,
            nonce: Some("n-issued"),
            now: NOW,
            max_age_secs: 300,
        };
        let err = proof.verify_claims(&pol).unwrap_err();
        assert!(
            matches!(&err, Oid4vciError::InvalidProof(m) if m.contains("nonce")),
            "{err:?}"
        );

        // A proof with no nonce at all is also rejected when one was issued.
        let no_nonce =
            KeyProof::parse(&build_key_proof_jwt(&s, ISSUER, None, NOW).unwrap()).unwrap();
        assert!(no_nonce.verify_claims(&pol).is_err());

        // Matching nonce passes.
        let ok = KeyProof::parse(&build_key_proof_jwt(&s, ISSUER, Some("n-issued"), NOW).unwrap())
            .unwrap();
        assert!(ok.verify_claims(&pol).is_ok());
    }

    #[test]
    fn verify_rejects_stale_and_future() {
        let s = signer(9, "did:key:zH#0");
        let jwt = build_key_proof_jwt(&s, ISSUER, None, NOW).unwrap();
        let proof = KeyProof::parse(&jwt).unwrap();
        // Stale: now is far past iat.
        assert!(proof.verify_claims(&policy(ISSUER, NOW + 10_000)).is_err());
        // Future: iat well ahead of now.
        assert!(proof.verify_claims(&policy(ISSUER, NOW - 10_000)).is_err());
        // Fresh.
        assert!(proof.verify_claims(&policy(ISSUER, NOW + 10)).is_ok());
    }

    #[test]
    fn verify_rejects_wrong_key() {
        let s = signer(10, "did:key:zH#0");
        let other = signer(11, "did:key:zH#0");
        let v = EdDsaVerifier::from_bytes(&other.public_key_bytes()).unwrap();
        let jwt = build_key_proof_jwt(&s, ISSUER, None, NOW).unwrap();
        let proof = KeyProof::parse(&jwt).unwrap();
        assert!(proof.verify_signature(&v).is_err());
    }

    #[test]
    fn parse_rejects_wrong_typ() {
        // A plain JWT (typ=JWT), not an openid4vci proof.
        let s = signer(12, "did:key:zH#0");
        let header = serde_json::json!({ "typ": "JWT", "alg": "EdDSA", "kid": "did:key:zH#0" });
        let payload = serde_json::json!({ "aud": ISSUER, "iat": NOW });
        let jwt = jwt::encode_compact_jws(&header, &payload, &s).unwrap();
        let err = KeyProof::parse(&jwt).unwrap_err();
        assert!(
            matches!(&err, Oid4vciError::InvalidProof(m) if m.contains("typ")),
            "{err:?}"
        );
    }

    #[test]
    fn parse_rejects_missing_key_id() {
        let s = signer(13, "ignored");
        // No kid, no jwk in the header.
        let header = serde_json::json!({ "typ": KEY_PROOF_TYP, "alg": "EdDSA" });
        let payload = serde_json::json!({ "aud": ISSUER, "iat": NOW });
        let jwt = jwt::encode_compact_jws(&header, &payload, &s).unwrap();
        let err = KeyProof::parse(&jwt).unwrap_err();
        assert!(
            matches!(&err, Oid4vciError::InvalidProof(m) if m.contains("kid")),
            "{err:?}"
        );
    }

    #[test]
    fn parse_accepts_array_audience() {
        let s = signer(14, "did:key:zH#0");
        let header =
            serde_json::json!({ "typ": KEY_PROOF_TYP, "alg": "EdDSA", "kid": "did:key:zH#0" });
        let payload = serde_json::json!({ "aud": [ISSUER, "https://b.example"], "iat": NOW });
        let jwt = jwt::encode_compact_jws(&header, &payload, &s).unwrap();
        let proof = KeyProof::parse(&jwt).unwrap();
        assert!(proof.claims().aud.contains(ISSUER));
        assert!(proof.claims().aud.contains("https://b.example"));
    }

    #[test]
    fn build_requires_a_key_id() {
        // A signer with no kid cannot build a proof.
        let s = EdDsaSigner::from_bytes(&[15u8; 32]).unwrap();
        assert!(build_key_proof_jwt(&s, ISSUER, None, NOW).is_err());
    }
}

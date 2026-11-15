/*!
 * Bridge from this crate's raw-bytes [`JwtSigner`] / [`JwtVerifier`] to the
 * compact-JWS traits of [`affinidi_sd_jwt`] (`sd-jwt` feature).
 *
 * The two crates have traits with the same names and different shapes:
 *
 * | | this crate (`jwt`) | `affinidi_sd_jwt::signer` |
 * |---|---|---|
 * | sign | `sign(signing_input) -> signature bytes` | `sign_jwt(header, payload) -> compact JWS` |
 * | verify | `verify(signing_input, signature)` | `verify_jwt(compact JWS) -> payload` |
 *
 * The raw-bytes pair is the one to implement: key handling stays in the
 * implementation, while compact-JWS parsing, `alg=none` refusal and the
 * algorithm allowlist stay in one audited place
 * ([`decode_compact_jws_verified_with_algs`]). The adapters here let any
 * raw-bytes implementation — [`Es256Verifier`](crate::es256::Es256Verifier),
 * [`EdDsaVerifier`](crate::eddsa::EdDsaVerifier), or a KMS-backed one — plug
 * straight into `affinidi_sd_jwt::verifier::verify` and the SD-JWT issuer and
 * holder:
 *
 * - [`AllowlistVerifier`] implements [`affinidi_sd_jwt::JwtVerifier`] over a
 *   raw verifier plus the algorithms the caller accepts.
 * - [`SdJwtSigner`] implements [`affinidi_sd_jwt::JwtSigner`] over a raw
 *   signer.
 * - [`holder_key_verifier`] (with `es256` and/or `eddsa`) is a production
 *   [`HolderKeyVerifier`](affinidi_sd_jwt::verifier::HolderKeyVerifier) for
 *   KB-JWTs under `cnf.jwk`.
 */

use affinidi_sd_jwt::SdJwtError;
use serde_json::Value;

use crate::jwt::{
    JwtError, JwtSigner, JwtVerifier, decode_compact_jws_verified_with_algs, encode_compact_jws,
};

fn sd_jwt_error(error: JwtError) -> SdJwtError {
    match error {
        JwtError::Signing(m) => SdJwtError::Signing(m),
        JwtError::InvalidFormat(m) => SdJwtError::InvalidFormat(m),
        other => SdJwtError::Verification(other.to_string()),
    }
}

/// An [`affinidi_sd_jwt::JwtVerifier`] over a raw-bytes [`JwtVerifier`] that
/// accepts only the listed JWS algorithms.
///
/// `verify_jwt` parses the compact JWS, refuses `alg=none`, a missing `alg`
/// and any `alg` outside the allowlist **before** the signature is checked,
/// then verifies the signature with the inner verifier and returns the payload
/// (see [`decode_compact_jws_verified_with_algs`]). An empty allowlist accepts
/// nothing.
///
/// ```ignore
/// let verifier = AllowlistVerifier::new(Es256Verifier::from_jwk(&issuer_jwk)?, &["ES256"]);
/// let result = affinidi_sd_jwt::verifier::verify(&sd_jwt, &verifier, &hasher, &options)?;
/// ```
pub struct AllowlistVerifier<V> {
    inner: V,
    allowed_algs: Vec<String>,
}

impl<V: JwtVerifier> AllowlistVerifier<V> {
    /// Wrap `inner`, accepting only `allowed_algs` (exact JWA names, e.g.
    /// `"ES256"`, `"EdDSA"`).
    pub fn new(inner: V, allowed_algs: &[&str]) -> Self {
        Self {
            inner,
            allowed_algs: allowed_algs.iter().map(|alg| (*alg).to_string()).collect(),
        }
    }

    /// The accepted algorithms.
    pub fn allowed_algs(&self) -> &[String] {
        &self.allowed_algs
    }

    /// The wrapped raw-bytes verifier.
    pub fn inner(&self) -> &V {
        &self.inner
    }

    /// Verify a compact JWS, returning its header and payload.
    pub fn verify_compact(&self, jws: &str) -> Result<(Value, Value), JwtError> {
        let allowed: Vec<&str> = self.allowed_algs.iter().map(String::as_str).collect();
        decode_compact_jws_verified_with_algs(jws, &self.inner, &allowed)
    }
}

impl<V: JwtVerifier> affinidi_sd_jwt::JwtVerifier for AllowlistVerifier<V> {
    fn verify_jwt(&self, jws: &str) -> Result<Value, SdJwtError> {
        self.verify_compact(jws)
            .map(|(_, payload)| payload)
            .map_err(sd_jwt_error)
    }
}

/// An [`affinidi_sd_jwt::JwtSigner`] over a raw-bytes [`JwtSigner`].
///
/// `algorithm` and `key_id` come from the inner signer; `sign_jwt` builds the
/// compact JWS with [`encode_compact_jws`].
pub struct SdJwtSigner<S>(pub S);

impl<S: JwtSigner> affinidi_sd_jwt::JwtSigner for SdJwtSigner<S> {
    fn algorithm(&self) -> &str {
        self.0.algorithm()
    }

    fn key_id(&self) -> Option<&str> {
        self.0.key_id()
    }

    fn sign_jwt(&self, header: &Value, payload: &Value) -> Result<String, SdJwtError> {
        encode_compact_jws(header, payload, &self.0).map_err(sd_jwt_error)
    }
}

/// A production [`HolderKeyVerifier`](affinidi_sd_jwt::verifier::HolderKeyVerifier)
/// for KB-JWTs: picks the verifier from the holder's `cnf.jwk`.
///
/// - `kty: EC`, `crv: P-256` → ES256 (needs the `es256` feature)
/// - `kty: OKP`, `crv: Ed25519` → EdDSA (needs the `eddsa` feature)
///
/// Each key accepts exactly its own algorithm, so a KB-JWT cannot pick a
/// different `alg` than its key implies. Any other key type is refused.
///
/// Pass it as `&holder_key_verifier` where a `HolderKeyVerifier` is expected.
#[cfg(any(feature = "es256", feature = "eddsa"))]
pub fn holder_key_verifier(
    jwk: &Value,
) -> Result<Box<dyn affinidi_sd_jwt::JwtVerifier>, SdJwtError> {
    let kty = jwk.get("kty").and_then(Value::as_str);
    let crv = jwk.get("crv").and_then(Value::as_str);
    match (kty, crv) {
        #[cfg(feature = "es256")]
        (Some("EC"), Some("P-256")) => {
            let inner = crate::es256::Es256Verifier::from_jwk(jwk).map_err(sd_jwt_error)?;
            Ok(Box::new(AllowlistVerifier::new(inner, &["ES256"])))
        }
        #[cfg(feature = "eddsa")]
        (Some("OKP"), Some("Ed25519")) => {
            let inner = crate::eddsa::EdDsaVerifier::from_jwk(jwk).map_err(sd_jwt_error)?;
            Ok(Box::new(AllowlistVerifier::new(inner, &["EdDSA"])))
        }
        _ => Err(SdJwtError::KeyBinding(format!(
            "unsupported holder key (kty {kty:?}, crv {crv:?})"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jwt::test_utils::{HmacTestSigner, HmacTestVerifier};
    use affinidi_sd_jwt::JwtVerifier as _;
    use serde_json::json;

    #[test]
    fn allowlist_verifier_round_trips_through_the_sd_jwt_traits() {
        use affinidi_sd_jwt::JwtSigner as _;
        let signer = SdJwtSigner(HmacTestSigner::new(b"bridge-key-0123456789abcdef!!!!"));
        let jws = signer
            .sign_jwt(&json!({"alg": signer.algorithm()}), &json!({"sub": "x"}))
            .unwrap();

        let verifier = AllowlistVerifier::new(
            HmacTestVerifier::new(b"bridge-key-0123456789abcdef!!!!"),
            &["HS256"],
        );
        assert_eq!(verifier.verify_jwt(&jws).unwrap()["sub"], "x");

        let strict = AllowlistVerifier::new(
            HmacTestVerifier::new(b"bridge-key-0123456789abcdef!!!!"),
            &["ES256"],
        );
        assert!(
            strict.verify_jwt(&jws).is_err(),
            "alg outside the allowlist"
        );

        let wrong_key = AllowlistVerifier::new(HmacTestVerifier::new(b"other"), &["HS256"]);
        assert!(wrong_key.verify_jwt(&jws).is_err());
    }

    #[cfg(feature = "es256")]
    #[test]
    fn es256_issuer_signature_verifies_an_sd_jwt() {
        use affinidi_sd_jwt::{Sha256Hasher, issuer, verifier};

        let raw_signer = crate::es256::Es256Signer::generate();
        let issuer_jwk = raw_signer.public_key_jwk();
        let signer = SdJwtSigner(raw_signer);
        let claims = json!({"iss": "https://issuer.example", "given_name": "Alice"});
        let frame = json!({"_sd": ["given_name"]});
        let sd_jwt = issuer::issue(&claims, &frame, &signer, &Sha256Hasher, None).unwrap();

        let verifier = AllowlistVerifier::new(
            crate::es256::Es256Verifier::from_jwk(&issuer_jwk).unwrap(),
            &["ES256"],
        );
        let result = verifier::verify(
            &sd_jwt,
            &verifier,
            &Sha256Hasher,
            &verifier::VerificationOptions::default(),
        )
        .unwrap();
        assert_eq!(result.claims["given_name"], "Alice");
    }

    #[cfg(all(feature = "es256", feature = "eddsa"))]
    #[test]
    fn holder_key_verifier_binds_alg_to_key_type() {
        use affinidi_sd_jwt::JwtSigner as _;
        let ed = crate::eddsa::EdDsaSigner::generate();
        let ed_jwk = ed.public_key_jwk();
        let ed = SdJwtSigner(ed);
        let jws = ed
            .sign_jwt(&json!({"alg": "EdDSA", "typ": "kb+jwt"}), &json!({"n": 1}))
            .unwrap();
        let verifier = holder_key_verifier(&ed_jwk).unwrap();
        assert_eq!(verifier.verify_jwt(&jws).unwrap()["n"], 1);

        // An EC key never accepts an EdDSA-signed token.
        let ec_jwk = crate::es256::Es256Signer::generate().public_key_jwk();
        assert!(
            holder_key_verifier(&ec_jwk)
                .unwrap()
                .verify_jwt(&jws)
                .is_err()
        );

        // Symmetric and unknown keys are refused outright.
        assert!(holder_key_verifier(&json!({"kty": "oct", "k": "AA"})).is_err());
    }
}

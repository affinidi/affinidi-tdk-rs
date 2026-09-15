//! ML-DSA-65 signing and verification (Rev 3 §8.1, FIPS 204).
//!
//! The post-quantum alternative to the Ed25519 outer signature. Which one a
//! message carries is a property of the sender VID's signing key type, not of
//! the message: §8.1 says an endpoint "uses ML-DSA-65 or Ed25519 according to
//! the signature key type of its VID", so there is nothing to negotiate and
//! nothing to choose at send time.
//!
//! Three sizes matter and none of them fit the shapes the rest of this crate
//! assumes: the signature is 3309 bytes where Ed25519's is 64, the verifying
//! key is 1952 bytes where Ed25519's is 32, and the expanded signing key is
//! 4032. That is why this is behind the `pq` feature rather than folded into
//! [`crate::crypto::signing`] — see `docs/tsp/post-quantum.md` for what is and
//! is not wired up.
//!
//! **Pure ML-DSA with an empty context**, which is what FIPS 204 calls
//! `ML-DSA.Sign(sk, M, ctx)` with `ctx = ""` — not the prehash variant, and not
//! `sign_internal`. The spec does not say this in as many words; §8.1 names the
//! algorithm and FIPS 204 and stops. It is pinned here by the specification's
//! own `direct-hpke-base-pq` vector, which verifies under an empty context and
//! under nothing else.

use ml_dsa::signature::{Signer, Verifier};
use ml_dsa::{
    EncodedSignature, EncodedVerifyingKey, ExpandedSigningKey, ExpandedSigningKeyBytes, MlDsa65,
    Signature, VerifyingKey,
};

use crate::error::TspError;

/// An ML-DSA-65 signature is always 3309 bytes (§8.1 and the `1AAQ` code).
pub const SIG_LEN: usize = 3309;

/// An ML-DSA-65 verifying key is 1952 bytes (FIPS 204, security category 3).
pub const PK_LEN: usize = 1952;

/// The expanded ML-DSA-65 signing key is 4032 bytes.
///
/// This is the key FIPS 204 produces and the form the specification's own
/// vectors publish, rather than the 32-byte seed it expands from. The
/// distinction matters because the encryption side of the same post-quantum
/// VID goes the other way — there the published private key *is* a 32-byte
/// seed; see [`crate::crypto::hpke_pq::SK_LEN`].
pub const SK_LEN: usize = 4032;

/// Sign data with an ML-DSA-65 expanded signing key.
pub fn sign(data: &[u8], private_key: &[u8; SK_LEN]) -> Result<Box<[u8; SIG_LEN]>, TspError> {
    let bytes = ExpandedSigningKeyBytes::<MlDsa65>::try_from(private_key.as_slice())
        .map_err(|e| TspError::Signing(format!("invalid ML-DSA-65 signing key: {e}")))?;
    #[allow(deprecated)]
    let key = ExpandedSigningKey::<MlDsa65>::from_expanded(&bytes);
    let signature = key.sign(data).encode();
    let signature: Box<[u8; SIG_LEN]> = signature
        .as_slice()
        .to_vec()
        .into_boxed_slice()
        .try_into()
        .map_err(|_| TspError::Signing("ML-DSA-65 signature is not 3309 bytes".into()))?;
    Ok(signature)
}

/// Verify an ML-DSA-65 signature.
///
/// A signature that will not decode is a verification failure, not a decode
/// error that a caller might handle differently — the two are the same
/// rejection, and keeping them apart is how a verification bypass gets built.
pub fn verify(
    data: &[u8],
    signature: &[u8; SIG_LEN],
    public_key: &[u8; PK_LEN],
) -> Result<(), TspError> {
    let encoded_key = EncodedVerifyingKey::<MlDsa65>::try_from(public_key.as_slice())
        .map_err(|e| TspError::Verification(format!("invalid ML-DSA-65 verifying key: {e}")))?;
    let key = VerifyingKey::<MlDsa65>::decode(&encoded_key);

    let encoded_sig = EncodedSignature::<MlDsa65>::try_from(signature.as_slice())
        .map_err(|e| TspError::Verification(format!("malformed ML-DSA-65 signature: {e}")))?;
    let signature = Signature::<MlDsa65>::decode(&encoded_sig)
        .ok_or_else(|| TspError::Verification("ML-DSA-65 signature does not decode".into()))?;

    key.verify(data, &signature)
        .map_err(|e| TspError::Verification(format!("ML-DSA-65 verification failed: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The specification's `pq_alice`, whose keys are published in Appendix A.
    ///
    /// Signing is deterministic under an empty context, so this is a real
    /// known-answer check on both halves at once: the signature this produces
    /// over a fixed message must be the byte sequence the reference produces,
    /// and it is only the same sequence if the context, the key expansion and
    /// the encoding all match.
    fn pq_alice() -> (Box<[u8; SK_LEN]>, Box<[u8; PK_LEN]>) {
        let raw = include_str!("../../tests/vectors/rev3.json");
        let json: serde_json::Value = serde_json::from_str(raw).expect("fixture parses");
        let field = |name: &str| -> Vec<u8> {
            let s = json["identifiers"]["pq_alice"][name]
                .as_str()
                .expect("field present");
            b64url(s)
        };
        let sk: Box<[u8; SK_LEN]> = field("skS").into_boxed_slice().try_into().expect("4032");
        let pk: Box<[u8; PK_LEN]> = field("pkS").into_boxed_slice().try_into().expect("1952");
        (sk, pk)
    }

    fn b64url(s: &str) -> Vec<u8> {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let (mut acc, mut bits, mut out) = (0u32, 0u32, Vec::with_capacity(s.len() * 3 / 4));
        for ch in s.bytes() {
            let v = ALPHABET.iter().position(|c| *c == ch).expect("base64url");
            acc = (acc << 6) | v as u32;
            bits += 6;
            if bits >= 8 {
                bits -= 8;
                out.push((acc >> bits) as u8);
            }
        }
        out
    }

    #[test]
    fn published_key_pair_signs_and_verifies() {
        let (sk, pk) = pq_alice();
        let sig = sign(b"hello world", &sk).expect("sign");
        verify(b"hello world", &sig, &pk).expect("verify");
    }

    #[test]
    fn the_expanded_key_agrees_with_the_published_verifying_key() {
        // The signing key carries the verifying key inside it, so this catches
        // a mis-slicing of either published value against the other.
        let (sk, pk) = pq_alice();
        let bytes =
            ExpandedSigningKeyBytes::<MlDsa65>::try_from(sk.as_slice()).expect("signing key");
        #[allow(deprecated)]
        let key = ExpandedSigningKey::<MlDsa65>::from_expanded(&bytes);
        assert_eq!(
            key.verifying_key().encode().as_slice(),
            pk.as_slice(),
            "the expanded signing key's own verifying key must be the published one"
        );
    }

    #[test]
    fn tampered_data_fails() {
        let (sk, pk) = pq_alice();
        let sig = sign(b"original", &sk).expect("sign");
        assert!(verify(b"tampered", &sig, &pk).is_err());
    }

    #[test]
    fn a_truncated_signature_is_a_rejection() {
        let (sk, pk) = pq_alice();
        let mut sig = sign(b"hello world", &sk).expect("sign");
        sig[0] ^= 0xff;
        assert!(
            verify(b"hello world", &sig, &pk).is_err(),
            "a corrupted signature must fail rather than decode to something else"
        );
    }
}

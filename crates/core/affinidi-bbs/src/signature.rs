/*!
 * BBS Sign and Verify operations.
 *
 * Per IETF draft §3.4.1 (Sign) and §3.4.2 (Verify):
 *
 * Sign(SK, PK, header, messages):
 *   1. Compute message scalars and generators
 *   2. domain = calculate_domain(PK, Q1, generators, header)
 *   3. e = hash_to_scalar(serialize(SK, domain, msg1..msgL))
 *   4. B = P1 + Q1*domain + H1*msg1 + ... + HL*msgL
 *   5. A = B * (1 / (SK + e))
 *   6. Return (A, e)
 *
 * Verify(PK, signature, header, messages):
 *   1. Recompute domain and B
 *   2. Check pairing: e(A, W + BP2*e) == e(B, BP2)
 */

use bls12_381_plus::{G1Affine, G2Affine, G2Prepared, G2Projective, multi_miller_loop};
use group::Group;

use crate::ciphersuite::Ciphersuite;
use crate::error::{BbsError, Result};
use crate::generators::{calculate_domain, create_generators, p1_generator};
use crate::hash::{hash_to_scalar, messages_to_scalars};
use crate::types::{PublicKey, SecretKey, Signature};

/// Sign a set of messages with a BBS secret key.
///
/// # Arguments
///
/// * `sk` - The signer's secret key
/// * `pk` - The corresponding public key
/// * `header` - Application-specific header bytes
/// * `messages` - The messages to sign
/// * `cs` - The ciphersuite to use
///
/// # Returns
///
/// A BBS signature (80 bytes for SHA-256 ciphersuite).
pub fn core_sign(
    sk: &SecretKey,
    pk: &PublicKey,
    header: &[u8],
    messages: &[&[u8]],
    cs: Ciphersuite,
) -> Result<Signature> {
    let l = messages.len();

    // 1. Convert messages to scalars
    let msg_scalars = messages_to_scalars(messages, cs)?;

    // 2. Create generators: Q1, H1, ..., HL (need L+1 generators)
    let generators = create_generators(l + 1, cs)?;
    let q1 = &generators[0];
    let h_generators = &generators[1..];

    // 3. Calculate domain
    let domain = calculate_domain(pk, q1, h_generators, header, cs)?;

    // 4. Compute e
    let e_dst = [cs.api_id().as_slice(), b"H2S_"].concat();
    let mut e_input = Vec::new();
    e_input.extend_from_slice(&sk.0.to_be_bytes());
    e_input.extend_from_slice(&domain.to_be_bytes());
    for scalar in &msg_scalars {
        e_input.extend_from_slice(&scalar.to_be_bytes());
    }
    let e = hash_to_scalar(&e_input, &e_dst, cs)?;

    // 5. Compute B = P1 + Q1*domain + H1*msg1 + ... + HL*msgL
    let mut b = p1_generator() + *q1 * domain;
    for (i, scalar) in msg_scalars.iter().enumerate() {
        b += h_generators[i] * scalar;
    }

    // 6. A = B * (1 / (SK + e))
    let sk_plus_e = sk.0 + e;
    let inv = sk_plus_e.invert();
    if inv.is_none().into() {
        return Err(BbsError::Crypto("SK + e has no inverse".into()));
    }
    let a = b * inv.unwrap();

    Ok(Signature { a, e })
}

/// Verify a BBS signature.
///
/// Checks the pairing equation: e(A, W + BP2*e) == e(B, BP2)
///
/// Equivalently: e(A, W + BP2*e) * e(-B, BP2) == 1_GT
pub fn core_verify(
    pk: &PublicKey,
    signature: &Signature,
    header: &[u8],
    messages: &[&[u8]],
    cs: Ciphersuite,
) -> Result<bool> {
    let l = messages.len();

    // Validate A is not identity
    if bool::from(G1Affine::from(&signature.a).is_identity()) {
        return Err(BbsError::InvalidSignature("A is identity".into()));
    }

    // 1. Convert messages to scalars
    let msg_scalars = messages_to_scalars(messages, cs)?;

    // 2. Create generators
    let generators = create_generators(l + 1, cs)?;
    let q1 = &generators[0];
    let h_generators = &generators[1..];

    // 3. Calculate domain
    let domain = calculate_domain(pk, q1, h_generators, header, cs)?;

    // 4. Compute B = P1 + Q1*domain + H1*msg1 + ... + HL*msgL
    let mut b = p1_generator() + *q1 * domain;
    for (i, scalar) in msg_scalars.iter().enumerate() {
        b += h_generators[i] * scalar;
    }

    // 5. Pairing check: e(A, W + BP2*e) == e(B, BP2)
    let bp2 = G2Projective::generator();
    let w = pk.0;
    let w_plus_bp2_e = w + bp2 * signature.e;

    // Use multi_miller_loop for efficiency:
    // e(A, W+BP2*e) * e(-B, BP2) == 1_GT
    let a_affine = G1Affine::from(&signature.a);
    let neg_b_affine = G1Affine::from(&(-b));
    let w_plus_affine = G2Affine::from(&w_plus_bp2_e);
    let bp2_affine = G2Affine::from(&bp2);

    let result = multi_miller_loop(&[
        (&a_affine, &G2Prepared::from(w_plus_affine)),
        (&neg_b_affine, &G2Prepared::from(bp2_affine)),
    ])
    .final_exponentiation();

    Ok(bool::from(result.is_identity()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::SecretKey;
    use bls12_381_plus::Scalar;

    fn test_keypair() -> (SecretKey, PublicKey) {
        let sk_scalar = Scalar::from(12345u64);
        let sk = SecretKey(sk_scalar);
        let pk = PublicKey(G2Projective::generator() * sk_scalar);
        (sk, pk)
    }

    #[test]
    fn sign_single_message() {
        let (sk, pk) = test_keypair();
        let messages: Vec<&[u8]> = vec![b"hello"];
        let sig = core_sign(&sk, &pk, b"", &messages, Ciphersuite::Bls12381Sha256).unwrap();

        // Signature should be non-trivial
        assert!(!bool::from(G1Affine::from(&sig.a).is_identity()));
        assert_ne!(sig.e, Scalar::ZERO);
    }

    #[test]
    fn sign_verify_single_message() {
        let (sk, pk) = test_keypair();
        let messages: Vec<&[u8]> = vec![b"hello world"];
        let sig = core_sign(
            &sk,
            &pk,
            b"test-header",
            &messages,
            Ciphersuite::Bls12381Sha256,
        )
        .unwrap();
        let valid = core_verify(
            &pk,
            &sig,
            b"test-header",
            &messages,
            Ciphersuite::Bls12381Sha256,
        )
        .unwrap();
        assert!(valid);
    }

    #[test]
    fn sign_verify_multiple_messages() {
        let (sk, pk) = test_keypair();
        let messages: Vec<&[u8]> = vec![b"msg1", b"msg2", b"msg3", b"msg4", b"msg5"];
        let sig = core_sign(&sk, &pk, b"header", &messages, Ciphersuite::Bls12381Sha256).unwrap();
        let valid =
            core_verify(&pk, &sig, b"header", &messages, Ciphersuite::Bls12381Sha256).unwrap();
        assert!(valid);
    }

    #[test]
    fn sign_verify_empty_header() {
        let (sk, pk) = test_keypair();
        let messages: Vec<&[u8]> = vec![b"msg"];
        let sig = core_sign(&sk, &pk, b"", &messages, Ciphersuite::Bls12381Sha256).unwrap();
        let valid = core_verify(&pk, &sig, b"", &messages, Ciphersuite::Bls12381Sha256).unwrap();
        assert!(valid);
    }

    #[test]
    fn verify_wrong_message_fails() {
        let (sk, pk) = test_keypair();
        let messages: Vec<&[u8]> = vec![b"correct"];
        let sig = core_sign(&sk, &pk, b"", &messages, Ciphersuite::Bls12381Sha256).unwrap();

        let wrong_messages: Vec<&[u8]> = vec![b"wrong"];
        let valid =
            core_verify(&pk, &sig, b"", &wrong_messages, Ciphersuite::Bls12381Sha256).unwrap();
        assert!(!valid);
    }

    #[test]
    fn verify_wrong_header_fails() {
        let (sk, pk) = test_keypair();
        let messages: Vec<&[u8]> = vec![b"msg"];
        let sig = core_sign(&sk, &pk, b"header1", &messages, Ciphersuite::Bls12381Sha256).unwrap();

        let valid = core_verify(
            &pk,
            &sig,
            b"header2",
            &messages,
            Ciphersuite::Bls12381Sha256,
        )
        .unwrap();
        assert!(!valid);
    }

    #[test]
    fn verify_wrong_key_fails() {
        let (sk, pk) = test_keypair();
        let messages: Vec<&[u8]> = vec![b"msg"];
        let sig = core_sign(&sk, &pk, b"", &messages, Ciphersuite::Bls12381Sha256).unwrap();

        // Different key
        let wrong_pk = PublicKey(G2Projective::generator() * Scalar::from(99999u64));
        let valid =
            core_verify(&wrong_pk, &sig, b"", &messages, Ciphersuite::Bls12381Sha256).unwrap();
        assert!(!valid);
    }

    #[test]
    fn signature_serialization_roundtrip() {
        let (sk, pk) = test_keypair();
        let messages: Vec<&[u8]> = vec![b"test"];
        let sig = core_sign(&sk, &pk, b"", &messages, Ciphersuite::Bls12381Sha256).unwrap();

        let bytes = sig.to_bytes();
        assert_eq!(bytes.len(), 80);

        let recovered = Signature::from_bytes(&bytes).unwrap();
        // Verify with recovered signature
        let valid =
            core_verify(&pk, &recovered, b"", &messages, Ciphersuite::Bls12381Sha256).unwrap();
        assert!(valid);
    }

    #[test]
    fn sign_verify_many_messages() {
        let (sk, pk) = test_keypair();
        let messages: Vec<&[u8]> = vec![
            b"msg0", b"msg1", b"msg2", b"msg3", b"msg4", b"msg5", b"msg6", b"msg7", b"msg8",
            b"msg9",
        ];
        let sig = core_sign(&sk, &pk, b"header", &messages, Ciphersuite::Bls12381Sha256).unwrap();
        let valid =
            core_verify(&pk, &sig, b"header", &messages, Ciphersuite::Bls12381Sha256).unwrap();
        assert!(valid);
    }
}

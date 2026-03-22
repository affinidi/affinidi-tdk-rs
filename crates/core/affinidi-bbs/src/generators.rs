/*!
 * BBS generator creation and domain calculation.
 *
 * Per IETF draft §4.1:
 * - `create_generators`: Deterministically derive G1 generators via hash-to-curve
 * - `calculate_domain`: Bind PK, generators, and header into a domain scalar
 *
 * Generators are hash-to-curve derived points in G1 used as bases for
 * the multi-scalar multiplication in signing and verification.
 * They MUST be independently derived (not scalar multiples of each other).
 */

use bls12_381_plus::{G1Affine, G1Projective, Scalar};
use elliptic_curve::hash2curve::{ExpandMsg, ExpandMsgXmd, Expander};
use group::Group;
use sha2::Sha256;

use crate::ciphersuite::Ciphersuite;
use crate::error::Result;
use crate::hash::hash_to_scalar;
use crate::types::PublicKey;

/// The P1 generator point — a fixed, publicly known G1 point.
pub fn p1_generator() -> G1Projective {
    G1Projective::generator()
}

/// Create `count` deterministic generators (Q1, H1, H2, ..., H_{count-1}).
///
/// Per IETF draft §4.3.4 and zkryptium's verified implementation:
/// ```text
/// seed_dst = api_id || "SIG_GENERATOR_SEED_"
/// generator_dst = api_id || "SIG_GENERATOR_DST_"
/// generator_seed = api_id || "MESSAGE_GENERATOR_SEED"
/// v = expand_message(generator_seed, seed_dst, expand_len)
/// for i in 1..count+1:
///     v = expand_message(v || I2OSP(i, 8), seed_dst, expand_len)
///     generator_i = hash_to_curve_g1(v, generator_dst)
/// ```
pub fn create_generators(count: usize, cs: Ciphersuite) -> Result<Vec<G1Projective>> {
    let api_id = cs.api_id();

    let seed_dst = [api_id.as_slice(), b"SIG_GENERATOR_SEED_"].concat();
    let generator_dst = [api_id.as_slice(), b"SIG_GENERATOR_DST_"].concat();
    let generator_seed = [api_id.as_slice(), b"MESSAGE_GENERATOR_SEED"].concat();

    let expand_len = cs.expand_len();
    let mut generators = Vec::with_capacity(count);

    // Initial seed: v = expand_message(generator_seed, seed_dst, expand_len)
    let mut v = expand_msg_xmd(&generator_seed, &seed_dst, expand_len);

    for i in 1..=count {
        // v = expand_message(v || I2OSP(i, 8), seed_dst, expand_len)
        let mut input = v.clone();
        input.extend_from_slice(&(i as u64).to_be_bytes()); // I2OSP(i, 8)
        v = expand_msg_xmd(&input, &seed_dst, expand_len);

        // generator_i = hash_to_curve_g1(v, generator_dst)
        let point = G1Projective::hash::<ExpandMsgXmd<Sha256>>(&v, &generator_dst);
        generators.push(point);
    }

    Ok(generators)
}

/// Expand message using the elliptic_curve crate's XMD implementation.
///
/// This ensures byte-exact compatibility with what `bls12_381_plus::hash`
/// uses internally for its hash-to-curve operations.
fn expand_msg_xmd(msg: &[u8], dst: &[u8], len: usize) -> Vec<u8> {
    let mut output = vec![0u8; len];
    <ExpandMsgXmd<Sha256> as ExpandMsg<'_>>::expand_message(&[msg], &[dst], len)
        .expect("expand_message should not fail")
        .fill_bytes(&mut output);
    output
}

/// Calculate the domain value that binds PK, generators, and header.
///
/// Per IETF draft §4.1.2:
/// ```text
/// domain = hash_to_scalar(
///     serialize(PK, len(generators), Q1, H1..HL, ciphersuite_id, header),
///     api_id || "H2S_"
/// )
/// ```
pub fn calculate_domain(
    pk: &PublicKey,
    q1: &G1Projective,
    generators: &[G1Projective],
    header: &[u8],
    cs: Ciphersuite,
) -> Result<Scalar> {
    let domain_dst = [cs.api_id().as_slice(), b"H2S_"].concat();

    let pk_bytes = pk.to_bytes();
    let count = (generators.len() as u64).to_be_bytes();
    let q1_bytes = point_to_bytes(q1);

    let mut data = Vec::new();
    data.extend_from_slice(&pk_bytes);
    data.extend_from_slice(&count);
    data.extend_from_slice(&q1_bytes);
    for g in generators {
        data.extend_from_slice(&point_to_bytes(g));
    }
    data.extend_from_slice(cs.id().as_bytes());
    data.extend_from_slice(&(header.len() as u64).to_be_bytes());
    data.extend_from_slice(header);

    hash_to_scalar(&data, &domain_dst, cs)
}

/// Serialize a G1 projective point to compressed bytes (48 bytes).
pub fn point_to_bytes(p: &G1Projective) -> [u8; 48] {
    G1Affine::from(p).to_compressed()
}

/// Deserialize a G1 point from compressed bytes.
pub fn point_from_bytes(bytes: &[u8; 48]) -> Option<G1Projective> {
    let affine = G1Affine::from_compressed(bytes);
    if affine.is_some().into() {
        Some(G1Projective::from(affine.unwrap()))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_generators_correct_count() {
        let gens = create_generators(5, Ciphersuite::Bls12381Sha256).unwrap();
        assert_eq!(gens.len(), 5);
    }

    #[test]
    fn generators_are_deterministic() {
        let g1 = create_generators(3, Ciphersuite::Bls12381Sha256).unwrap();
        let g2 = create_generators(3, Ciphersuite::Bls12381Sha256).unwrap();
        for (a, b) in g1.iter().zip(g2.iter()) {
            assert_eq!(point_to_bytes(a), point_to_bytes(b));
        }
    }

    #[test]
    fn generators_are_distinct() {
        let gens = create_generators(5, Ciphersuite::Bls12381Sha256).unwrap();
        for i in 0..gens.len() {
            for j in (i + 1)..gens.len() {
                assert_ne!(point_to_bytes(&gens[i]), point_to_bytes(&gens[j]));
            }
        }
    }

    #[test]
    fn generators_are_not_identity() {
        let gens = create_generators(5, Ciphersuite::Bls12381Sha256).unwrap();
        for g in &gens {
            assert!(!bool::from(G1Affine::from(g).is_identity()));
        }
    }

    #[test]
    fn point_roundtrip() {
        let p = G1Projective::generator();
        let bytes = point_to_bytes(&p);
        let recovered = point_from_bytes(&bytes).unwrap();
        assert_eq!(point_to_bytes(&recovered), bytes);
    }

    #[test]
    fn generators_match_ietf_fixtures() {
        // From DIF BBS fixture: bls12-381-sha-256/generators.json
        let expected_q1 = "a9ec65b70a7fbe40c874c9eb041c2cb0a7af36ccec1bea48fa2ba4c2eb67ef7f9ecb17ed27d38d27cdeddff44c8137be";
        let expected_h0 = "98cd5313283aaf5db1b3ba8611fe6070d19e605de4078c38df36019fbaad0bd28dd090fd24ed27f7f4d22d5ff5dea7d4";
        let expected_h1 = "a31fbe20c5c135bcaa8d9fc4e4ac665cc6db0226f35e737507e803044093f37697a9d452490a970eea6f9ad6c3dcaa3a";

        let gens = create_generators(11, Ciphersuite::Bls12381Sha256).unwrap();
        let q1_hex = hex::encode(point_to_bytes(&gens[0]));
        let h0_hex = hex::encode(point_to_bytes(&gens[1]));
        let h1_hex = hex::encode(point_to_bytes(&gens[2]));

        assert_eq!(q1_hex, expected_q1, "Q1 generator mismatch");
        assert_eq!(h0_hex, expected_h0, "H0 generator mismatch");
        assert_eq!(h1_hex, expected_h1, "H1 generator mismatch");
    }
}

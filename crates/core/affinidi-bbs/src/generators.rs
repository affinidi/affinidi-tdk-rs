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

use std::sync::LazyLock;

use bls12_381_plus::{G1Affine, G1Projective, Scalar};
use elliptic_curve::hash2curve::ExpandMsgXmd;
use sha2::Sha256;

use crate::ciphersuite::Ciphersuite;
use crate::error::{BbsError, Result};
use crate::hash::hash_to_scalar;
use crate::types::PublicKey;

/// Hard upper bound on the number of generators (≈ message count) any operation
/// will build. Generator creation is `O(count)` hash-to-curve work, and on the
/// verify path `count` is derived from the *untrusted* proof length — without a
/// cap, a multi-megabyte bogus proof forces unbounded work (a cheap DoS). No
/// legitimate credential signs anywhere near this many messages, so the bound
/// is generous for real use while rejecting abuse cheaply, before the loop.
pub const MAX_GENERATORS: usize = 1024;

/// The BBS ciphersuite constant `P1` for **BLS12-381-SHA-256**, as fixed by
/// `draft-irtf-cfrg-bbs-signatures`.
///
/// This is a specific hash-to-curve-derived point baked into the ciphersuite —
/// **not** the standard BLS12-381 G1 generator. Using the wrong P1 produces
/// signatures and proofs that no conforming implementation can verify.
const P1_SHA256_COMPRESSED: &str = "a8ce256102840821a3e94ea9025e4662b205762f9776b3a766c872b948f1fd225e7c59698588e70d11406d161b4e28c9";

static P1: LazyLock<G1Projective> = LazyLock::new(|| {
    let bytes = hex::decode(P1_SHA256_COMPRESSED).expect("valid P1 hex");
    let arr: [u8; 48] = bytes.try_into().expect("P1 is 48 bytes");
    let affine = G1Affine::from_compressed(&arr);
    assert!(
        bool::from(affine.is_some()),
        "P1 is a valid compressed G1 point"
    );
    G1Projective::from(affine.unwrap())
});

/// The BBS `P1` ciphersuite constant (BLS12-381-SHA-256).
pub fn p1_generator() -> G1Projective {
    *P1
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
    create_generators_with_api_id(count, &cs.api_id(), cs)
}

/// Create `count` deterministic generators under an explicit `api_id`.
///
/// Identical to [`create_generators`] but lets the caller namespace the
/// generators (the core suite uses [`Ciphersuite::api_id`]; blind BBS uses
/// [`Ciphersuite::blind_api_id`] and `"BLIND_" || blind_api_id` for its blind
/// generators).
pub fn create_generators_with_api_id(
    count: usize,
    api_id: &[u8],
    cs: Ciphersuite,
) -> Result<Vec<G1Projective>> {
    // Reject not-yet-implemented ciphersuites (SHAKE-256) at the generator
    // chokepoint: the hash-to-curve below is hard-wired to ExpandMsgXmd<Sha256>.
    cs.ensure_supported()?;

    // Cap the count BEFORE the O(count) hash-to-curve loop. On the verify path
    // `count` comes from the untrusted proof length, so an oversized bogus proof
    // would otherwise force unbounded generator work.
    if count > MAX_GENERATORS {
        return Err(BbsError::InvalidProof(format!(
            "generator/message count {count} exceeds maximum {MAX_GENERATORS}"
        )));
    }

    let seed_dst = [api_id, b"SIG_GENERATOR_SEED_"].concat();
    let generator_dst = [api_id, b"SIG_GENERATOR_DST_"].concat();
    let generator_seed = [api_id, b"MESSAGE_GENERATOR_SEED"].concat();

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
    // Use the shared implementation from hash module
    crate::hash::expand_msg_xmd(msg, dst, len)
        .expect("generator expand_message should not fail with valid DST")
}

/// Calculate the domain value that binds PK, generators, and header.
///
/// Per IETF draft calculate_domain:
/// ```text
/// domain = hash_to_scalar(
///     serialize(PK, len(generators), Q1, H1..HL, api_id, header),
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
    calculate_domain_with_api_id(pk, q1, generators, header, &cs.api_id(), cs)
}

/// Calculate the domain under an explicit `api_id` (see [`calculate_domain`]).
///
/// Blind BBS computes the domain over the combined message + blind generators
/// under [`Ciphersuite::blind_api_id`].
pub fn calculate_domain_with_api_id(
    pk: &PublicKey,
    q1: &G1Projective,
    generators: &[G1Projective],
    header: &[u8],
    api_id: &[u8],
    cs: Ciphersuite,
) -> Result<Scalar> {
    let domain_dst = [api_id, b"H2S_"].concat();

    let pk_bytes = pk.to_bytes();
    let count = (generators.len() as u64).to_be_bytes();
    let q1_bytes = point_to_bytes(q1);

    // Per draft-irtf-cfrg-bbs-signatures calculate_domain:
    //   dom_octs  = serialize(L, Q_1, H_1..H_L) || api_id
    //   dom_input = PK || dom_octs || I2OSP(length(header), 8) || header
    // Interop-critical: the trailing id is `api_id`
    // (ciphersuite_id || "H2G_HM2S_"), NOT the bare ciphersuite_id.
    let mut data = Vec::new();
    data.extend_from_slice(&pk_bytes);
    data.extend_from_slice(&count);
    data.extend_from_slice(&q1_bytes);
    for g in generators {
        data.extend_from_slice(&point_to_bytes(g));
    }
    data.extend_from_slice(api_id);
    data.extend_from_slice(&(header.len() as u64).to_be_bytes());
    data.extend_from_slice(header);

    hash_to_scalar(&data, &domain_dst, cs)
}

/// Serialize a G1 projective point to compressed bytes (48 bytes).
pub fn point_to_bytes(p: &G1Projective) -> [u8; 48] {
    G1Affine::from(p).to_compressed()
}

/// Deserialize a G1 point from compressed bytes.
///
/// SECURITY: must use `from_compressed` (full on-curve + prime-order subgroup
/// `is_torsion_free` check), NOT `from_compressed_unchecked` — skipping the
/// subgroup check would open small-subgroup / cofactor attacks on every
/// attacker-supplied proof point (Abar/Bbar/D, pseudonym).
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
    use group::Group; // for G1Projective::generator() in tests

    use super::*;

    #[test]
    fn create_generators_correct_count() {
        let gens = create_generators(5, Ciphersuite::Bls12381Sha256).unwrap();
        assert_eq!(gens.len(), 5);
    }

    #[test]
    fn create_generators_caps_at_max() {
        // At the limit: allowed.
        assert!(create_generators(MAX_GENERATORS, Ciphersuite::Bls12381Sha256).is_ok());
        // One over: rejected cheaply, before building any generators.
        let err = create_generators(MAX_GENERATORS + 1, Ciphersuite::Bls12381Sha256).unwrap_err();
        assert!(matches!(err, BbsError::InvalidProof(_)), "got {err:?}");
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

    /// Regression vector for the subgroup check (audit Finding 6).
    ///
    /// A compressed G1 encoding (x-coordinate = 4) that decodes to a point which
    /// is **on the curve** but **not in the prime-order subgroup** (cofactor
    /// torsion). `point_from_bytes` MUST reject it: accepting torsion points —
    /// e.g. via an accidental `from_compressed_unchecked` swap — would open
    /// small-subgroup / cofactor attacks on every attacker-supplied proof point
    /// (Abar/Bbar/D, pseudonym). The `_unchecked` assertions below prove the
    /// vector is a genuine subgroup-evasion case rather than mere garbage.
    #[test]
    fn point_from_bytes_rejects_on_curve_non_subgroup() {
        let vector: [u8; 48] = hex::decode(
            "800000000000000000000000000000000000000000000000\
             000000000000000000000000000000000000000000000004",
        )
        .unwrap()
        .try_into()
        .unwrap();

        // The hardened path rejects it.
        assert!(
            point_from_bytes(&vector).is_none(),
            "subgroup check must reject an on-curve torsion point"
        );
        assert!(bool::from(G1Affine::from_compressed(&vector).is_none()));

        // Prove the vector really is on-curve-but-not-subgroup (so the test is
        // meaningful): the unchecked decode succeeds, the point is on the curve,
        // but it fails the prime-order subgroup membership test.
        let unchecked = G1Affine::from_compressed_unchecked(&vector);
        assert!(
            bool::from(unchecked.is_some()),
            "vector must decode unchecked"
        );
        let p = unchecked.unwrap();
        assert!(bool::from(p.is_on_curve()), "vector must be on the curve");
        assert!(
            !bool::from(p.is_torsion_free()),
            "vector must be outside the prime-order subgroup"
        );
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

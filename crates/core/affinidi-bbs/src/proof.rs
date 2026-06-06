/*!
 * BBS ProofGen and ProofVerify — zero-knowledge selective disclosure.
 *
 * Per IETF draft §3.4.3 (ProofGen) and §3.4.4 (ProofVerify):
 *
 * ProofGen creates a zero-knowledge proof that the prover knows a valid
 * BBS signature over a set of messages, selectively disclosing a subset.
 *
 * The proof is unlinkable: different proofs from the same signature
 * cannot be correlated by verifiers.
 */

use std::collections::HashSet;

use bls12_381_plus::{
    G1Affine, G1Projective, G2Affine, G2Prepared, G2Projective, Scalar, multi_miller_loop,
};
use ff::Field;
use group::Group;
use rand::Rng;

use crate::ciphersuite::Ciphersuite;
use crate::error::{BbsError, Result};
use crate::generators::{calculate_domain, create_generators, p1_generator, point_to_bytes};
use crate::hash::{hash_to_scalar, messages_to_scalars, scalar_to_bytes};
use crate::pseudonym::calculate_pseudonym_generator;
use crate::signature::compute_b;
use crate::types::{Proof, Pseudonym, PublicKey, Signature};

/// Generate a zero-knowledge proof of selective disclosure.
///
/// # Arguments
///
/// * `pk` - The signer's public key
/// * `signature` - The BBS signature to prove knowledge of
/// * `header` - The same header used during signing
/// * `presentation_header` - Session-specific header (binds proof to session)
/// * `messages` - All messages that were signed
/// * `disclosed_indexes` - Which message indexes to reveal (0-based)
/// * `cs` - The ciphersuite
///
/// # Returns
///
/// A zero-knowledge proof. The verifier receives only the disclosed messages
/// and can verify the proof without learning anything about undisclosed messages.
pub fn core_proof_gen(
    pk: &PublicKey,
    signature: &Signature,
    header: &[u8],
    presentation_header: &[u8],
    messages: &[&[u8]],
    disclosed_indexes: &[usize],
    cs: Ciphersuite,
) -> Result<Proof> {
    Ok(core_proof_gen_impl(
        pk,
        signature,
        header,
        presentation_header,
        messages,
        disclosed_indexes,
        None,
        None,
        cs,
    )?
    .0)
}

/// Generate a selective-disclosure proof bound to a per-verifier pseudonym
/// (draft-irtf-cfrg-bbs-per-verifier-linkability `ProofGenWithPseudonym`).
///
/// The **last** message in `messages` is the holder's `nym_secret` and MUST be
/// undisclosed. `verifier_context` is the per-verifier context id (the
/// pseudonym entropy). Returns the proof and the [`Pseudonym`].
#[allow(clippy::too_many_arguments)]
pub fn core_proof_gen_with_pseudonym(
    pk: &PublicKey,
    signature: &Signature,
    header: &[u8],
    presentation_header: &[u8],
    messages: &[&[u8]],
    disclosed_indexes: &[usize],
    verifier_context: &[u8],
    cs: Ciphersuite,
) -> Result<(Proof, Pseudonym)> {
    let op = calculate_pseudonym_generator(verifier_context, cs);
    let (proof, pseudonym) = core_proof_gen_impl(
        pk,
        signature,
        header,
        presentation_header,
        messages,
        disclosed_indexes,
        None,
        Some(op),
        cs,
    )?;
    let pseudonym = pseudonym.ok_or_else(|| BbsError::Crypto("pseudonym not produced".into()))?;
    Ok((proof, Pseudonym(pseudonym)))
}

/// Verify a selective-disclosure proof bound to a per-verifier pseudonym
/// (`ProofVerifyWithPseudonym`). `verifier_context` must match generation, and
/// `pseudonym` is the value the holder presented.
#[allow(clippy::too_many_arguments)]
pub fn core_proof_verify_with_pseudonym(
    pk: &PublicKey,
    proof: &Proof,
    header: &[u8],
    presentation_header: &[u8],
    disclosed_messages: &[&[u8]],
    disclosed_indexes: &[usize],
    verifier_context: &[u8],
    pseudonym: &Pseudonym,
    cs: Ciphersuite,
) -> Result<bool> {
    let op = calculate_pseudonym_generator(verifier_context, cs);
    core_proof_verify_impl(
        pk,
        proof,
        header,
        presentation_header,
        disclosed_messages,
        disclosed_indexes,
        Some((op, pseudonym.0)),
        cs,
    )
}

/// The per-proof random scalars (`r1, r2, ẽ, r̃1, r̃3, m̃_j`). Normally sampled;
/// injectable so the deterministic IETF proof vectors can be reproduced exactly.
struct ProofRandomScalars {
    r1: Scalar,
    r2: Scalar,
    e_tilde: Scalar,
    r1_tilde: Scalar,
    r3_tilde: Scalar,
    m_tildes: Vec<Scalar>,
}

impl ProofRandomScalars {
    fn random(u: usize) -> Self {
        let mut rng = rand::rng();
        ProofRandomScalars {
            r1: random_nonzero_scalar(&mut rng),
            r2: random_nonzero_scalar(&mut rng),
            e_tilde: random_nonzero_scalar(&mut rng),
            r1_tilde: random_nonzero_scalar(&mut rng),
            r3_tilde: random_nonzero_scalar(&mut rng),
            m_tildes: (0..u).map(|_| random_nonzero_scalar(&mut rng)).collect(),
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn core_proof_gen_impl(
    pk: &PublicKey,
    signature: &Signature,
    header: &[u8],
    presentation_header: &[u8],
    messages: &[&[u8]],
    disclosed_indexes: &[usize],
    random_scalars: Option<ProofRandomScalars>,
    nym_op: Option<G1Projective>,
    cs: Ciphersuite,
) -> Result<(Proof, Option<G1Projective>)> {
    let l = messages.len();

    // Validate disclosed indexes: bounds check and no duplicates
    {
        let mut seen = HashSet::with_capacity(disclosed_indexes.len());
        for &idx in disclosed_indexes {
            if idx >= l {
                return Err(BbsError::InvalidIndex(format!(
                    "disclosed index {idx} >= message count {l}"
                )));
            }
            if !seen.insert(idx) {
                return Err(BbsError::InvalidIndex(format!(
                    "duplicate disclosed index: {idx}"
                )));
            }
        }
    }

    // 1. Convert messages to scalars
    let msg_scalars = messages_to_scalars(messages, cs)?;

    // 2. Create generators
    let generators = create_generators(l + 1, cs)?;
    let q1 = &generators[0];
    let h_generators = &generators[1..];

    // 3. Calculate domain
    let domain = calculate_domain(pk, q1, h_generators, header, cs)?;

    // Partition into disclosed/undisclosed
    let mut undisclosed_indexes: Vec<usize> =
        (0..l).filter(|i| !disclosed_indexes.contains(i)).collect();
    undisclosed_indexes.sort();
    let u = undisclosed_indexes.len();

    // 4. Random scalars — injected for deterministic KATs, otherwise sampled.
    let ProofRandomScalars {
        r1,
        r2,
        e_tilde,
        r1_tilde,
        r3_tilde,
        m_tildes,
    } = random_scalars.unwrap_or_else(|| ProofRandomScalars::random(u));
    debug_assert_eq!(m_tildes.len(), u, "one m~ per undisclosed message");

    // 5. Compute B = P1 + Q1*domain + H1*msg1 + ... + HL*msgL
    let b = compute_b(q1, &domain, h_generators, &msg_scalars);

    // 6. Blinding: D = B * r2, Abar = A * (r1 * r2), Bbar = D * r1 - Abar * e
    let d = b * r2;
    let r1_r2 = r1 * r2;
    let abar = signature.a * r1_r2;
    let bbar = d * r1 - abar * signature.e;

    // r3 = r2^(-1)
    let r3 = r2.invert().unwrap();

    // 7. Compute T1 = Abar * e~ + D * r1~
    let t1 = abar * e_tilde + d * r1_tilde;

    // 8. Compute T2 = D * r3~ + sum(H_j * m~_j for undisclosed j)
    let mut t2 = d * r3_tilde;
    for (k, &j) in undisclosed_indexes.iter().enumerate() {
        t2 += h_generators[j] * m_tildes[k];
    }

    // 8b. Per-verifier pseudonym binding (optional). Per
    // draft-irtf-cfrg-bbs-per-verifier-linkability, the `nym_secret` is the
    // LAST signed message (always undisclosed); the pseudonym reuses that
    // message's blinding `m~`. PseudonymProofInit: Pseudonym = OP·nym_secret,
    // Ut = OP·m~_nym.
    let nym_terms: Option<(G1Projective, G1Projective, G1Projective)> = match nym_op {
        Some(op) => {
            let nym_index = l - 1;
            if disclosed_indexes.contains(&nym_index) {
                return Err(BbsError::InvalidIndex(
                    "nym_secret (last message) must not be disclosed".into(),
                ));
            }
            // L-1 is the largest index, hence the last entry of the sorted
            // undisclosed list, so its m~ is m_tildes[u-1].
            let pseudonym = op * msg_scalars[nym_index];
            let ut = op * m_tildes[u - 1];
            if bool::from(pseudonym.is_identity()) || bool::from(ut.is_identity()) {
                return Err(BbsError::Crypto("pseudonym or Ut is identity".into()));
            }
            Some((pseudonym, op, ut))
        }
        None => None,
    };

    // 9. Fiat-Shamir challenge (uses only disclosed message scalars)
    let disclosed_msg_scalars: Vec<Scalar> =
        disclosed_indexes.iter().map(|&i| msg_scalars[i]).collect();

    let challenge = compute_challenge(
        &abar,
        &bbar,
        &d,
        &t1,
        &t2,
        disclosed_indexes,
        &disclosed_msg_scalars,
        &domain,
        presentation_header,
        nym_terms.as_ref().map(|(p, o, u)| (p, o, u)),
        cs,
    )?;

    // 10. Compute response scalars
    let e_hat = e_tilde + challenge * signature.e;
    let r1_hat = r1_tilde - challenge * r1;
    let r3_hat = r3_tilde - challenge * r3;

    let mut m_hats: Vec<Scalar> = Vec::with_capacity(u);
    for (k, &j) in undisclosed_indexes.iter().enumerate() {
        // Per IETF draft: m^_j = m~_j + msg_j * c (addition, not subtraction)
        m_hats.push(m_tildes[k] + challenge * msg_scalars[j]);
    }

    // 11. Serialize proof
    let mut proof_bytes = Vec::new();
    proof_bytes.extend_from_slice(&point_to_bytes(&abar));
    proof_bytes.extend_from_slice(&point_to_bytes(&bbar));
    proof_bytes.extend_from_slice(&point_to_bytes(&d));
    proof_bytes.extend_from_slice(&scalar_to_bytes(&e_hat));
    proof_bytes.extend_from_slice(&scalar_to_bytes(&r1_hat));
    proof_bytes.extend_from_slice(&scalar_to_bytes(&r3_hat));
    for m_hat in &m_hats {
        proof_bytes.extend_from_slice(&scalar_to_bytes(m_hat));
    }
    proof_bytes.extend_from_slice(&scalar_to_bytes(&challenge));

    let pseudonym = nym_terms.map(|(pseudonym, _, _)| pseudonym);
    Ok((Proof::from_bytes(&proof_bytes), pseudonym))
}

/// Verify a BBS zero-knowledge proof.
///
/// # Arguments
///
/// * `pk` - The signer's public key
/// * `proof` - The proof to verify
/// * `header` - The same header used during signing
/// * `presentation_header` - The same presentation header used in proof generation
/// * `disclosed_messages` - The messages that were disclosed (in order of disclosed_indexes)
/// * `disclosed_indexes` - The indexes of the disclosed messages
/// * `cs` - The ciphersuite
pub fn core_proof_verify(
    pk: &PublicKey,
    proof: &Proof,
    header: &[u8],
    presentation_header: &[u8],
    disclosed_messages: &[&[u8]],
    disclosed_indexes: &[usize],
    cs: Ciphersuite,
) -> Result<bool> {
    core_proof_verify_impl(
        pk,
        proof,
        header,
        presentation_header,
        disclosed_messages,
        disclosed_indexes,
        None,
        cs,
    )
}

/// Shared verify implementation. `nym = Some((OP, Pseudonym))` checks the
/// per-verifier pseudonym binding (`Uv = OP·m̂_nym − Pseudonym·c`).
#[allow(clippy::too_many_arguments)]
fn core_proof_verify_impl(
    pk: &PublicKey,
    proof: &Proof,
    header: &[u8],
    presentation_header: &[u8],
    disclosed_messages: &[&[u8]],
    disclosed_indexes: &[usize],
    nym: Option<(G1Projective, G1Projective)>,
    cs: Ciphersuite,
) -> Result<bool> {
    // Validate public key
    pk.validate()?;

    let proof_bytes = proof.to_bytes();

    // Determine U (undisclosed count) from proof length
    let r = disclosed_indexes.len();
    let scalar_len = cs.octet_scalar_length();
    let point_len = cs.octet_point_length();
    let min_len = 3 * point_len + 4 * scalar_len;

    if proof_bytes.len() < min_len {
        return Err(BbsError::InvalidProof("proof too short".into()));
    }

    let u = (proof_bytes.len() - min_len) / scalar_len;
    let l = r + u; // Total message count

    if disclosed_messages.len() != r {
        return Err(BbsError::InvalidProof(
            "disclosed message count mismatch".into(),
        ));
    }

    // 1. Deserialize proof components
    let mut offset = 0;

    let mut abar_bytes = [0u8; 48];
    abar_bytes.copy_from_slice(&proof_bytes[offset..offset + 48]);
    let abar = crate::generators::point_from_bytes(&abar_bytes)
        .ok_or_else(|| BbsError::InvalidProof("invalid Abar point".into()))?;
    offset += 48;

    let mut bbar_bytes = [0u8; 48];
    bbar_bytes.copy_from_slice(&proof_bytes[offset..offset + 48]);
    let bbar = crate::generators::point_from_bytes(&bbar_bytes)
        .ok_or_else(|| BbsError::InvalidProof("invalid Bbar point".into()))?;
    offset += 48;

    let mut d_bytes = [0u8; 48];
    d_bytes.copy_from_slice(&proof_bytes[offset..offset + 48]);
    let d = crate::generators::point_from_bytes(&d_bytes)
        .ok_or_else(|| BbsError::InvalidProof("invalid D point".into()))?;
    offset += 48;

    let e_hat = read_scalar(proof_bytes, &mut offset)?;
    let r1_hat = read_scalar(proof_bytes, &mut offset)?;
    let r3_hat = read_scalar(proof_bytes, &mut offset)?;

    let mut m_hats = Vec::with_capacity(u);
    for _ in 0..u {
        m_hats.push(read_scalar(proof_bytes, &mut offset)?);
    }

    let challenge = read_scalar(proof_bytes, &mut offset)?;

    // 2. Convert disclosed messages to scalars
    let disclosed_scalars = messages_to_scalars(disclosed_messages, cs)?;

    // 3. Create generators for L+1 messages
    let generators = create_generators(l + 1, cs)?;
    let q1 = &generators[0];
    let h_generators = &generators[1..];

    // 4. Calculate domain
    let domain = calculate_domain(pk, q1, h_generators, header, cs)?;

    // 5. Determine undisclosed indexes
    let undisclosed_indexes: Vec<usize> =
        (0..l).filter(|i| !disclosed_indexes.contains(i)).collect();

    // 6. Recompute T1 = Abar * e^ + D * r1^ + Bbar * challenge
    let t1 = abar * e_hat + d * r1_hat + bbar * challenge;

    // Per the spec, ProofVerifyInit computes T2 as:
    // Bv = P1 + Q1*domain + sum(H_i*msg_i for disclosed)
    // T2 = Bv*c + D*r3^ + sum(H_j*m^_j for undisclosed) - Bbar*c
    //
    // This is because during ProofGen:
    // T2 = D*r3~ + sum(H_j*m~_j)
    // And the relationship Bbar = D*r1 - Abar*e means:
    // T2_verify = Bv*c + D*r3^ + sum(H_j*m^_j) - Bbar*c
    let mut bv = p1_generator() + *q1 * domain;
    for (k, &i) in disclosed_indexes.iter().enumerate() {
        bv += h_generators[i] * disclosed_scalars[k];
    }

    let mut t2 = bv * challenge + d * r3_hat;
    for (k, &j) in undisclosed_indexes.iter().enumerate() {
        t2 += h_generators[j] * m_hats[k];
    }

    // 7b. Per-verifier pseudonym binding (optional). nym_secret is the last
    // message (index L-1), always undisclosed; its response is m_hats[u-1].
    // PseudonymProofVerify: Uv = OP·m̂_nym − Pseudonym·c.
    let nym_terms: Option<(G1Projective, G1Projective, G1Projective)> = match nym {
        Some((op, pseudonym)) => {
            let nym_index = l - 1;
            if disclosed_indexes.contains(&nym_index) {
                return Err(BbsError::InvalidIndex(
                    "nym_secret (last message) must not be disclosed".into(),
                ));
            }
            if bool::from(op.is_identity()) || bool::from(pseudonym.is_identity()) {
                return Ok(false);
            }
            let uv = op * m_hats[u - 1] - pseudonym * challenge;
            if bool::from(uv.is_identity()) {
                return Ok(false);
            }
            Some((pseudonym, op, uv))
        }
        None => None,
    };

    // 8. Recompute challenge
    let recomputed_challenge = compute_challenge(
        &abar,
        &bbar,
        &d,
        &t1,
        &t2,
        disclosed_indexes,
        &disclosed_scalars,
        &domain,
        presentation_header,
        nym_terms.as_ref().map(|(p, o, u)| (p, o, u)),
        cs,
    )?;

    // 9. Check challenge matches
    if challenge != recomputed_challenge {
        return Ok(false);
    }

    // 10. Pairing check: e(Abar, W) * e(Bbar, -BP2) == 1_GT
    let w = pk.0;
    let bp2 = G2Projective::generator();

    let abar_affine = G1Affine::from(&abar);
    let neg_bbar_affine = G1Affine::from(&(-bbar));
    let w_affine = G2Affine::from(&w);
    let bp2_affine = G2Affine::from(&bp2);

    let result = multi_miller_loop(&[
        (&abar_affine, &G2Prepared::from(w_affine)),
        (&neg_bbar_affine, &G2Prepared::from(bp2_affine)),
    ])
    .final_exponentiation();

    Ok(bool::from(result.is_identity()))
}

/// Compute the Fiat-Shamir challenge.
///
/// When `nym_terms` is `Some((Pseudonym, OP, Ut))`, the per-verifier pseudonym
/// points are inserted between `T2` and `domain`, per
/// draft-irtf-cfrg-bbs-per-verifier-linkability ProofWithPseudonymChallengeCalculate:
///   `c_arr = (R, i,msg.., Abar, Bbar, D, T1, T2, pseudonym, OP, Ut, domain)`.
/// With `None` the transcript is byte-identical to the plain BBS proof.
#[allow(clippy::too_many_arguments)]
fn compute_challenge(
    abar: &G1Projective,
    bbar: &G1Projective,
    d: &G1Projective,
    t1: &G1Projective,
    t2: &G1Projective,
    disclosed_indexes: &[usize],
    disclosed_scalars: &[Scalar],
    domain: &Scalar,
    presentation_header: &[u8],
    nym_terms: Option<(&G1Projective, &G1Projective, &G1Projective)>,
    cs: Ciphersuite,
) -> Result<Scalar> {
    let challenge_dst = [cs.api_id().as_slice(), b"H2S_"].concat();

    // Per draft-irtf-cfrg-bbs-signatures ProofChallengeCalculate:
    //   c_arr  = (R, i_1, msg_i1, ..., i_R, msg_iR, Abar, Bbar, D, T1, T2, domain)
    //   c_octs = serialize(c_arr) || I2OSP(length(ph), 8) || ph
    // Interop-critical ordering: the disclosed (index, message) PAIRS are
    // interleaved and come FIRST (after the count R), the proof points come
    // AFTER the messages, and the presentation header is length-prefixed last.
    debug_assert_eq!(disclosed_indexes.len(), disclosed_scalars.len());
    let mut data = Vec::new();

    // R, then interleaved (i_j, msg_i_j) pairs.
    data.extend_from_slice(&(disclosed_indexes.len() as u64).to_be_bytes());
    for (&idx, scalar) in disclosed_indexes.iter().zip(disclosed_scalars) {
        data.extend_from_slice(&(idx as u64).to_be_bytes());
        data.extend_from_slice(&scalar_to_bytes(scalar));
    }

    // Proof points; the pseudonym binding (Pseudonym, OP, Ut) goes between T2
    // and domain when present; then domain.
    data.extend_from_slice(&point_to_bytes(abar));
    data.extend_from_slice(&point_to_bytes(bbar));
    data.extend_from_slice(&point_to_bytes(d));
    data.extend_from_slice(&point_to_bytes(t1));
    data.extend_from_slice(&point_to_bytes(t2));
    if let Some((pseudonym, op, ut)) = nym_terms {
        data.extend_from_slice(&point_to_bytes(pseudonym));
        data.extend_from_slice(&point_to_bytes(op));
        data.extend_from_slice(&point_to_bytes(ut));
    }
    data.extend_from_slice(&scalar_to_bytes(domain));

    // Length-prefixed presentation header.
    data.extend_from_slice(&(presentation_header.len() as u64).to_be_bytes());
    data.extend_from_slice(presentation_header);

    hash_to_scalar(&data, &challenge_dst, cs)
}

/// Generate a random nonzero scalar.
fn random_nonzero_scalar(rng: &mut impl Rng) -> Scalar {
    loop {
        let bytes: [u8; 48] = rng.random();
        let s = Scalar::from_okm(&bytes);
        if !bool::from(s.is_zero()) {
            return s;
        }
    }
}

/// Read a 32-byte scalar from a buffer at the given offset.
fn read_scalar(buf: &[u8], offset: &mut usize) -> Result<Scalar> {
    if *offset + 32 > buf.len() {
        return Err(BbsError::InvalidProof("proof too short for scalar".into()));
    }
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&buf[*offset..*offset + 32]);
    *offset += 32;

    let s = Scalar::from_be_bytes(&bytes);
    if s.is_some().into() {
        Ok(s.unwrap())
    } else {
        Err(BbsError::Deserialization("invalid scalar in proof".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::SecretKey;
    use bls12_381_plus::Scalar;

    fn test_keypair() -> (SecretKey, PublicKey) {
        let sk_scalar = Scalar::from(42u64);
        let sk = SecretKey(sk_scalar);
        let pk = PublicKey(G2Projective::generator() * sk_scalar);
        (sk, pk)
    }

    // --- exact proof reproduction against the IETF/DIF vectors ---------------
    //
    // Proofs are randomized, so the published vectors fix the random scalars in
    // their `trace`. Injecting those scalars must reproduce the proof bytes
    // exactly — the definitive check that OUR prover is spec-compliant (a
    // conforming verifier will accept our proofs), complementing the
    // proof-verify KATs in tests/interop_kat.rs (we accept theirs).

    fn scalar_from_hex(s: &str) -> Scalar {
        let bytes: [u8; 32] = hex::decode(s).unwrap().try_into().unwrap();
        Scalar::from_be_bytes(&bytes).unwrap()
    }

    fn reproduce_proof_fixture(name: &str) {
        let path = format!(
            "{}/tests/fixtures/bls12-381-sha-256/{}",
            env!("CARGO_MANIFEST_DIR"),
            name
        );
        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();

        let pk_bytes: [u8; 96] = hex::decode(v["signerPublicKey"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let pk = PublicKey::from_bytes(&pk_bytes).unwrap();
        let sig =
            Signature::from_bytes(&hex::decode(v["signature"].as_str().unwrap()).unwrap()).unwrap();
        let header = hex::decode(v["header"].as_str().unwrap()).unwrap();
        let ph = hex::decode(v["presentationHeader"].as_str().unwrap()).unwrap();
        let msgs: Vec<Vec<u8>> = v["messages"]
            .as_array()
            .unwrap()
            .iter()
            .map(|m| hex::decode(m.as_str().unwrap()).unwrap())
            .collect();
        let refs: Vec<&[u8]> = msgs.iter().map(|m| m.as_slice()).collect();
        let disclosed: Vec<usize> = v["disclosedIndexes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|i| i.as_u64().unwrap() as usize)
            .collect();

        let rs = &v["trace"]["random_scalars"];
        let scalars = ProofRandomScalars {
            r1: scalar_from_hex(rs["r1"].as_str().unwrap()),
            r2: scalar_from_hex(rs["r2"].as_str().unwrap()),
            e_tilde: scalar_from_hex(rs["e_tilde"].as_str().unwrap()),
            r1_tilde: scalar_from_hex(rs["r1_tilde"].as_str().unwrap()),
            r3_tilde: scalar_from_hex(rs["r3_tilde"].as_str().unwrap()),
            m_tildes: rs["m_tilde_scalars"]
                .as_array()
                .unwrap()
                .iter()
                .map(|s| scalar_from_hex(s.as_str().unwrap()))
                .collect(),
        };

        let (proof, _) = core_proof_gen_impl(
            &pk,
            &sig,
            &header,
            &ph,
            &refs,
            &disclosed,
            Some(scalars),
            None,
            Ciphersuite::Bls12381Sha256,
        )
        .unwrap();

        assert_eq!(
            hex::encode(proof.to_bytes()),
            v["proof"].as_str().unwrap(),
            "reproduced proof bytes diverge from the IETF vector ({name})"
        );
    }

    #[test]
    fn reproduce_proof_single_disclosed_vector() {
        reproduce_proof_fixture("proof001.json");
    }

    #[test]
    fn reproduce_proof_partial_disclosure_vector() {
        reproduce_proof_fixture("proof003.json");
    }

    #[test]
    fn proof_single_message_single_disclosed() {
        let (sk, pk) = test_keypair();
        let messages: Vec<&[u8]> = vec![b"hello"];
        let sig =
            crate::signature::core_sign(&sk, &pk, b"", &messages, Ciphersuite::Bls12381Sha256)
                .unwrap();

        let proof = core_proof_gen(
            &pk,
            &sig,
            b"",
            b"ph",
            &messages,
            &[0],
            Ciphersuite::Bls12381Sha256,
        )
        .unwrap();

        let valid = core_proof_verify(
            &pk,
            &proof,
            b"",
            b"ph",
            &[b"hello"],
            &[0],
            Ciphersuite::Bls12381Sha256,
        )
        .unwrap();

        assert!(valid);
    }

    #[test]
    fn proof_multiple_messages_partial_disclosure() {
        let (sk, pk) = test_keypair();
        let messages: Vec<&[u8]> = vec![b"msg0", b"msg1", b"msg2", b"msg3"];
        let sig = crate::signature::core_sign(
            &sk,
            &pk,
            b"header",
            &messages,
            Ciphersuite::Bls12381Sha256,
        )
        .unwrap();

        // Disclose only msg0 and msg2
        let proof = core_proof_gen(
            &pk,
            &sig,
            b"header",
            b"session-ph",
            &messages,
            &[0, 2],
            Ciphersuite::Bls12381Sha256,
        )
        .unwrap();

        let valid = core_proof_verify(
            &pk,
            &proof,
            b"header",
            b"session-ph",
            &[b"msg0", b"msg2"],
            &[0, 2],
            Ciphersuite::Bls12381Sha256,
        )
        .unwrap();

        assert!(valid);
    }

    #[test]
    fn proof_all_disclosed() {
        let (sk, pk) = test_keypair();
        let messages: Vec<&[u8]> = vec![b"a", b"b", b"c"];
        let sig =
            crate::signature::core_sign(&sk, &pk, b"", &messages, Ciphersuite::Bls12381Sha256)
                .unwrap();

        let proof = core_proof_gen(
            &pk,
            &sig,
            b"",
            b"ph",
            &messages,
            &[0, 1, 2],
            Ciphersuite::Bls12381Sha256,
        )
        .unwrap();

        let valid = core_proof_verify(
            &pk,
            &proof,
            b"",
            b"ph",
            &[b"a", b"b", b"c"],
            &[0, 1, 2],
            Ciphersuite::Bls12381Sha256,
        )
        .unwrap();

        assert!(valid);
    }

    #[test]
    fn proof_none_disclosed() {
        let (sk, pk) = test_keypair();
        let messages: Vec<&[u8]> = vec![b"secret1", b"secret2"];
        let sig =
            crate::signature::core_sign(&sk, &pk, b"", &messages, Ciphersuite::Bls12381Sha256)
                .unwrap();

        // Disclose nothing — prove existence without revealing any messages
        let proof = core_proof_gen(
            &pk,
            &sig,
            b"",
            b"ph",
            &messages,
            &[],
            Ciphersuite::Bls12381Sha256,
        )
        .unwrap();

        let valid = core_proof_verify(
            &pk,
            &proof,
            b"",
            b"ph",
            &[],
            &[],
            Ciphersuite::Bls12381Sha256,
        )
        .unwrap();

        assert!(valid);
    }

    #[test]
    fn proof_wrong_disclosed_message_fails() {
        let (sk, pk) = test_keypair();
        let messages: Vec<&[u8]> = vec![b"real"];
        let sig =
            crate::signature::core_sign(&sk, &pk, b"", &messages, Ciphersuite::Bls12381Sha256)
                .unwrap();

        let proof = core_proof_gen(
            &pk,
            &sig,
            b"",
            b"ph",
            &messages,
            &[0],
            Ciphersuite::Bls12381Sha256,
        )
        .unwrap();

        let valid = core_proof_verify(
            &pk,
            &proof,
            b"",
            b"ph",
            &[b"fake"],
            &[0],
            Ciphersuite::Bls12381Sha256,
        )
        .unwrap();

        assert!(!valid);
    }

    #[test]
    fn proof_wrong_presentation_header_fails() {
        let (sk, pk) = test_keypair();
        let messages: Vec<&[u8]> = vec![b"msg"];
        let sig =
            crate::signature::core_sign(&sk, &pk, b"", &messages, Ciphersuite::Bls12381Sha256)
                .unwrap();

        let proof = core_proof_gen(
            &pk,
            &sig,
            b"",
            b"ph1",
            &messages,
            &[0],
            Ciphersuite::Bls12381Sha256,
        )
        .unwrap();

        let valid = core_proof_verify(
            &pk,
            &proof,
            b"",
            b"ph2",
            &[b"msg"],
            &[0],
            Ciphersuite::Bls12381Sha256,
        )
        .unwrap();

        assert!(!valid);
    }

    #[test]
    fn proofs_are_unlinkable() {
        let (sk, pk) = test_keypair();
        let messages: Vec<&[u8]> = vec![b"msg"];
        let sig =
            crate::signature::core_sign(&sk, &pk, b"", &messages, Ciphersuite::Bls12381Sha256)
                .unwrap();

        let proof1 = core_proof_gen(
            &pk,
            &sig,
            b"",
            b"session1",
            &messages,
            &[0],
            Ciphersuite::Bls12381Sha256,
        )
        .unwrap();

        let proof2 = core_proof_gen(
            &pk,
            &sig,
            b"",
            b"session2",
            &messages,
            &[0],
            Ciphersuite::Bls12381Sha256,
        )
        .unwrap();

        // Proofs should be different (randomized)
        assert_ne!(proof1.to_bytes(), proof2.to_bytes());

        // Both should verify
        assert!(
            core_proof_verify(
                &pk,
                &proof1,
                b"",
                b"session1",
                &[b"msg"],
                &[0],
                Ciphersuite::Bls12381Sha256,
            )
            .unwrap()
        );
        assert!(
            core_proof_verify(
                &pk,
                &proof2,
                b"",
                b"session2",
                &[b"msg"],
                &[0],
                Ciphersuite::Bls12381Sha256,
            )
            .unwrap()
        );
    }

    #[test]
    fn proof_invalid_index_rejected() {
        let (sk, pk) = test_keypair();
        let messages: Vec<&[u8]> = vec![b"msg"];
        let sig =
            crate::signature::core_sign(&sk, &pk, b"", &messages, Ciphersuite::Bls12381Sha256)
                .unwrap();

        let result = core_proof_gen(
            &pk,
            &sig,
            b"",
            b"ph",
            &messages,
            &[5], // Index 5 out of bounds
            Ciphersuite::Bls12381Sha256,
        );

        assert!(result.is_err());
    }

    #[test]
    fn proof_ten_messages_selective() {
        let (sk, pk) = test_keypair();
        let messages: Vec<&[u8]> = vec![
            b"m0", b"m1", b"m2", b"m3", b"m4", b"m5", b"m6", b"m7", b"m8", b"m9",
        ];
        let sig =
            crate::signature::core_sign(&sk, &pk, b"hdr", &messages, Ciphersuite::Bls12381Sha256)
                .unwrap();

        // Disclose messages 2, 5, 7
        let proof = core_proof_gen(
            &pk,
            &sig,
            b"hdr",
            b"ph",
            &messages,
            &[2, 5, 7],
            Ciphersuite::Bls12381Sha256,
        )
        .unwrap();

        let valid = core_proof_verify(
            &pk,
            &proof,
            b"hdr",
            b"ph",
            &[b"m2", b"m5", b"m7"],
            &[2, 5, 7],
            Ciphersuite::Bls12381Sha256,
        )
        .unwrap();

        assert!(valid);
    }
}

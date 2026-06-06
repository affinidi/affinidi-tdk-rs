/*!
 * Per-verifier pseudonym BBS — blind issuance with a holder `nym_secret`
 * (`draft-irtf-cfrg-bbs-per-verifier-linkability`, blind variant).
 *
 * Builds on blind BBS ([`crate::blind`]): the holder commits a `prover_nym`
 * (alongside any other committed messages), the issuer adds `signer_nym_entropy`
 * while signing, and the holder's `nym_secret = prover_nym + signer_nym_entropy`
 * becomes the last committed message — known to neither party alone. At
 * presentation the holder derives a stable per-verifier [`Pseudonym`] from a
 * verifier `context_id` (see [`crate::pseudonym`]) bound into the proof.
 *
 * This module covers the **issuance** half (NymCommit / BlindSignWithNym /
 * BlindVerifyWithNym); the pseudonym-bound proof is in [`crate::proof`].
 *
 * Construction matches `@digitalbazaar/bbs-signatures` and is KAT-gated
 * byte-for-byte against the official IETF pseudonym test vectors.
 */

use bls12_381_plus::Scalar;

use crate::blind::{
    blind_b_calculate, blind_message_count, core_commit, deserialize_and_validate_commit,
    finalize_blind_sign, random_scalars,
};
use crate::ciphersuite::Ciphersuite;
use crate::error::{BbsError, Result};
use crate::generators::{calculate_domain_with_api_id, create_generators_with_api_id};
use crate::hash::messages_to_scalars_with_api_id;
use crate::proof::{ProofRandomScalars, proof_gen_core, proof_verify_core};
use crate::pseudonym::calculate_pseudonym_generator_with_api_id;
use crate::signature::{compute_b, verify_signature_pairing};
use crate::types::{Proof, Pseudonym, PublicKey, SecretKey, Signature};

/// The api_id for the pseudonym blind (committed-message) generators:
/// `"BLIND_" || pseudonym_api_id`.
fn pseudonym_blind_generators_api_id(cs: Ciphersuite) -> Vec<u8> {
    [b"BLIND_".as_slice(), cs.pseudonym_api_id().as_slice()].concat()
}

/// Holder commitment to a `prover_nym` (plus any other committed messages).
///
/// Like [`crate::blind::commit`], but `prover_nym` is appended as the final
/// committed message. Returns `(commitment_with_proof, secret_prover_blind)`.
pub fn nym_commit(
    prover_nym: Scalar,
    committed_messages: &[&[u8]],
    cs: Ciphersuite,
) -> Result<(Vec<u8>, Scalar)> {
    // committed_message_scalars = [committed..., prover_nym] → CoreCommit needs
    // len + 2 random scalars.
    let count = committed_messages.len() + 1 + 2;
    let randoms = random_scalars(count);
    nym_commit_with_random_scalars(prover_nym, committed_messages, &randoms, cs)
}

/// [`nym_commit`] with injected random scalars (reproduces the IETF vectors).
/// `random_scalars` length must be `committed_messages.len() + 3`.
pub(crate) fn nym_commit_with_random_scalars(
    prover_nym: Scalar,
    committed_messages: &[&[u8]],
    random_scalars: &[Scalar],
    cs: Ciphersuite,
) -> Result<(Vec<u8>, Scalar)> {
    let api_id = cs.pseudonym_api_id();
    let mut committed_scalars = messages_to_scalars_with_api_id(committed_messages, &api_id, cs)?;
    committed_scalars.push(prover_nym);

    let blind_generators = create_generators_with_api_id(
        committed_scalars.len() + 1,
        &pseudonym_blind_generators_api_id(cs),
        cs,
    )?;

    core_commit(
        &committed_scalars,
        &blind_generators,
        &api_id,
        random_scalars,
        cs,
    )
}

/// Issuer blind-signs a holder `commitment_with_proof` (from [`nym_commit`])
/// together with its own `messages`, mixing in `signer_nym_entropy`.
///
/// The commitment proof is verified first. `signer_nym_entropy` is added to the
/// `nym_generator` (the last blind generator) so the signed nym message becomes
/// `nym_secret = prover_nym + signer_nym_entropy`.
pub fn blind_sign_with_nym(
    sk: &SecretKey,
    pk: &PublicKey,
    commitment_with_proof: &[u8],
    signer_nym_entropy: Scalar,
    header: &[u8],
    messages: &[&[u8]],
    cs: Ciphersuite,
) -> Result<Signature> {
    let api_id = cs.pseudonym_api_id();
    let l = messages.len();
    let m = blind_message_count(commitment_with_proof.len(), cs)?;

    let generators = create_generators_with_api_id(l + 1, &api_id, cs)?;
    let blind_generators =
        create_generators_with_api_id(m + 1, &pseudonym_blind_generators_api_id(cs), cs)?;

    let commitment =
        deserialize_and_validate_commit(commitment_with_proof, &blind_generators, &api_id, cs)?;
    let message_scalars = messages_to_scalars_with_api_id(messages, &api_id, cs)?;

    // B = blind_B + nym_generator * signer_nym_entropy
    let mut b = blind_b_calculate(&generators, commitment, &message_scalars, cs)?;
    let nym_generator = blind_generators
        .last()
        .ok_or_else(|| BbsError::Crypto("missing nym generator".into()))?;
    b += nym_generator * signer_nym_entropy;
    if bool::from(b.is_identity()) {
        return Err(BbsError::InvalidSignature(
            "blind B with nym is identity".into(),
        ));
    }

    finalize_blind_sign(
        sk,
        pk,
        b,
        &generators,
        &blind_generators,
        header,
        &api_id,
        cs,
    )
}

/// Verify a nym blind signature over the full message set.
///
/// Reconstructs `nym_secret = prover_nym + signer_nym_entropy` and checks the
/// signature over generators `(Q_1, H_1…H_L, Q_2, J_1…J_M, J_nym)` and message
/// vector `(m_1…m_L, secret_prover_blind, cm_1…cm_M, nym_secret)`.
#[allow(clippy::too_many_arguments)]
pub fn blind_verify_with_nym(
    pk: &PublicKey,
    signature: &Signature,
    header: &[u8],
    messages: &[&[u8]],
    committed_messages: &[&[u8]],
    prover_nym: Scalar,
    signer_nym_entropy: Scalar,
    secret_prover_blind: Scalar,
    cs: Ciphersuite,
) -> Result<bool> {
    pk.validate()?;
    if bool::from(signature.a.is_identity()) {
        return Err(BbsError::InvalidSignature("A is identity".into()));
    }

    let api_id = cs.pseudonym_api_id();
    let nym_secret = prover_nym + signer_nym_entropy;

    let mut msg_scalars = messages_to_scalars_with_api_id(messages, &api_id, cs)?;
    let l = msg_scalars.len();

    // committed_message_scalars = (secret_prover_blind, cm_1…cm_M, nym_secret)
    let mut committed_scalars = Vec::with_capacity(committed_messages.len() + 2);
    committed_scalars.push(secret_prover_blind);
    committed_scalars.extend(messages_to_scalars_with_api_id(
        committed_messages,
        &api_id,
        cs,
    )?);
    committed_scalars.push(nym_secret);

    let generators = create_generators_with_api_id(l + 1, &api_id, cs)?;
    let blind_generators = create_generators_with_api_id(
        committed_scalars.len(),
        &pseudonym_blind_generators_api_id(cs),
        cs,
    )?;

    let mut all_gens = generators;
    all_gens.extend_from_slice(&blind_generators);
    let q1 = &all_gens[0];
    let h_generators = &all_gens[1..];

    msg_scalars.extend_from_slice(&committed_scalars);

    let domain = calculate_domain_with_api_id(pk, q1, h_generators, header, &api_id, cs)?;
    let b = compute_b(q1, &domain, h_generators, &msg_scalars);

    Ok(verify_signature_pairing(pk, signature, &b))
}

/// Generate a selective-disclosure proof over a nym blind signature, bound to a
/// per-verifier [`Pseudonym`] derived from `context_id`.
///
/// `nym_secret` is the holder secret (never disclosed). `messages` /
/// `committed_messages` are the full signer / committed sets;
/// `disclosed_indexes` / `disclosed_committed_indexes` select what to reveal.
/// Returns the proof and the pseudonym.
#[allow(clippy::too_many_arguments)]
pub fn proof_gen_with_nym(
    pk: &PublicKey,
    signature: &Signature,
    header: &[u8],
    presentation_header: &[u8],
    nym_secret: Scalar,
    context_id: &[u8],
    messages: &[&[u8]],
    disclosed_indexes: &[usize],
    committed_messages: &[&[u8]],
    disclosed_committed_indexes: &[usize],
    secret_prover_blind: Scalar,
    cs: Ciphersuite,
) -> Result<(Proof, Pseudonym)> {
    proof_gen_with_nym_impl(
        pk,
        signature,
        header,
        presentation_header,
        nym_secret,
        context_id,
        messages,
        disclosed_indexes,
        committed_messages,
        disclosed_committed_indexes,
        secret_prover_blind,
        None,
        cs,
    )
}

/// [`proof_gen_with_nym`] with injectable proof random scalars (for KATs).
#[allow(clippy::too_many_arguments)]
pub(crate) fn proof_gen_with_nym_impl(
    pk: &PublicKey,
    signature: &Signature,
    header: &[u8],
    presentation_header: &[u8],
    nym_secret: Scalar,
    context_id: &[u8],
    messages: &[&[u8]],
    disclosed_indexes: &[usize],
    committed_messages: &[&[u8]],
    disclosed_committed_indexes: &[usize],
    secret_prover_blind: Scalar,
    random_scalars: Option<ProofRandomScalars>,
    cs: Ciphersuite,
) -> Result<(Proof, Pseudonym)> {
    let api_id = cs.pseudonym_api_id();
    let l = messages.len();
    let m = committed_messages.len();
    if disclosed_indexes.iter().any(|&i| i >= l) {
        return Err(BbsError::InvalidIndex(
            "disclosed signer index out of range".into(),
        ));
    }
    if disclosed_committed_indexes.iter().any(|&j| j >= m) {
        return Err(BbsError::InvalidIndex(
            "disclosed committed index out of range".into(),
        ));
    }

    // Full message vector: [signer.., secret_prover_blind, committed.., nym_secret]
    let mut full_scalars = messages_to_scalars_with_api_id(messages, &api_id, cs)?;
    full_scalars.push(secret_prover_blind);
    full_scalars.extend(messages_to_scalars_with_api_id(
        committed_messages,
        &api_id,
        cs,
    )?);
    full_scalars.push(nym_secret);

    // Combined generators: [Q_1, H_1..H_L, Q_2, J_1..J_{M+1}]
    let generators = create_generators_with_api_id(l + 1, &api_id, cs)?;
    let blind_generators =
        create_generators_with_api_id(m + 2, &pseudonym_blind_generators_api_id(cs), cs)?;
    let mut all_gens = generators;
    all_gens.extend_from_slice(&blind_generators);

    // Disclosed indexes: committed j maps to (j + L + 1) (skipping spb at L).
    let mut indexes = disclosed_indexes.to_vec();
    for &j in disclosed_committed_indexes {
        indexes.push(j + l + 1);
    }

    let op = calculate_pseudonym_generator_with_api_id(context_id, &api_id);
    let domain =
        calculate_domain_with_api_id(pk, &all_gens[0], &all_gens[1..], header, &api_id, cs)?;

    let (proof, pseudonym) = proof_gen_core(
        signature,
        &all_gens[0],
        &all_gens[1..],
        &full_scalars,
        domain,
        presentation_header,
        &indexes,
        random_scalars,
        Some(op),
        &api_id,
        cs,
    )?;
    let pseudonym = pseudonym.ok_or_else(|| BbsError::Crypto("pseudonym not produced".into()))?;
    Ok((proof, Pseudonym(pseudonym)))
}

/// Verify a nym pseudonym proof. `l` is the signer message count `L` (the
/// committed count is recovered from the proof). `pseudonym` and `context_id`
/// must match generation.
#[allow(clippy::too_many_arguments)]
pub fn proof_verify_with_nym(
    pk: &PublicKey,
    proof: &Proof,
    header: &[u8],
    presentation_header: &[u8],
    pseudonym: &Pseudonym,
    context_id: &[u8],
    l: usize,
    disclosed_messages: &[&[u8]],
    disclosed_indexes: &[usize],
    disclosed_committed_messages: &[&[u8]],
    disclosed_committed_indexes: &[usize],
    cs: Ciphersuite,
) -> Result<bool> {
    let api_id = cs.pseudonym_api_id();

    // Recover M (= committed count + 1) from the proof's undisclosed count.
    let scalar_len = cs.octet_scalar_length();
    let point_len = cs.octet_point_length();
    let min_len = 3 * point_len + 4 * scalar_len;
    let plen = proof.to_bytes().len();
    if plen < min_len {
        return Err(BbsError::InvalidProof("proof too short".into()));
    }
    let u = (plen - min_len) / scalar_len;
    let total_no_messages = disclosed_indexes.len() + disclosed_committed_indexes.len() + u;
    let m = total_no_messages
        .checked_sub(l + 1)
        .ok_or_else(|| BbsError::InvalidProof("inconsistent message counts".into()))?;

    let generators = create_generators_with_api_id(l + 1, &api_id, cs)?;
    let blind_generators =
        create_generators_with_api_id(m + 1, &pseudonym_blind_generators_api_id(cs), cs)?;
    let mut all_gens = generators;
    all_gens.extend_from_slice(&blind_generators);

    let mut disclosed_scalars = messages_to_scalars_with_api_id(disclosed_messages, &api_id, cs)?;
    disclosed_scalars.extend(messages_to_scalars_with_api_id(
        disclosed_committed_messages,
        &api_id,
        cs,
    )?);

    let mut indexes = disclosed_indexes.to_vec();
    for &j in disclosed_committed_indexes {
        indexes.push(j + l + 1);
    }

    let op = calculate_pseudonym_generator_with_api_id(context_id, &api_id);
    let domain =
        calculate_domain_with_api_id(pk, &all_gens[0], &all_gens[1..], header, &api_id, cs)?;

    proof_verify_core(
        pk,
        proof,
        &all_gens[0],
        &all_gens[1..],
        &indexes,
        &disclosed_scalars,
        domain,
        presentation_header,
        Some((op, pseudonym.0)),
        &api_id,
        cs,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blind::mocked_calculate_random_scalars;
    use crate::hash::scalar_to_bytes;
    use serde_json::Value;

    fn hexd(s: &str) -> Vec<u8> {
        hex::decode(s).expect("fixture hex")
    }

    fn scalar(s: &str) -> Scalar {
        let b: [u8; 32] = hexd(s).try_into().unwrap();
        crate::hash::scalar_from_bytes(&b).unwrap()
    }

    fn fixture() -> Value {
        let path = format!(
            "{}/tests/fixtures/pseudonym/bls12-381-sha-256.json",
            env!("CARGO_MANIFEST_DIR")
        );
        let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
        serde_json::from_str(&text).expect("fixture json")
    }

    fn list_all(fx: &Value, key: &str) -> Vec<Vec<u8>> {
        fx[key]
            .as_array()
            .unwrap()
            .iter()
            .map(|m| hexd(m.as_str().unwrap()))
            .collect()
    }

    fn resolve<'a>(v: &Value, all: &'a [Vec<u8>]) -> Vec<&'a [u8]> {
        match v {
            Value::String(s) if s == "ALL" => all.iter().map(|m| m.as_slice()).collect(),
            Value::Array(a) => {
                assert!(a.is_empty(), "non-ALL arrays are empty in fixture");
                vec![]
            }
            _ => panic!("unexpected message field"),
        }
    }

    fn keys(fx: &Value) -> (SecretKey, PublicKey) {
        let sk: [u8; 32] = hexd(fx["SK"].as_str().unwrap()).try_into().unwrap();
        let pk: [u8; 96] = hexd(fx["PK"].as_str().unwrap()).try_into().unwrap();
        (
            SecretKey::from_bytes(&sk).unwrap(),
            PublicKey::from_bytes(&pk).unwrap(),
        )
    }

    #[test]
    fn nym_commit_matches_ietf_vectors() {
        let fx = fixture();
        let cs = Ciphersuite::Bls12381Sha256;
        let prover_nym = scalar(fx["prover_nym"].as_str().unwrap());
        let seed = hexd(fx["commit_mocked_random_scalars"]["seed"].as_str().unwrap());
        let dst = fx["commit_mocked_random_scalars"]["dst"]
            .as_str()
            .unwrap()
            .as_bytes();
        let committed_all = list_all(&fx, "committed_messages");

        for case in fx["nym_commit_cases"].as_array().unwrap() {
            let name = case["name"].as_str().unwrap();
            let committed = resolve(&case["committed_messages"], &committed_all);
            // committed_message_scalars = committed + prover_nym → CoreCommit count = (len+1)+2
            let count = committed.len() + 1 + 2;
            let randoms = mocked_calculate_random_scalars(count, &seed, dst, cs).unwrap();
            let (cwp, spb) =
                nym_commit_with_random_scalars(prover_nym, &committed, &randoms, cs).unwrap();

            assert_eq!(
                hex::encode(&cwp),
                case["commitment_with_proof"].as_str().unwrap(),
                "commitment_with_proof mismatch ({name})"
            );
            assert_eq!(
                hex::encode(scalar_to_bytes(&spb)),
                case["secret_prover_blind"].as_str().unwrap(),
                "secret_prover_blind mismatch ({name})"
            );
        }
    }

    #[test]
    fn blind_sign_and_verify_with_nym_match_ietf_vectors() {
        let fx = fixture();
        let cs = Ciphersuite::Bls12381Sha256;
        let (sk, pk) = keys(&fx);
        let header = hexd(fx["header"].as_str().unwrap());
        let prover_nym = scalar(fx["prover_nym"].as_str().unwrap());
        let signer_nym_entropy = scalar(fx["signer_nym_entropy"].as_str().unwrap());
        let messages_all = list_all(&fx, "messages");
        let committed_all = list_all(&fx, "committed_messages");

        for case in fx["blind_sign_cases"].as_array().unwrap() {
            let name = case["name"].as_str().unwrap();
            let cwp = hexd(case["commitment_with_proof"].as_str().unwrap());
            let messages = resolve(&case["messages"], &messages_all);
            let committed = resolve(&case["committed_messages"], &committed_all);
            let spb = scalar(case["secret_prover_blind"].as_str().unwrap());

            let sig =
                blind_sign_with_nym(&sk, &pk, &cwp, signer_nym_entropy, &header, &messages, cs)
                    .unwrap();
            assert_eq!(
                hex::encode(sig.to_bytes()),
                case["signature"].as_str().unwrap(),
                "nym blind signature mismatch ({name})"
            );

            assert!(
                blind_verify_with_nym(
                    &pk,
                    &sig,
                    &header,
                    &messages,
                    &committed,
                    prover_nym,
                    signer_nym_entropy,
                    spb,
                    cs
                )
                .unwrap(),
                "blind_verify_with_nym rejected a valid signature ({name})"
            );
        }
    }

    #[test]
    fn nym_secret_is_prover_plus_signer_entropy() {
        let fx = fixture();
        let prover_nym = scalar(fx["prover_nym"].as_str().unwrap());
        let signer_nym_entropy = scalar(fx["signer_nym_entropy"].as_str().unwrap());
        let nym_secret = scalar(fx["nym_secret"].as_str().unwrap());
        assert_eq!(prover_nym + signer_nym_entropy, nym_secret);
    }

    #[test]
    fn nym_roundtrip_random() {
        let fx = fixture();
        let cs = Ciphersuite::Bls12381Sha256;
        let (sk, pk) = keys(&fx);
        let prover_nym = scalar(fx["prover_nym"].as_str().unwrap());
        let signer_nym_entropy = scalar(fx["signer_nym_entropy"].as_str().unwrap());
        let committed: Vec<&[u8]> = vec![b"holder-secret".as_ref()];
        let signer: Vec<&[u8]> = vec![b"role:member".as_ref()];

        let (cwp, spb) = nym_commit(prover_nym, &committed, cs).unwrap();
        let sig =
            blind_sign_with_nym(&sk, &pk, &cwp, signer_nym_entropy, b"hdr", &signer, cs).unwrap();
        assert!(
            blind_verify_with_nym(
                &pk,
                &sig,
                b"hdr",
                &signer,
                &committed,
                prover_nym,
                signer_nym_entropy,
                spb,
                cs
            )
            .unwrap()
        );
        // wrong signer entropy → wrong nym_secret → reject
        assert!(
            !blind_verify_with_nym(
                &pk,
                &sig,
                b"hdr",
                &signer,
                &committed,
                prover_nym,
                signer_nym_entropy + Scalar::ONE,
                spb,
                cs
            )
            .unwrap()
        );
    }

    #[test]
    fn proof_gen_verify_with_nym_match_ietf_vectors() {
        let fx = fixture();
        let cs = Ciphersuite::Bls12381Sha256;
        let (_sk, pk) = keys(&fx);
        let header = hexd(fx["header"].as_str().unwrap());
        let ph = hexd(fx["ph"].as_str().unwrap());
        let context_id = hexd(fx["context_id"].as_str().unwrap());
        let exp_pseudonym = fx["pseudonym"].as_str().unwrap();
        let nym_secret = scalar(fx["nym_secret"].as_str().unwrap());
        let spb = scalar(fx["proof_secret_prover_blind"].as_str().unwrap());
        let sig = Signature::from_bytes(&hexd(fx["proof_signature"].as_str().unwrap())).unwrap();
        let seed = hexd(fx["proof_mocked_random_scalars"]["seed"].as_str().unwrap());
        let dst = fx["proof_mocked_random_scalars"]["dst"]
            .as_str()
            .unwrap()
            .as_bytes();

        let messages = list_all(&fx, "messages");
        let committed = list_all(&fx, "committed_messages");
        let msg_refs: Vec<&[u8]> = messages.iter().map(|m| m.as_slice()).collect();
        let com_refs: Vec<&[u8]> = committed.iter().map(|m| m.as_slice()).collect();
        let l = msg_refs.len();
        let total = l + com_refs.len() + 2; // signer + spb + committed + nym

        for case in fx["proof_cases"].as_array().unwrap() {
            let name = case["name"].as_str().unwrap();
            let di: Vec<usize> = case["disclosed_indexes"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_u64().unwrap() as usize)
                .collect();
            let dci: Vec<usize> = case["disclosed_committed_indexes"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_u64().unwrap() as usize)
                .collect();

            let r = di.len() + dci.len();
            let u = total - r;
            let randoms = mocked_calculate_random_scalars(5 + u, &seed, dst, cs).unwrap();
            let rs = ProofRandomScalars::from_slice(&randoms);

            let (proof, pseudonym) = proof_gen_with_nym_impl(
                &pk,
                &sig,
                &header,
                &ph,
                nym_secret,
                &context_id,
                &msg_refs,
                &di,
                &com_refs,
                &dci,
                spb,
                Some(rs),
                cs,
            )
            .unwrap();

            assert_eq!(
                hex::encode(proof.to_bytes()),
                case["proof"].as_str().unwrap(),
                "nym proof mismatch ({name})"
            );
            assert_eq!(
                hex::encode(pseudonym.to_bytes()),
                exp_pseudonym,
                "pseudonym mismatch ({name})"
            );

            // Verify with only the disclosed messages.
            let disc_msgs: Vec<&[u8]> = di.iter().map(|&i| msg_refs[i]).collect();
            let disc_com: Vec<&[u8]> = dci.iter().map(|&j| com_refs[j]).collect();
            assert!(
                proof_verify_with_nym(
                    &pk,
                    &proof,
                    &header,
                    &ph,
                    &pseudonym,
                    &context_id,
                    l,
                    &disc_msgs,
                    &di,
                    &disc_com,
                    &dci,
                    cs,
                )
                .unwrap(),
                "nym proof verify failed ({name})"
            );
        }
    }
}

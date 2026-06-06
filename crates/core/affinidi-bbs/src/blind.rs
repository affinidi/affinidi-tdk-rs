/*!
 * Blind BBS signatures (`draft-irtf-cfrg-bbs-blind-signatures`).
 *
 * Blind issuance lets a holder commit to *hidden* messages that the issuer
 * never learns, while the issuer signs over that commitment together with its
 * own (cleartext) messages. The resulting signature is an ordinary BBS
 * signature over the combined message set, so it verifies and proves exactly
 * like a plain BBS signature.
 *
 * This is the foundation for holder binding / per-verifier pseudonyms
 * (`#353` / `#360`): the holder's `nym_secret` is a committed message.
 *
 * # Flow
 *
 * 1. **Holder** runs [`commit`] over its committed messages →
 *    `(commitment_with_proof, secret_prover_blind)`. The `commitment_with_proof`
 *    is sent to the issuer; `secret_prover_blind` is kept secret.
 * 2. **Issuer** runs [`blind_sign`] over the `commitment_with_proof` and its own
 *    messages → a blind [`Signature`]. The commitment proof is verified first so
 *    a malformed commitment is rejected.
 * 3. **Holder** runs [`blind_verify`] (with the committed messages and
 *    `secret_prover_blind`) to confirm the signature is valid over the full
 *    message set.
 *
 * # Ciphersuite namespacing
 *
 * Blind BBS uses [`Ciphersuite::blind_api_id`] (`…_BLIND_H2G_HM2S_`) for its
 * signer generators and hashing, and `"BLIND_" || blind_api_id` for the blind
 * (committed-message) generators. These are distinct from the core api_id, so a
 * blind signature uses a different generator set than a plain one.
 *
 * Construction matches the reference `@digitalbazaar/bbs-signatures`; all
 * primitives are KAT-gated byte-for-byte against the official IETF
 * blind-signatures draft test vectors.
 */

use bls12_381_plus::{G1Projective, Scalar};
use ff::Field;
use rand::Rng;
use zeroize::Zeroize;

use crate::ciphersuite::Ciphersuite;
use crate::error::{BbsError, Result};
use crate::generators::{
    calculate_domain_with_api_id, create_generators_with_api_id, p1_generator, point_from_bytes,
    point_to_bytes,
};
use crate::hash::{
    hash_to_scalar, messages_to_scalars_with_api_id, scalar_from_bytes, scalar_to_bytes,
};
use crate::types::{PublicKey, SecretKey, Signature};

/// The api_id used for the blind (committed-message) generators:
/// `"BLIND_" || blind_api_id`.
pub(crate) fn blind_generators_api_id(cs: Ciphersuite) -> Vec<u8> {
    [b"BLIND_".as_slice(), cs.blind_api_id().as_slice()].concat()
}

/// Commit to a set of hidden (committed) messages.
///
/// Returns `(commitment_with_proof, secret_prover_blind)`. The
/// `commitment_with_proof` octets are handed to the issuer (see [`blind_sign`]);
/// `secret_prover_blind` is retained by the holder and is required to verify
/// (and later prove over) the resulting blind signature.
///
/// Random scalars are sampled fresh; the commitment is therefore not
/// reproducible (each call yields a different, equally valid commitment).
pub fn commit(committed_messages: &[&[u8]], cs: Ciphersuite) -> Result<(Vec<u8>, Scalar)> {
    let m = committed_messages.len();
    let random_scalars = random_scalars(m + 2);
    commit_with_random_scalars(committed_messages, &random_scalars, cs)
}

/// [`commit`] with the random scalars injected — used to reproduce the
/// deterministic IETF test vectors exactly. `random_scalars` must have length
/// `committed_messages.len() + 2`: `(secret_prover_blind, s~, m~_1, …, m~_M)`.
pub(crate) fn commit_with_random_scalars(
    committed_messages: &[&[u8]],
    random_scalars: &[Scalar],
    cs: Ciphersuite,
) -> Result<(Vec<u8>, Scalar)> {
    let m = committed_messages.len();
    if random_scalars.len() != m + 2 {
        return Err(BbsError::Crypto(format!(
            "blind commit needs {} random scalars, got {}",
            m + 2,
            random_scalars.len()
        )));
    }

    let api_id = cs.blind_api_id();
    let committed_scalars = messages_to_scalars_with_api_id(committed_messages, &api_id, cs)?;
    // blind_generators = (Q_2, J_1, …, J_M), length M + 1
    let blind_generators = create_generators_with_api_id(m + 1, &blind_generators_api_id(cs), cs)?;

    core_commit(
        &committed_scalars,
        &blind_generators,
        &api_id,
        random_scalars,
        cs,
    )
}

/// `CoreCommit`: build the commitment `C` to the committed message scalars and a
/// zero-knowledge proof of its correct construction.
pub(crate) fn core_commit(
    committed_scalars: &[Scalar],
    blind_generators: &[G1Projective],
    api_id: &[u8],
    random_scalars: &[Scalar],
    cs: Ciphersuite,
) -> Result<(Vec<u8>, Scalar)> {
    let m = committed_scalars.len();
    if blind_generators.len() != m + 1 {
        return Err(BbsError::Crypto(
            "blind_generators length must be committed message count + 1".into(),
        ));
    }
    let q2 = &blind_generators[0];
    let j = &blind_generators[1..];

    let secret_prover_blind = random_scalars[0];
    let s_tilde = random_scalars[1];
    let m_tildes = &random_scalars[2..];

    // C = Q_2 * secret_prover_blind + sum_i J_i * msg_i
    let mut c = q2 * secret_prover_blind;
    for (i, msg) in committed_scalars.iter().enumerate() {
        c += j[i] * msg;
    }

    // Cbar = Q_2 * s~ + sum_i J_i * m~_i
    let mut cbar = q2 * s_tilde;
    for (i, mt) in m_tildes.iter().enumerate() {
        cbar += j[i] * mt;
    }

    // challenge = calculate_blind_challenge(C, Cbar, blind_generators, api_id)
    let challenge = calculate_blind_challenge(&c, &cbar, blind_generators, api_id, cs)?;

    // s^ = s~ + secret_prover_blind * challenge
    let s_hat = s_tilde + secret_prover_blind * challenge;
    // m^_i = m~_i + msg_i * challenge
    let m_hats: Vec<Scalar> = m_tildes
        .iter()
        .zip(committed_scalars.iter())
        .map(|(mt, msg)| mt + msg * challenge)
        .collect();

    // proof = (s^, m^_1, …, m^_M, challenge)
    let mut proof = Vec::with_capacity(m + 2);
    proof.push(s_hat);
    proof.extend_from_slice(&m_hats);
    proof.push(challenge);

    let octets = commitment_with_proof_to_octets(&c, &proof);
    Ok((octets, secret_prover_blind))
}

/// `calculate_blind_challenge`: Fiat–Shamir challenge over the blind generators
/// and the commitment points. Serializes `(M, Q_2, J_1…J_M, C, Cbar)` and hashes
/// to a scalar under `api_id || "H2S_"`.
fn calculate_blind_challenge(
    c: &G1Projective,
    cbar: &G1Projective,
    blind_generators: &[G1Projective],
    api_id: &[u8],
    cs: Ciphersuite,
) -> Result<Scalar> {
    let dst = [api_id, b"H2S_"].concat();
    let m = blind_generators.len() - 1;

    let mut data = Vec::new();
    data.extend_from_slice(&(m as u64).to_be_bytes()); // I2OSP(M, 8)
    for g in blind_generators {
        data.extend_from_slice(&point_to_bytes(g));
    }
    data.extend_from_slice(&point_to_bytes(c));
    data.extend_from_slice(&point_to_bytes(cbar));

    hash_to_scalar(&data, &dst, cs)
}

/// Serialize `commitment_with_proof = serialize(C) || serialize(proof scalars)`.
fn commitment_with_proof_to_octets(commitment: &G1Projective, proof: &[Scalar]) -> Vec<u8> {
    let mut out = Vec::with_capacity(48 + proof.len() * 32);
    out.extend_from_slice(&point_to_bytes(commitment));
    for s in proof {
        out.extend_from_slice(&scalar_to_bytes(s));
    }
    out
}

/// Parse `commitment_with_proof` octets back into `(C, proof scalars)`.
///
/// Rejects an identity commitment, zero/out-of-range scalars, a trailing partial
/// scalar, and proofs with fewer than two scalars (per the draft).
fn octets_to_commitment_with_proof(
    bytes: &[u8],
    cs: Ciphersuite,
) -> Result<(G1Projective, Vec<Scalar>)> {
    let point_len = cs.octet_point_length();
    let scalar_len = cs.octet_scalar_length();
    let floor = point_len + 2 * scalar_len;
    if bytes.len() < floor {
        return Err(BbsError::Deserialization(format!(
            "commitment_with_proof too short: {} < {floor}",
            bytes.len()
        )));
    }

    let mut c_bytes = [0u8; 48];
    c_bytes.copy_from_slice(&bytes[..point_len]);
    let commitment = point_from_bytes(&c_bytes)
        .ok_or_else(|| BbsError::Deserialization("invalid commitment point".into()))?;
    if bool::from(commitment.is_identity()) {
        return Err(BbsError::Deserialization("commitment is identity".into()));
    }

    let mut proof = Vec::new();
    let mut idx = point_len;
    while idx + scalar_len <= bytes.len() {
        let mut s_bytes = [0u8; 32];
        s_bytes.copy_from_slice(&bytes[idx..idx + scalar_len]);
        let s = scalar_from_bytes(&s_bytes).ok_or_else(|| {
            BbsError::Deserialization("invalid scalar in commitment proof".into())
        })?;
        if bool::from(s.is_zero()) {
            return Err(BbsError::Deserialization(
                "zero scalar in commitment proof".into(),
            ));
        }
        proof.push(s);
        idx += scalar_len;
    }
    if idx != bytes.len() {
        return Err(BbsError::Deserialization(
            "trailing bytes in commitment proof".into(),
        ));
    }
    if proof.len() < 2 {
        return Err(BbsError::Deserialization(
            "commitment proof must have at least two scalars".into(),
        ));
    }

    Ok((commitment, proof))
}

/// `CoreCommitVerify`: check the commitment proof. `commitment_proof` is
/// `(s^, m^_1, …, m^_M, cp)`; recomputes `Cbar` and confirms the challenge.
fn core_commit_verify(
    commitment: &G1Projective,
    commitment_proof: &[Scalar],
    blind_generators: &[G1Projective],
    api_id: &[u8],
    cs: Ciphersuite,
) -> Result<bool> {
    // (s^, m^_1..m^_M, cp)
    let s_hat = commitment_proof[0];
    let cp = commitment_proof[commitment_proof.len() - 1];
    let m_hats = &commitment_proof[1..commitment_proof.len() - 1];

    let m = m_hats.len();
    if blind_generators.len() != m + 1 {
        return Err(BbsError::Crypto(
            "blind_generators length must equal commitment message count + 1".into(),
        ));
    }
    let q2 = &blind_generators[0];
    let j = &blind_generators[1..];

    // Cbar = Q_2 * s^ + sum_i J_i * m^_i - commitment * cp
    let mut cbar = q2 * s_hat;
    for (i, mh) in m_hats.iter().enumerate() {
        cbar += j[i] * mh;
    }
    cbar -= commitment * cp;

    let cv = calculate_blind_challenge(commitment, &cbar, blind_generators, api_id, cs)?;
    Ok(cv == cp)
}

/// Parse and verify a `commitment_with_proof` from the holder, returning the
/// commitment point `C`. An empty input means "no committed messages" and yields
/// the identity element. A failed proof or generator-count mismatch is rejected.
pub(crate) fn deserialize_and_validate_commit(
    commitment_with_proof: &[u8],
    blind_generators: &[G1Projective],
    api_id: &[u8],
    cs: Ciphersuite,
) -> Result<G1Projective> {
    if commitment_with_proof.is_empty() {
        return Ok(G1Projective::IDENTITY);
    }

    let (commitment, proof) = octets_to_commitment_with_proof(commitment_with_proof, cs)?;

    // (number of message commitments) + 1 must equal the blind generator count.
    let msg_commitments = proof.len() - 2;
    if msg_commitments + 1 != blind_generators.len() {
        return Err(BbsError::Deserialization(format!(
            "commitment message count ({msg_commitments}) + 1 != blind generators ({})",
            blind_generators.len()
        )));
    }

    if !core_commit_verify(&commitment, &proof, blind_generators, api_id, cs)? {
        return Err(BbsError::InvalidProof("commitment proof failed".into()));
    }
    Ok(commitment)
}

/// `B_calculate` for blind signing: `B = P1 + sum_i H_i * msg_i + commitment`.
///
/// Note `Q_1 * domain` is folded in later by [`finalize_blind_sign`].
pub(crate) fn blind_b_calculate(
    generators: &[G1Projective],
    commitment: G1Projective,
    message_scalars: &[Scalar],
    cs: Ciphersuite,
) -> Result<G1Projective> {
    let l = message_scalars.len();
    if generators.len() != l + 1 {
        return Err(BbsError::Crypto(
            "generators length must equal signer message count + 1".into(),
        ));
    }
    let h = &generators[1..]; // H_1..H_L (Q_1 = generators[0] used for domain)

    let mut b = p1_generator();
    for (i, msg) in message_scalars.iter().enumerate() {
        b += h[i] * msg;
    }
    b += commitment;

    let _ = cs;
    if bool::from(b.is_identity()) {
        return Err(BbsError::InvalidSignature("blind B is identity".into()));
    }
    Ok(b)
}

/// `FinalizeBlindSign`: turn `B` into a BBS signature `(A, e)` over the combined
/// signer + blind generators. Per the draft fix, `Q_1 * domain` is mixed into
/// `B` here and `e = hash_to_scalar(serialize(SK, B), api_id || "H2S_")`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn finalize_blind_sign(
    sk: &SecretKey,
    pk: &PublicKey,
    b: G1Projective,
    generators: &[G1Projective],
    blind_generators: &[G1Projective],
    header: &[u8],
    api_id: &[u8],
    cs: Ciphersuite,
) -> Result<Signature> {
    let q1 = &generators[0];

    // domain over (H_1..H_L, Q_2, J_1..J_M) with Q_1 as the domain generator.
    let mut h_list: Vec<G1Projective> = generators[1..].to_vec();
    h_list.extend_from_slice(blind_generators);
    let domain = calculate_domain_with_api_id(pk, q1, &h_list, header, api_id, cs)?;

    // B += Q_1 * domain
    let b = b + q1 * domain;

    // e = hash_to_scalar(serialize(SK, B), api_id || "H2S_")
    let e_dst = [api_id, b"H2S_"].concat();
    let mut e_input = Vec::with_capacity(32 + 48);
    e_input.extend_from_slice(&sk.scalar().to_be_bytes());
    e_input.extend_from_slice(&point_to_bytes(&b));
    let e = hash_to_scalar(&e_input, &e_dst, cs)?;
    e_input.zeroize();

    // A = B * (1 / (SK + e))
    let mut sk_plus_e = sk.scalar() + e;
    let inv = sk_plus_e.invert();
    sk_plus_e.zeroize();
    if inv.is_none().into() {
        return Err(BbsError::Crypto("SK + e has no inverse".into()));
    }
    let a = b * inv.unwrap();
    if bool::from(a.is_identity()) {
        return Err(BbsError::InvalidSignature(
            "blind signature A is identity".into(),
        ));
    }
    Ok(Signature { a, e })
}

/// Blind-sign a holder commitment together with the issuer's own messages.
///
/// `commitment_with_proof` is the holder's output from [`commit`] (empty for no
/// committed messages); `messages` are the issuer's cleartext messages. The
/// commitment proof is verified before signing. Returns a BBS [`Signature`] over
/// the combined message set, which the holder checks with [`blind_verify`].
pub fn blind_sign(
    sk: &SecretKey,
    pk: &PublicKey,
    commitment_with_proof: &[u8],
    header: &[u8],
    messages: &[&[u8]],
    cs: Ciphersuite,
) -> Result<Signature> {
    let api_id = cs.blind_api_id();
    let l = messages.len();
    let m = blind_message_count(commitment_with_proof.len(), cs)?;

    // generators = (Q_1, H_1..H_L); blind_generators = (Q_2, J_1..J_M)
    let generators = create_generators_with_api_id(l + 1, &api_id, cs)?;
    let blind_generators = create_generators_with_api_id(m + 1, &blind_generators_api_id(cs), cs)?;

    let commitment =
        deserialize_and_validate_commit(commitment_with_proof, &blind_generators, &api_id, cs)?;
    let message_scalars = messages_to_scalars_with_api_id(messages, &api_id, cs)?;
    let b = blind_b_calculate(&generators, commitment, &message_scalars, cs)?;

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

/// Verify a blind signature over the full message set.
///
/// The holder supplies the issuer's `messages`, its own `committed_messages`,
/// and the `secret_prover_blind` from [`commit`]. The signature is checked over
/// the combined generators `(Q_1, H_1…H_L, Q_2, J_1…J_M)` and the message vector
/// `(m_1…m_L, secret_prover_blind, cm_1…cm_M)`.
pub fn blind_verify(
    pk: &PublicKey,
    signature: &Signature,
    header: &[u8],
    messages: &[&[u8]],
    committed_messages: &[&[u8]],
    secret_prover_blind: Scalar,
    cs: Ciphersuite,
) -> Result<bool> {
    pk.validate()?;
    if bool::from(signature.a.is_identity()) {
        return Err(BbsError::InvalidSignature("A is identity".into()));
    }

    let api_id = cs.blind_api_id();

    // message_scalars (signer) and committed_message_scalars = (spb, cm_1…cm_M)
    let mut msg_scalars = messages_to_scalars_with_api_id(messages, &api_id, cs)?;
    let l = msg_scalars.len();
    let mut committed_scalars = Vec::with_capacity(committed_messages.len() + 1);
    committed_scalars.push(secret_prover_blind);
    committed_scalars.extend(messages_to_scalars_with_api_id(
        committed_messages,
        &api_id,
        cs,
    )?);

    // generators (Q_1, H_1…H_L) and blind_generators (Q_2, J_1…J_M)
    let generators = create_generators_with_api_id(l + 1, &api_id, cs)?;
    let blind_generators =
        create_generators_with_api_id(committed_scalars.len(), &blind_generators_api_id(cs), cs)?;

    // Combined generator list and combined message-scalar vector.
    let mut all_gens = generators;
    all_gens.extend_from_slice(&blind_generators);
    let q1 = &all_gens[0];
    let h_generators = &all_gens[1..];

    msg_scalars.extend_from_slice(&committed_scalars);

    let domain = calculate_domain_with_api_id(pk, q1, h_generators, header, &api_id, cs)?;
    let b = crate::signature::compute_b(q1, &domain, h_generators, &msg_scalars);

    Ok(crate::signature::verify_signature_pairing(
        pk, signature, &b,
    ))
}

/// Recover the committed-message count `M` from the length of a
/// `commitment_with_proof` (length `0` ⇒ no committed messages, `M = 0`).
pub(crate) fn blind_message_count(cwp_len: usize, cs: Ciphersuite) -> Result<usize> {
    if cwp_len == 0 {
        return Ok(0);
    }
    let point_len = cs.octet_point_length();
    let scalar_len = cs.octet_scalar_length();
    let floor = point_len + 2 * scalar_len;
    if cwp_len < floor || !(cwp_len - floor).is_multiple_of(scalar_len) {
        return Err(BbsError::Deserialization(format!(
            "invalid commitment_with_proof length {cwp_len}"
        )));
    }
    Ok((cwp_len - floor) / scalar_len)
}

/// Sample `count` non-zero random scalars (production path for [`commit`]).
pub(crate) fn random_scalars(count: usize) -> Vec<Scalar> {
    let mut rng = rand::rng();
    (0..count)
        .map(|_| {
            loop {
                let bytes: [u8; 48] = rng.random();
                let s = Scalar::from_okm(&bytes);
                if !bool::from(s.is_zero()) {
                    return s;
                }
            }
        })
        .collect()
}

/// Deterministic mocked random scalars per the IETF draft (`expand_message` over
/// a fixed seed), used only to reproduce the published test vectors.
#[cfg(test)]
pub(crate) fn mocked_calculate_random_scalars(
    count: usize,
    seed: &[u8],
    dst: &[u8],
    cs: Ciphersuite,
) -> Result<Vec<Scalar>> {
    let expand_len = cs.expand_len();
    let v = crate::hash::expand_msg_xmd(seed, dst, expand_len * count)?;
    Ok((0..count)
        .map(|i| crate::hash::os2ip_mod_r(&v[i * expand_len..(i + 1) * expand_len]))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn hexd(s: &str) -> Vec<u8> {
        hex::decode(s).expect("fixture hex")
    }

    fn fixture() -> Value {
        let path = format!(
            "{}/tests/fixtures/blind/bls12-381-sha-256.json",
            env!("CARGO_MANIFEST_DIR")
        );
        let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
        serde_json::from_str(&text).expect("fixture json")
    }

    /// Resolve a fixture message list that is either an explicit array or the
    /// sentinel `"ALL"` (the full `committed_messages` / `messages` set).
    fn resolve<'a>(v: &Value, all: &'a [Vec<u8>]) -> Vec<&'a [u8]> {
        match v {
            Value::String(s) if s == "ALL" => all.iter().map(|m| m.as_slice()).collect(),
            Value::Array(_) => {
                assert!(
                    v.as_array().unwrap().is_empty(),
                    "non-ALL arrays are empty in fixture"
                );
                vec![]
            }
            _ => panic!("unexpected message field"),
        }
    }

    fn list_all(fx: &Value, key: &str) -> Vec<Vec<u8>> {
        fx[key]
            .as_array()
            .unwrap()
            .iter()
            .map(|m| hexd(m.as_str().unwrap()))
            .collect()
    }

    fn committed_all(fx: &Value) -> Vec<Vec<u8>> {
        list_all(fx, "committed_messages")
    }

    fn keys(fx: &Value) -> (SecretKey, PublicKey) {
        let sk_bytes: [u8; 32] = hexd(fx["SK"].as_str().unwrap()).try_into().unwrap();
        let pk_bytes: [u8; 96] = hexd(fx["PK"].as_str().unwrap()).try_into().unwrap();
        (
            SecretKey::from_bytes(&sk_bytes).unwrap(),
            PublicKey::from_bytes(&pk_bytes).unwrap(),
        )
    }

    #[test]
    fn commit_matches_ietf_vectors() {
        let fx = fixture();
        let cs = Ciphersuite::Bls12381Sha256;
        let seed = hexd(fx["mocked_random_scalars"]["seed"].as_str().unwrap());
        let commit_dst = fx["mocked_random_scalars"]["commit_dst"]
            .as_str()
            .unwrap()
            .as_bytes();
        let all = committed_all(&fx);

        for case in fx["commit_cases"].as_array().unwrap() {
            let name = case["name"].as_str().unwrap();
            let committed = resolve(&case["committed_messages"], &all);
            let m = committed.len();

            let randoms = mocked_calculate_random_scalars(m + 2, &seed, commit_dst, cs).unwrap();
            let (cwp, spb) = commit_with_random_scalars(&committed, &randoms, cs).unwrap();

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

            // The freshly serialized commitment must round-trip back to a valid
            // commitment + proof of the right arity.
            let (_c, proof) = octets_to_commitment_with_proof(&cwp, cs).unwrap();
            assert_eq!(proof.len(), m + 2, "proof arity ({name})");
        }
    }

    #[test]
    fn blind_sign_matches_ietf_vectors() {
        let fx = fixture();
        let cs = Ciphersuite::Bls12381Sha256;
        let (sk, pk) = keys(&fx);
        let header = hexd(fx["header"].as_str().unwrap());
        let messages_all = list_all(&fx, "messages");

        for case in fx["blind_sign_cases"].as_array().unwrap() {
            let name = case["name"].as_str().unwrap();
            let cwp = hexd(case["commitment_with_proof"].as_str().unwrap());
            let messages = resolve(&case["messages"], &messages_all);

            let sig = blind_sign(&sk, &pk, &cwp, &header, &messages, cs).unwrap();

            assert_eq!(
                hex::encode(sig.to_bytes()),
                case["signature"].as_str().unwrap(),
                "blind signature mismatch ({name})"
            );
        }
    }

    #[test]
    fn blind_verify_accepts_ietf_signatures() {
        let fx = fixture();
        let cs = Ciphersuite::Bls12381Sha256;
        let (_sk, pk) = keys(&fx);
        let header = hexd(fx["header"].as_str().unwrap());
        let messages_all = list_all(&fx, "messages");
        let committed_all = committed_all(&fx);

        for case in fx["blind_sign_cases"].as_array().unwrap() {
            let name = case["name"].as_str().unwrap();
            let messages = resolve(&case["messages"], &messages_all);
            let committed = resolve(&case["committed_messages"], &committed_all);
            let spb = {
                let b: [u8; 32] = hexd(case["secret_prover_blind"].as_str().unwrap())
                    .try_into()
                    .unwrap();
                scalar_from_bytes(&b).unwrap()
            };
            let sig = Signature::from_bytes(&hexd(case["signature"].as_str().unwrap())).unwrap();

            assert!(
                blind_verify(&pk, &sig, &header, &messages, &committed, spb, cs).unwrap(),
                "blind_verify rejected a valid IETF signature ({name})"
            );
        }
    }

    #[test]
    fn blind_roundtrip_and_tamper_rejection() {
        let cs = Ciphersuite::Bls12381Sha256;
        let fx = fixture();
        let (sk, pk) = keys(&fx);
        let header = b"app-header";

        let committed_owned = committed_all(&fx);
        let committed: Vec<&[u8]> = committed_owned.iter().map(|m| m.as_slice()).collect();
        let signer: Vec<&[u8]> = vec![b"role:issuer".as_ref(), b"level:gold"];

        // Holder commits (fresh random scalars), issuer blind-signs, holder verifies.
        let (cwp, spb) = commit(&committed, cs).unwrap();
        let sig = blind_sign(&sk, &pk, &cwp, header, &signer, cs).unwrap();
        assert!(blind_verify(&pk, &sig, header, &signer, &committed, spb, cs).unwrap());

        // Wrong secret_prover_blind is rejected.
        assert!(
            !blind_verify(
                &pk,
                &sig,
                header,
                &signer,
                &committed,
                spb + Scalar::ONE,
                cs
            )
            .unwrap()
        );

        // Tampered signer message is rejected.
        let bad_signer: Vec<&[u8]> = vec![b"role:issuer".as_ref(), b"level:platinum"];
        assert!(!blind_verify(&pk, &sig, header, &bad_signer, &committed, spb, cs).unwrap());

        // Tampered committed message is rejected.
        let mut bad_committed = committed.clone();
        bad_committed[0] = b"forged";
        assert!(!blind_verify(&pk, &sig, header, &signer, &bad_committed, spb, cs).unwrap());

        // A different holder commitment yields a different (still valid) signature.
        let (cwp2, spb2) = commit(&committed, cs).unwrap();
        assert_ne!(cwp, cwp2, "commitments must be randomized");
        let sig2 = blind_sign(&sk, &pk, &cwp2, header, &signer, cs).unwrap();
        assert!(blind_verify(&pk, &sig2, header, &signer, &committed, spb2, cs).unwrap());
    }

    #[test]
    fn blind_sign_rejects_malformed_commitment() {
        let cs = Ciphersuite::Bls12381Sha256;
        let fx = fixture();
        let (sk, pk) = keys(&fx);
        // Valid-length commitment_with_proof but corrupted proof scalar → the
        // commitment proof must fail to verify.
        let mut cwp = hexd(
            fx["commit_cases"][1]["commitment_with_proof"]
                .as_str()
                .unwrap(),
        );
        let n = cwp.len();
        cwp[n - 1] ^= 0x01;
        let committed = committed_all(&fx);
        let signer: Vec<&[u8]> = committed.iter().map(|m| m.as_slice()).collect();
        assert!(blind_sign(&sk, &pk, &cwp, b"h", &signer, cs).is_err());
    }
}

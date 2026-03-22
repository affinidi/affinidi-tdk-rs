/*!
 * BBS-2023 Data Integrity Cryptosuite.
 *
 * Implements the [W3C VC Data Integrity BBS Cryptosuites](https://www.w3.org/TR/vc-di-bbs/)
 * specification for zero-knowledge selective disclosure of Verifiable Credentials.
 *
 * # Overview
 *
 * The bbs-2023 cryptosuite uses BBS signatures over BLS12-381 to enable:
 * - **Base proof creation** (issuer): Sign a VC with selective disclosure capabilities
 * - **Derived proof creation** (holder): Create a ZK proof revealing only chosen claims
 * - **Proof verification** (verifier): Verify the ZK proof without seeing hidden claims
 *
 * # Flow
 *
 * ```text
 * Issuer: sign_base(document, mandatory_pointers, sk, pk) → base_proof
 * Holder: derive_proof(base_document, selective_pointers, ph) → derived_proof
 * Verifier: verify_proof(derived_document, pk) → bool
 * ```
 *
 * # eIDAS 2.0
 *
 * Addresses ARF ZKP requirements ZKP_01 through ZKP_06 for unlinkable
 * selective disclosure of PID and QEAA attributes.
 */

use affinidi_bbs::{self as bbs, Ciphersuite, PublicKey, SecretKey, Signature};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::DataIntegrityError;

/// Sign a document's claims with BBS, creating a base proof.
///
/// The base proof contains the BBS signature and metadata needed
/// for the holder to later create derived (selective disclosure) proofs.
///
/// # Arguments
///
/// * `claims` - The credential claims as key-value pairs
/// * `mandatory_pointers` - JSON pointers to claims that MUST always be disclosed
/// * `header` - Application-specific header (typically SHA-256 of proof options)
/// * `sk` - The issuer's BBS secret key
/// * `pk` - The issuer's BBS public key
///
/// # Returns
///
/// A tuple of (BBS signature, message bytes used for signing).
pub fn sign_base(
    claims: &[(&str, &[u8])],
    header: &[u8],
    sk: &SecretKey,
    pk: &PublicKey,
) -> Result<(Signature, Vec<Vec<u8>>), DataIntegrityError> {
    // Convert claims to message bytes
    let messages: Vec<Vec<u8>> = claims
        .iter()
        .map(|(key, value)| {
            let mut msg = key.as_bytes().to_vec();
            msg.push(b':');
            msg.extend_from_slice(value);
            msg
        })
        .collect();

    let msg_refs: Vec<&[u8]> = messages.iter().map(|m| m.as_slice()).collect();

    let signature = bbs::sign(sk, pk, header, &msg_refs)
        .map_err(|e| DataIntegrityError::CryptoError(format!("BBS sign failed: {e}")))?;

    Ok((signature, messages))
}

/// Create a derived proof by selectively disclosing claims.
///
/// # Arguments
///
/// * `pk` - The issuer's BBS public key
/// * `signature` - The BBS signature from the base proof
/// * `header` - The same header used during signing
/// * `presentation_header` - Session-specific header (nonce from verifier)
/// * `messages` - All message bytes (from sign_base)
/// * `disclosed_indexes` - Which claim indexes to reveal
///
/// # Returns
///
/// The BBS zero-knowledge proof bytes.
pub fn derive_proof(
    pk: &PublicKey,
    signature: &Signature,
    header: &[u8],
    presentation_header: &[u8],
    messages: &[Vec<u8>],
    disclosed_indexes: &[usize],
) -> Result<bbs::Proof, DataIntegrityError> {
    let msg_refs: Vec<&[u8]> = messages.iter().map(|m| m.as_slice()).collect();

    bbs::proof_gen(
        pk,
        signature,
        header,
        presentation_header,
        &msg_refs,
        disclosed_indexes,
    )
    .map_err(|e| DataIntegrityError::CryptoError(format!("BBS proof generation failed: {e}")))
}

/// Verify a derived proof.
///
/// # Arguments
///
/// * `pk` - The issuer's BBS public key
/// * `proof` - The BBS proof to verify
/// * `header` - The same header used during signing
/// * `presentation_header` - The same session-specific header
/// * `disclosed_messages` - The messages that were disclosed
/// * `disclosed_indexes` - The indexes of disclosed messages
///
/// # Returns
///
/// `true` if the proof is valid.
pub fn verify_proof(
    pk: &PublicKey,
    proof: &bbs::Proof,
    header: &[u8],
    presentation_header: &[u8],
    disclosed_messages: &[&[u8]],
    disclosed_indexes: &[usize],
) -> Result<bool, DataIntegrityError> {
    bbs::proof_verify(
        pk,
        proof,
        header,
        presentation_header,
        disclosed_messages,
        disclosed_indexes,
    )
    .map_err(|e| {
        DataIntegrityError::VerificationError(format!("BBS proof verification failed: {e}"))
    })
}

/// Compute a BBS header from proof options and mandatory claims.
///
/// Per W3C vc-di-bbs: `header = SHA-256(proof_options) || SHA-256(mandatory_statements)`
pub fn compute_bbs_header(proof_options: &[u8], mandatory_statements: &[&[u8]]) -> Vec<u8> {
    let mut header = Vec::with_capacity(64);

    // SHA-256 of proof options
    let options_hash = Sha256::digest(proof_options);
    header.extend_from_slice(&options_hash);

    // SHA-256 of concatenated mandatory statements
    let mut mandatory_hasher = Sha256::new();
    for statement in mandatory_statements {
        mandatory_hasher.update(statement);
    }
    let mandatory_hash = mandatory_hasher.finalize();
    header.extend_from_slice(&mandatory_hash);

    header
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_keypair() -> (SecretKey, PublicKey) {
        let sk = bbs::keygen(b"test-key-material-for-bbs-2023!!", b"").unwrap();
        let pk = bbs::sk_to_pk(&sk);
        (sk, pk)
    }

    #[test]
    fn sign_base_and_verify() {
        let (sk, pk) = test_keypair();

        let claims = vec![
            ("given_name", b"John".as_ref()),
            ("family_name", b"Doe"),
            ("age_over_18", b"true"),
        ];

        let header = compute_bbs_header(b"proof-options", &[b"mandatory-1"]);

        let (signature, messages) = sign_base(&claims, &header, &sk, &pk).unwrap();

        // Verify the full signature
        let msg_refs: Vec<&[u8]> = messages.iter().map(|m| m.as_slice()).collect();
        let valid = bbs::verify(&pk, &signature, &header, &msg_refs).unwrap();
        assert!(valid);
    }

    #[test]
    fn derive_and_verify_selective_proof() {
        let (sk, pk) = test_keypair();

        let claims = vec![
            ("given_name", b"John".as_ref()),
            ("family_name", b"Doe"),
            ("age_over_18", b"true"),
            ("nationality", b"DE"),
        ];

        let header = compute_bbs_header(b"proof-options", &[]);

        let (signature, messages) = sign_base(&claims, &header, &sk, &pk).unwrap();

        // Holder: disclose only age_over_18 (index 2)
        let proof = derive_proof(
            &pk,
            &signature,
            &header,
            b"verifier-session-nonce",
            &messages,
            &[2],
        )
        .unwrap();

        // Verifier: verify with only the disclosed message
        let disclosed_msg = messages[2].as_slice();
        let valid = verify_proof(
            &pk,
            &proof,
            &header,
            b"verifier-session-nonce",
            &[disclosed_msg],
            &[2],
        )
        .unwrap();

        assert!(valid);
    }

    #[test]
    fn derive_proof_wrong_message_fails() {
        let (sk, pk) = test_keypair();

        let claims = vec![("name", b"Alice".as_ref())];
        let header = compute_bbs_header(b"opts", &[]);

        let (signature, messages) = sign_base(&claims, &header, &sk, &pk).unwrap();

        let proof = derive_proof(&pk, &signature, &header, b"ph", &messages, &[0]).unwrap();

        // Verify with wrong message
        let valid = verify_proof(
            &pk,
            &proof,
            &header,
            b"ph",
            &[b"name:Bob"], // Wrong!
            &[0],
        )
        .unwrap();

        assert!(!valid);
    }

    #[test]
    fn proofs_are_unlinkable() {
        let (sk, pk) = test_keypair();

        let claims = vec![("attr", b"value".as_ref())];
        let header = compute_bbs_header(b"opts", &[]);

        let (signature, messages) = sign_base(&claims, &header, &sk, &pk).unwrap();

        let proof1 = derive_proof(&pk, &signature, &header, b"session1", &messages, &[0]).unwrap();
        let proof2 = derive_proof(&pk, &signature, &header, b"session2", &messages, &[0]).unwrap();

        assert_ne!(proof1.to_bytes(), proof2.to_bytes());

        // Both verify
        let msg = messages[0].as_slice();
        assert!(verify_proof(&pk, &proof1, &header, b"session1", &[msg], &[0]).unwrap());
        assert!(verify_proof(&pk, &proof2, &header, b"session2", &[msg], &[0]).unwrap());
    }

    #[test]
    fn zero_knowledge_existence_proof() {
        let (sk, pk) = test_keypair();

        let claims = vec![("secret1", b"hidden".as_ref()), ("secret2", b"also_hidden")];
        let header = compute_bbs_header(b"opts", &[]);

        let (signature, messages) = sign_base(&claims, &header, &sk, &pk).unwrap();

        // Disclose nothing
        let proof = derive_proof(&pk, &signature, &header, b"ph", &messages, &[]).unwrap();

        let valid = verify_proof(&pk, &proof, &header, b"ph", &[], &[]).unwrap();
        assert!(valid);
    }

    #[test]
    fn compute_header_deterministic() {
        let h1 = compute_bbs_header(b"opts", &[b"stmt1", b"stmt2"]);
        let h2 = compute_bbs_header(b"opts", &[b"stmt1", b"stmt2"]);
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64); // Two SHA-256 hashes
    }

    #[test]
    fn compute_header_different_inputs() {
        let h1 = compute_bbs_header(b"opts1", &[b"stmt"]);
        let h2 = compute_bbs_header(b"opts2", &[b"stmt"]);
        assert_ne!(h1, h2);
    }
}

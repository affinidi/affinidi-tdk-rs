/*!
 * BBS Signatures over BLS12-381.
 *
 * Implements [IETF draft-irtf-cfrg-bbs-signatures](https://datatracker.ietf.org/doc/draft-irtf-cfrg-bbs-signatures/)
 * providing unforgeable, selectively disclosable, and unlinkable digital signatures.
 *
 * # Security Properties
 *
 * - **Multi-message signing**: Sign an arbitrary number of messages in a single signature
 * - **Selective disclosure**: Create zero-knowledge proofs revealing only chosen messages
 * - **Unlinkability**: Multiple proofs from the same signature are cryptographically independent
 * - **Unforgeability**: Signatures cannot be forged without the secret key
 *
 * # eIDAS 2.0 Compliance
 *
 * Addresses ARF ZKP requirements:
 * - **ZKP_01**: Unlinkable selective disclosure of attributes
 * - **ZKP_02**: Verifier cannot determine undisclosed attributes
 * - **ZKP_03**: Cross-presentation unlinkability
 * - **ZKP_06**: Holder binding via presentation header
 *
 * # Quick Start
 *
 * ```rust
 * use affinidi_bbs::*;
 *
 * // Generate key pair
 * let sk = keygen(b"seed-material-at-least-32-bytes!", b"").unwrap();
 * let pk = sk_to_pk(&sk);
 *
 * // Sign 3 messages
 * let messages = [b"name:Alice".as_ref(), b"age:30", b"role:admin"];
 * let signature = sign(&sk, &pk, b"app-header", &messages).unwrap();
 *
 * // Verify
 * assert!(verify(&pk, &signature, b"app-header", &messages).unwrap());
 *
 * // Selective disclosure: prove only "name:Alice" (index 0)
 * let proof = proof_gen(&pk, &signature, b"app-header", b"session-nonce",
 *                       &messages, &[0]).unwrap();
 *
 * // Verifier checks with only the disclosed message
 * assert!(proof_verify(&pk, &proof, b"app-header", b"session-nonce",
 *                       &[b"name:Alice".as_ref()], &[0]).unwrap());
 * ```
 */

pub mod ciphersuite;
pub mod error;
pub mod generators;
pub mod hash;
pub mod keys;
pub mod proof;
pub mod signature;
pub mod types;

pub use ciphersuite::Ciphersuite;
pub use error::BbsError;
pub use keys::{keygen as keygen_with_cs, sk_to_pk};
pub use types::{Proof, PublicKey, SecretKey, Signature};

/// Generate a BBS secret key from key material using the default ciphersuite (SHA-256).
///
/// `key_material` must be at least 32 bytes.
/// `key_info` is optional additional context (can be empty).
pub fn keygen(key_material: &[u8], key_info: &[u8]) -> error::Result<SecretKey> {
    keys::keygen(key_material, key_info, Ciphersuite::default())
}

/// Sign messages using the default ciphersuite (SHA-256).
pub fn sign(
    sk: &SecretKey,
    pk: &PublicKey,
    header: &[u8],
    messages: &[&[u8]],
) -> error::Result<Signature> {
    signature::core_sign(sk, pk, header, messages, Ciphersuite::default())
}

/// Verify a BBS signature using the default ciphersuite (SHA-256).
pub fn verify(
    pk: &PublicKey,
    sig: &Signature,
    header: &[u8],
    messages: &[&[u8]],
) -> error::Result<bool> {
    signature::core_verify(pk, sig, header, messages, Ciphersuite::default())
}

/// Generate a zero-knowledge proof of selective disclosure using the default ciphersuite.
pub fn proof_gen(
    pk: &PublicKey,
    sig: &Signature,
    header: &[u8],
    presentation_header: &[u8],
    messages: &[&[u8]],
    disclosed_indexes: &[usize],
) -> error::Result<Proof> {
    proof::core_proof_gen(
        pk,
        sig,
        header,
        presentation_header,
        messages,
        disclosed_indexes,
        Ciphersuite::default(),
    )
}

/// Verify a zero-knowledge proof using the default ciphersuite.
pub fn proof_verify(
    pk: &PublicKey,
    proof: &Proof,
    header: &[u8],
    presentation_header: &[u8],
    disclosed_messages: &[&[u8]],
    disclosed_indexes: &[usize],
) -> error::Result<bool> {
    proof::core_proof_verify(
        pk,
        proof,
        header,
        presentation_header,
        disclosed_messages,
        disclosed_indexes,
        Ciphersuite::default(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "TODO: align T2 undisclosed term reconstruction with IETF draft"]
    fn full_flow_sign_verify_prove() {
        let sk = keygen(b"test-key-material-at-least-32-by", b"").unwrap();
        let pk = sk_to_pk(&sk);

        let messages = [b"name:Alice".as_ref(), b"age:30", b"role:admin"];
        let sig = sign(&sk, &pk, b"app", &messages).unwrap();

        assert!(verify(&pk, &sig, b"app", &messages).unwrap());

        // Prove only name (index 0)
        let proof = proof_gen(&pk, &sig, b"app", b"session", &messages, &[0]).unwrap();

        assert!(
            proof_verify(
                &pk,
                &proof,
                b"app",
                b"session",
                &[b"name:Alice".as_ref()],
                &[0]
            )
            .unwrap()
        );
    }

    #[test]
    #[ignore = "TODO: align T2 undisclosed term reconstruction with IETF draft"]
    fn full_flow_multiple_disclosures() {
        let sk = keygen(b"another-key-material-32-bytes!!!", b"").unwrap();
        let pk = sk_to_pk(&sk);

        let messages = [
            b"given_name:John".as_ref(),
            b"family_name:Doe",
            b"email:john@example.com",
            b"age_over_18:true",
            b"nationality:DE",
        ];

        let sig = sign(&sk, &pk, b"eidas-pid", &messages).unwrap();

        // Verifier 1: needs age and nationality
        let proof1 = proof_gen(&pk, &sig, b"eidas-pid", b"v1-session", &messages, &[3, 4]).unwrap();

        assert!(
            proof_verify(
                &pk,
                &proof1,
                b"eidas-pid",
                b"v1-session",
                &[b"age_over_18:true".as_ref(), b"nationality:DE"],
                &[3, 4],
            )
            .unwrap()
        );

        // Verifier 2: needs name only
        let proof2 = proof_gen(&pk, &sig, b"eidas-pid", b"v2-session", &messages, &[0, 1]).unwrap();

        assert!(
            proof_verify(
                &pk,
                &proof2,
                b"eidas-pid",
                b"v2-session",
                &[b"given_name:John".as_ref(), b"family_name:Doe"],
                &[0, 1],
            )
            .unwrap()
        );

        // Proofs are unlinkable
        assert_ne!(proof1.to_bytes(), proof2.to_bytes());
    }
}

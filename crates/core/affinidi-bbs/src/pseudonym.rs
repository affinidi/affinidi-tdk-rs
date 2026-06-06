/*!
 * BBS per-verifier pseudonyms (holder binding).
 *
 * Implements the proof-side of
 * [draft-irtf-cfrg-bbs-per-verifier-linkability](https://datatracker.ietf.org/doc/draft-irtf-cfrg-bbs-per-verifier-linkability/):
 * the holder proves possession of a committed `nym_secret` and presents a
 * per-verifier `Pseudonym`, bound into the same proof as the selective
 * disclosure.
 *
 * # Construction (matches the reference `@digitalbazaar/bbs-signatures`)
 *
 * - The `nym_secret` is the **last** BBS-signed message, always undisclosed.
 * - `OP = hash_to_curve_g1(context_id, api_id)` — a generator unique to the
 *   verifier's `context_id`.
 * - `Pseudonym = OP · nym_secret`, and the proof reuses the `nym_secret`
 *   message's blinding `m~` to commit `Ut = OP · m~`. The Fiat-Shamir challenge
 *   inserts `(Pseudonym, OP, Ut)` between `T2` and `domain`
 *   (`ProofWithPseudonymChallengeCalculate`). Verification recomputes
 *   `Uv = OP · m̂_nym − Pseudonym · c`.
 *
 * # Properties
 *
 * - **Holder binding** — possession of the credential is not enough; the
 *   presenter must know the committed `nym_secret`.
 * - **Per-verifier linkability** — a fixed `context_id` gives a stable
 *   `Pseudonym`; different contexts give independent (unlinkable) ones.
 *
 * The full vc-di-bbs `pseudonym` feature additionally commits the `nym_secret`
 * via blind issuance (`signer_nym_entropy`); that issuance layer is tracked
 * separately. This module provides the proof primitive.
 */

use bls12_381_plus::G1Projective;
use elliptic_curve::hash2curve::ExpandMsgXmd;
use sha2::Sha256;

use crate::ciphersuite::Ciphersuite;

/// The per-verifier pseudonym generator `OP = hash_to_curve_g1(context_id)`,
/// using the ciphersuite `api_id` as the hash-to-curve domain separation tag.
///
/// The same `context_id` always yields the same `OP`, which is what makes a
/// holder's pseudonym stable per verifier and unlinkable across verifiers.
pub fn calculate_pseudonym_generator(context_id: &[u8], cs: Ciphersuite) -> G1Projective {
    calculate_pseudonym_generator_with_api_id(context_id, &cs.api_id())
}

/// [`calculate_pseudonym_generator`] with an explicit hash-to-curve domain
/// separation tag. Blind/pseudonym (nym) proofs derive `OP` under the pseudonym
/// api_id ([`Ciphersuite::pseudonym_api_id`]).
pub fn calculate_pseudonym_generator_with_api_id(context_id: &[u8], api_id: &[u8]) -> G1Projective {
    G1Projective::hash::<ExpandMsgXmd<Sha256>>(context_id, api_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generators::point_to_bytes;

    #[test]
    fn op_is_deterministic_per_context() {
        let a = calculate_pseudonym_generator(b"verifier-a", Ciphersuite::Bls12381Sha256);
        let b = calculate_pseudonym_generator(b"verifier-a", Ciphersuite::Bls12381Sha256);
        assert_eq!(point_to_bytes(&a), point_to_bytes(&b));
    }

    #[test]
    fn op_differs_per_context() {
        let a = calculate_pseudonym_generator(b"verifier-a", Ciphersuite::Bls12381Sha256);
        let b = calculate_pseudonym_generator(b"verifier-b", Ciphersuite::Bls12381Sha256);
        assert_ne!(point_to_bytes(&a), point_to_bytes(&b));
    }
}

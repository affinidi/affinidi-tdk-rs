/*!
 * BBS key generation per IETF draft §3.4.
 *
 * - `keygen`: Generate a secret key from key material
 * - `sk_to_pk`: Derive the public key from a secret key
 */

use bls12_381_plus::{G2Projective, Scalar};
use ff::Field;
use group::Group;

use crate::ciphersuite::Ciphersuite;
use crate::error::{BbsError, Result};
use crate::hash::hash_to_scalar;
use crate::types::{PublicKey, SecretKey};

/// Generate a BBS secret key from key material.
///
/// Per IETF draft §3.4:
/// - `key_material` must be at least 32 bytes
/// - `key_info` is optional additional context
///
/// The secret key is deterministically derived via `hash_to_scalar`.
pub fn keygen(key_material: &[u8], key_info: &[u8], cs: Ciphersuite) -> Result<SecretKey> {
    if key_material.len() < 32 {
        return Err(BbsError::InvalidKey(
            "key_material must be at least 32 bytes".into(),
        ));
    }

    let key_dst = [cs.id().as_bytes(), b"KEYGEN_DST_"].concat();

    // derive_input = key_material || I2OSP(length(key_info), 2) || key_info
    let mut derive_input = key_material.to_vec();
    derive_input.extend_from_slice(&(key_info.len() as u16).to_be_bytes());
    derive_input.extend_from_slice(key_info);

    let sk = hash_to_scalar(&derive_input, &key_dst, cs)?;

    if bool::from(sk.is_zero()) {
        return Err(BbsError::InvalidKey("derived key is zero".into()));
    }

    Ok(SecretKey(sk))
}

/// Derive the public key from a secret key.
///
/// `PK = SK * BP2` where BP2 is the G2 generator.
pub fn sk_to_pk(sk: &SecretKey) -> PublicKey {
    PublicKey(G2Projective::generator() * sk.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keygen_produces_nonzero_key() {
        let sk = keygen(
            b"this-is-at-least-32-bytes-of-key-material!",
            b"",
            Ciphersuite::Bls12381Sha256,
        )
        .unwrap();
        assert_ne!(sk.0, Scalar::ZERO);
    }

    #[test]
    fn keygen_deterministic() {
        let sk1 = keygen(
            b"same-material-at-least-32-bytes!",
            b"info",
            Ciphersuite::Bls12381Sha256,
        )
        .unwrap();
        let sk2 = keygen(
            b"same-material-at-least-32-bytes!",
            b"info",
            Ciphersuite::Bls12381Sha256,
        )
        .unwrap();
        assert_eq!(sk1.0, sk2.0);
    }

    #[test]
    fn keygen_different_material_different_key() {
        let sk1 = keygen(
            b"material-1-at-least-32-bytes-ok!",
            b"",
            Ciphersuite::Bls12381Sha256,
        )
        .unwrap();
        let sk2 = keygen(
            b"material-2-at-least-32-bytes-ok!",
            b"",
            Ciphersuite::Bls12381Sha256,
        )
        .unwrap();
        assert_ne!(sk1.0, sk2.0);
    }

    #[test]
    fn keygen_short_material_rejected() {
        let result = keygen(b"short", b"", Ciphersuite::Bls12381Sha256);
        assert!(result.is_err());
    }

    #[test]
    fn sk_to_pk_deterministic() {
        let sk = keygen(
            b"test-key-material-at-least-32-by",
            b"",
            Ciphersuite::Bls12381Sha256,
        )
        .unwrap();
        let pk1 = sk_to_pk(&sk);
        let pk2 = sk_to_pk(&sk);
        assert_eq!(pk1, pk2);
    }

    #[test]
    fn pk_roundtrip() {
        let sk = keygen(
            b"roundtrip-test-key-material-32b!",
            b"",
            Ciphersuite::Bls12381Sha256,
        )
        .unwrap();
        let pk = sk_to_pk(&sk);
        let bytes = pk.to_bytes();
        assert_eq!(bytes.len(), 96);
        let recovered = PublicKey::from_bytes(&bytes).unwrap();
        assert_eq!(pk, recovered);
    }
}

/*!
 * Core BBS types: SecretKey, PublicKey, Signature, Proof.
 */

use bls12_381_plus::{G1Affine, G1Projective, G2Affine, G2Projective, Scalar};
use ff::Field;
use group::Group;

use crate::error::{BbsError, Result};

/// A BBS secret key (scalar in the BLS12-381 group).
///
/// 32 bytes, must be nonzero and less than the group order.
#[derive(Clone)]
pub struct SecretKey(pub(crate) Scalar);

impl SecretKey {
    /// Create a secret key from raw scalar bytes (big-endian).
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self> {
        let scalar = Scalar::from_be_bytes(bytes);
        if scalar.is_some().into() {
            let s = scalar.unwrap();
            if s == Scalar::ZERO {
                return Err(BbsError::InvalidKey("secret key cannot be zero".into()));
            }
            Ok(SecretKey(s))
        } else {
            Err(BbsError::InvalidKey("invalid scalar bytes".into()))
        }
    }

    /// Serialize the secret key to big-endian bytes.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_be_bytes()
    }

    /// Get the inner scalar.
    pub fn scalar(&self) -> &Scalar {
        &self.0
    }
}

impl std::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecretKey([REDACTED])")
    }
}

/// Zeroize the secret key on drop.
impl Drop for SecretKey {
    fn drop(&mut self) {
        self.0 = Scalar::ZERO;
    }
}

/// A BBS public key (point in the G2 subgroup).
///
/// 96 bytes (compressed G2 point).
#[derive(Clone, Debug)]
pub struct PublicKey(pub(crate) G2Projective);

impl PublicKey {
    /// Deserialize a public key from compressed G2 bytes (96 bytes).
    pub fn from_bytes(bytes: &[u8; 96]) -> Result<Self> {
        let affine = G2Affine::from_compressed(bytes);
        if affine.is_some().into() {
            Ok(PublicKey(G2Projective::from(affine.unwrap())))
        } else {
            Err(BbsError::InvalidKey("invalid G2 point".into()))
        }
    }

    /// Serialize the public key to compressed G2 bytes.
    pub fn to_bytes(&self) -> [u8; 96] {
        G2Affine::from(&self.0).to_compressed()
    }

    /// Get the inner G2 projective point.
    pub fn point(&self) -> &G2Projective {
        &self.0
    }
}

impl PartialEq for PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.to_bytes() == other.to_bytes()
    }
}

/// A BBS signature.
///
/// Contains a G1 point `A` and a scalar `e`.
/// Total size: 48 + octet_scalar_length bytes (80 for SHA-256, 112 for SHAKE-256).
#[derive(Clone, Debug)]
pub struct Signature {
    pub(crate) a: G1Projective,
    pub(crate) e: Scalar,
}

impl Signature {
    /// Deserialize a signature from bytes (SHA-256 ciphersuite: 80 bytes).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 80 {
            return Err(BbsError::InvalidSignature(format!(
                "expected at least 80 bytes, got {}",
                bytes.len()
            )));
        }

        let mut a_bytes = [0u8; 48];
        a_bytes.copy_from_slice(&bytes[..48]);
        let a_affine = G1Affine::from_compressed(&a_bytes);
        if (!bool::from(a_affine.is_some())) || bool::from(a_affine.unwrap().is_identity()) {
            return Err(BbsError::InvalidSignature("invalid point A".into()));
        }
        let a = G1Projective::from(a_affine.unwrap());

        let mut e_bytes = [0u8; 32];
        e_bytes.copy_from_slice(&bytes[48..80]);
        let e = Scalar::from_be_bytes(&e_bytes);
        if (!bool::from(e.is_some())) || bool::from(e.unwrap().is_zero()) {
            return Err(BbsError::InvalidSignature("invalid scalar e".into()));
        }

        Ok(Signature { a, e: e.unwrap() })
    }

    /// Serialize the signature to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(80);
        bytes.extend_from_slice(&G1Affine::from(&self.a).to_compressed());
        bytes.extend_from_slice(&self.e.to_be_bytes());
        bytes
    }
}

/// A BBS zero-knowledge proof of selective disclosure.
///
/// Variable length: 144 + (4 + U) * scalar_length bytes,
/// where U is the number of undisclosed messages.
#[derive(Clone, Debug)]
pub struct Proof(pub(crate) Vec<u8>);

impl Proof {
    /// Create a proof from raw bytes.
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Proof(bytes)
    }

    /// Get the proof bytes.
    pub fn to_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Get the number of undisclosed messages in this proof.
    ///
    /// For SHA-256: U = (len - 3*48 - 4*32) / 32
    pub fn undisclosed_count_sha256(&self) -> usize {
        if self.0.len() < 272 {
            0
        } else {
            (self.0.len() - 3 * 48 - 4 * 32) / 32
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bls12_381_plus::G2Projective;

    #[test]
    fn secret_key_roundtrip() {
        let scalar = Scalar::from(42u64);
        let sk = SecretKey(scalar);
        let bytes = sk.to_bytes();
        let recovered = SecretKey::from_bytes(&bytes).unwrap();
        assert_eq!(sk.0, recovered.0);
    }

    #[test]
    fn secret_key_zero_rejected() {
        let bytes = [0u8; 32];
        assert!(SecretKey::from_bytes(&bytes).is_err());
    }

    #[test]
    fn public_key_roundtrip() {
        let pk = PublicKey(G2Projective::generator());
        let bytes = pk.to_bytes();
        let recovered = PublicKey::from_bytes(&bytes).unwrap();
        assert_eq!(pk, recovered);
    }

    #[test]
    fn secret_key_debug_redacted() {
        let sk = SecretKey(Scalar::from(42u64));
        let debug = format!("{sk:?}");
        assert!(debug.contains("REDACTED"));
        assert!(!debug.contains("42"));
    }
}

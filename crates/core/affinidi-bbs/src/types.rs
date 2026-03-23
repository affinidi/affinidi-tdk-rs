/*!
 * Core BBS types: SecretKey, PublicKey, Signature, Proof.
 */

use bls12_381_plus::{G1Affine, G1Projective, G2Affine, G2Projective, Scalar};
use ff::Field;

use crate::error::{BbsError, Result};

/// A BBS secret key (scalar in the BLS12-381 group).
///
/// 32 bytes, must be nonzero and less than the group order.
/// The key is zeroized in memory when dropped using volatile writes
/// to prevent compiler optimization of the zeroing.
#[derive(Clone)]
pub struct SecretKey(pub(crate) Scalar);

impl Drop for SecretKey {
    fn drop(&mut self) {
        // Overwrite the scalar's memory with zeros using volatile writes.
        // This prevents the compiler from optimizing away the zeroing.
        let ptr = &mut self.0 as *mut Scalar as *mut u8;
        let size = std::mem::size_of::<Scalar>();
        unsafe {
            for i in 0..size {
                std::ptr::write_volatile(ptr.add(i), 0);
            }
        }
    }
}

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

/// A BBS public key (point in the G2 subgroup).
///
/// 96 bytes (compressed G2 point). Must not be the identity point.
#[derive(Clone, Debug)]
pub struct PublicKey(pub(crate) G2Projective);

impl PublicKey {
    /// Deserialize a public key from compressed G2 bytes (96 bytes).
    ///
    /// Validates that the point is on the curve, in the correct subgroup,
    /// and is not the identity point.
    pub fn from_bytes(bytes: &[u8; 96]) -> Result<Self> {
        let affine = G2Affine::from_compressed(bytes);
        if affine.is_some().into() {
            let point = affine.unwrap();
            if bool::from(point.is_identity()) {
                return Err(BbsError::InvalidKey(
                    "public key cannot be the identity point".into(),
                ));
            }
            Ok(PublicKey(G2Projective::from(point)))
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

    /// Check that this public key is valid (not identity).
    pub(crate) fn validate(&self) -> Result<()> {
        if bool::from(G2Affine::from(&self.0).is_identity()) {
            return Err(BbsError::InvalidKey(
                "public key is the identity point".into(),
            ));
        }
        Ok(())
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
/// Total size: 80 bytes for the SHA-256 ciphersuite (48-byte point + 32-byte scalar).
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

    /// Serialize the signature to a fixed 80-byte array.
    pub fn to_bytes(&self) -> [u8; 80] {
        let mut bytes = [0u8; 80];
        bytes[..48].copy_from_slice(&G1Affine::from(&self.a).to_compressed());
        bytes[48..].copy_from_slice(&self.e.to_be_bytes());
        bytes
    }
}

/// A BBS zero-knowledge proof of selective disclosure.
///
/// Variable length: 144 + (4 + U) * 32 bytes for SHA-256,
/// where U is the number of undisclosed messages.
#[derive(Clone, Debug)]
pub struct Proof(pub(crate) Vec<u8>);

impl Proof {
    /// Create a proof from raw bytes.
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Proof(bytes.to_vec())
    }

    /// Get the proof bytes.
    pub fn to_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Get the number of undisclosed messages in this proof (SHA-256 ciphersuite).
    ///
    /// Returns 0 if the proof is too short to contain undisclosed message commitments.
    pub fn undisclosed_count_sha256(&self) -> usize {
        let min = 3 * 48 + 4 * 32; // 272 bytes minimum
        if self.0.len() < min {
            0
        } else {
            (self.0.len() - min) / 32
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn public_key_identity_rejected() {
        let identity = G2Projective::identity();
        let pk = PublicKey(identity);
        let bytes = pk.to_bytes();
        assert!(PublicKey::from_bytes(&bytes).is_err());
    }

    #[test]
    fn secret_key_debug_redacted() {
        let sk = SecretKey(Scalar::from(42u64));
        let debug = format!("{sk:?}");
        assert!(debug.contains("REDACTED"));
        assert!(!debug.contains("42"));
    }

    #[test]
    fn signature_to_bytes_fixed_size() {
        let sk_scalar = Scalar::from(12345u64);
        let sk = SecretKey(sk_scalar);
        let pk = PublicKey(G2Projective::generator() * sk_scalar);
        let messages: Vec<&[u8]> = vec![b"test"];
        let sig = crate::signature::core_sign(
            &sk,
            &pk,
            b"",
            &messages,
            crate::Ciphersuite::Bls12381Sha256,
        )
        .unwrap();
        let bytes = sig.to_bytes();
        assert_eq!(bytes.len(), 80);

        // Roundtrip
        let recovered = Signature::from_bytes(&bytes).unwrap();
        assert_eq!(
            G1Affine::from(&sig.a).to_compressed(),
            G1Affine::from(&recovered.a).to_compressed()
        );
    }

    #[test]
    fn signature_from_bytes_truncated_fails() {
        let bytes = [0u8; 40]; // Too short
        assert!(Signature::from_bytes(&bytes).is_err());
    }

    #[test]
    fn proof_from_bytes_clones() {
        let data = vec![1u8, 2, 3];
        let proof = Proof::from_bytes(&data);
        assert_eq!(proof.to_bytes(), &[1, 2, 3]);
    }
}

//! Key agreement trait and implementations for X25519, P-256, and K-256.
//!
//! The `KeyAgreement` enum provides curve-polymorphic ECDH operations,
//! eliminating the combinatorial match-arm explosion of the legacy crate.

use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::DIDCommError;

/// Supported key agreement curves.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Curve {
    X25519,
    P256,
    K256,
}

impl Curve {
    /// JWK `crv` value for this curve.
    pub fn jwk_crv(&self) -> &'static str {
        match self {
            Curve::X25519 => "X25519",
            Curve::P256 => "P-256",
            Curve::K256 => "secp256k1",
        }
    }
}

/// A public key for key agreement (any supported curve).
#[derive(Debug, Clone)]
pub enum PublicKeyAgreement {
    X25519([u8; 32]),
    P256(p256::PublicKey),
    K256(k256::PublicKey),
}

impl PublicKeyAgreement {
    /// The curve of this key.
    pub fn curve(&self) -> Curve {
        match self {
            PublicKeyAgreement::X25519(_) => Curve::X25519,
            PublicKeyAgreement::P256(_) => Curve::P256,
            PublicKeyAgreement::K256(_) => Curve::K256,
        }
    }

    /// Encode as a JWK JSON value.
    pub fn to_jwk(&self) -> Value {
        match self {
            PublicKeyAgreement::X25519(bytes) => {
                use base64ct::{Base64UrlUnpadded, Encoding};
                serde_json::json!({
                    "kty": "OKP",
                    "crv": "X25519",
                    "x": Base64UrlUnpadded::encode_string(bytes),
                })
            }
            PublicKeyAgreement::P256(pk) => {
                use p256::elliptic_curve::sec1::ToEncodedPoint;
                let point = pk.to_encoded_point(false);
                use base64ct::{Base64UrlUnpadded, Encoding};
                serde_json::json!({
                    "kty": "EC",
                    "crv": "P-256",
                    "x": Base64UrlUnpadded::encode_string(point.x().unwrap()),
                    "y": Base64UrlUnpadded::encode_string(point.y().unwrap()),
                })
            }
            PublicKeyAgreement::K256(pk) => {
                use k256::elliptic_curve::sec1::ToEncodedPoint;
                let point = pk.to_encoded_point(false);
                use base64ct::{Base64UrlUnpadded, Encoding};
                serde_json::json!({
                    "kty": "EC",
                    "crv": "secp256k1",
                    "x": Base64UrlUnpadded::encode_string(point.x().unwrap()),
                    "y": Base64UrlUnpadded::encode_string(point.y().unwrap()),
                })
            }
        }
    }

    /// Construct from raw bytes and a known curve.
    ///
    /// For X25519: expects 32 bytes.
    /// For P-256/K-256: expects SEC1 encoded point (compressed or uncompressed).
    pub fn from_raw_bytes(curve: Curve, bytes: &[u8]) -> Result<Self, DIDCommError> {
        match curve {
            Curve::X25519 => {
                let arr: [u8; 32] = bytes.try_into().map_err(|_| {
                    DIDCommError::KeyAgreement("X25519 public key must be 32 bytes".into())
                })?;
                Ok(PublicKeyAgreement::X25519(arr))
            }
            Curve::P256 => {
                let pk = p256::PublicKey::from_sec1_bytes(bytes).map_err(|e| {
                    DIDCommError::KeyAgreement(format!("invalid P-256 public key: {e}"))
                })?;
                Ok(PublicKeyAgreement::P256(pk))
            }
            Curve::K256 => {
                let pk = k256::PublicKey::from_sec1_bytes(bytes).map_err(|e| {
                    DIDCommError::KeyAgreement(format!("invalid K-256 public key: {e}"))
                })?;
                Ok(PublicKeyAgreement::K256(pk))
            }
        }
    }

    /// Parse from a JWK JSON value.
    pub fn from_jwk(jwk: &Value) -> Result<Self, DIDCommError> {
        let crv = jwk["crv"]
            .as_str()
            .ok_or_else(|| DIDCommError::KeyAgreement("missing crv in JWK".into()))?;

        use base64ct::{Base64UrlUnpadded, Encoding};

        match crv {
            "X25519" => {
                let x = jwk["x"]
                    .as_str()
                    .ok_or_else(|| DIDCommError::KeyAgreement("missing x in X25519 JWK".into()))?;
                let bytes = Base64UrlUnpadded::decode_vec(x)
                    .map_err(|e| DIDCommError::KeyAgreement(format!("invalid x: {e}")))?;
                let arr: [u8; 32] = bytes.try_into().map_err(|_| {
                    DIDCommError::KeyAgreement("X25519 key must be 32 bytes".into())
                })?;
                Ok(PublicKeyAgreement::X25519(arr))
            }
            "P-256" => {
                let x = jwk["x"]
                    .as_str()
                    .ok_or_else(|| DIDCommError::KeyAgreement("missing x in P-256 JWK".into()))?;
                let y = jwk["y"]
                    .as_str()
                    .ok_or_else(|| DIDCommError::KeyAgreement("missing y in P-256 JWK".into()))?;
                let x_bytes = Base64UrlUnpadded::decode_vec(x)
                    .map_err(|e| DIDCommError::KeyAgreement(format!("invalid x: {e}")))?;
                let y_bytes = Base64UrlUnpadded::decode_vec(y)
                    .map_err(|e| DIDCommError::KeyAgreement(format!("invalid y: {e}")))?;

                // Build uncompressed SEC1 point: 0x04 || x || y
                let mut point = Vec::with_capacity(1 + x_bytes.len() + y_bytes.len());
                point.push(0x04);
                point.extend_from_slice(&x_bytes);
                point.extend_from_slice(&y_bytes);

                let pk = p256::PublicKey::from_sec1_bytes(&point)
                    .map_err(|e| DIDCommError::KeyAgreement(format!("invalid P-256 key: {e}")))?;
                Ok(PublicKeyAgreement::P256(pk))
            }
            "secp256k1" => {
                let x = jwk["x"]
                    .as_str()
                    .ok_or_else(|| DIDCommError::KeyAgreement("missing x".into()))?;
                let y = jwk["y"]
                    .as_str()
                    .ok_or_else(|| DIDCommError::KeyAgreement("missing y".into()))?;
                let x_bytes = Base64UrlUnpadded::decode_vec(x)
                    .map_err(|e| DIDCommError::KeyAgreement(format!("invalid x: {e}")))?;
                let y_bytes = Base64UrlUnpadded::decode_vec(y)
                    .map_err(|e| DIDCommError::KeyAgreement(format!("invalid y: {e}")))?;

                let mut point = Vec::with_capacity(1 + x_bytes.len() + y_bytes.len());
                point.push(0x04);
                point.extend_from_slice(&x_bytes);
                point.extend_from_slice(&y_bytes);

                let pk = k256::PublicKey::from_sec1_bytes(&point)
                    .map_err(|e| DIDCommError::KeyAgreement(format!("invalid K-256 key: {e}")))?;
                Ok(PublicKeyAgreement::K256(pk))
            }
            _ => Err(DIDCommError::UnsupportedAlgorithm(format!(
                "unsupported curve: {crv}"
            ))),
        }
    }
}

/// A private key for key agreement (any supported curve).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub enum PrivateKeyAgreement {
    X25519(#[zeroize(skip)] x25519_dalek::StaticSecret),
    P256(#[zeroize(skip)] p256::SecretKey),
    K256(#[zeroize(skip)] k256::SecretKey),
}

impl std::fmt::Debug for PrivateKeyAgreement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PrivateKeyAgreement::X25519(_) => write!(f, "PrivateKeyAgreement::X25519([REDACTED])"),
            PrivateKeyAgreement::P256(_) => write!(f, "PrivateKeyAgreement::P256([REDACTED])"),
            PrivateKeyAgreement::K256(_) => write!(f, "PrivateKeyAgreement::K256([REDACTED])"),
        }
    }
}

impl PrivateKeyAgreement {
    /// Construct from raw private key bytes and a known curve.
    ///
    /// For X25519: expects 32 bytes (clamped scalar).
    /// For P-256/K-256: expects the scalar bytes.
    pub fn from_raw_bytes(curve: Curve, bytes: &[u8]) -> Result<Self, DIDCommError> {
        match curve {
            Curve::X25519 => {
                let arr: [u8; 32] = bytes.try_into().map_err(|_| {
                    DIDCommError::KeyAgreement("X25519 private key must be 32 bytes".into())
                })?;
                Ok(PrivateKeyAgreement::X25519(
                    x25519_dalek::StaticSecret::from(arr),
                ))
            }
            Curve::P256 => {
                let sk = p256::SecretKey::from_slice(bytes).map_err(|e| {
                    DIDCommError::KeyAgreement(format!("invalid P-256 private key: {e}"))
                })?;
                Ok(PrivateKeyAgreement::P256(sk))
            }
            Curve::K256 => {
                let sk = k256::SecretKey::from_slice(bytes).map_err(|e| {
                    DIDCommError::KeyAgreement(format!("invalid K-256 private key: {e}"))
                })?;
                Ok(PrivateKeyAgreement::K256(sk))
            }
        }
    }

    /// Generate a new random private key on the given curve.
    pub fn generate(curve: Curve) -> Self {
        match curve {
            Curve::X25519 => {
                PrivateKeyAgreement::X25519(x25519_dalek::StaticSecret::random_from_rng(OsRng))
            }
            Curve::P256 => PrivateKeyAgreement::P256(p256::SecretKey::random(&mut OsRng)),
            Curve::K256 => PrivateKeyAgreement::K256(k256::SecretKey::random(&mut OsRng)),
        }
    }

    /// Derive the public key.
    pub fn public_key(&self) -> PublicKeyAgreement {
        match self {
            PrivateKeyAgreement::X25519(sk) => {
                PublicKeyAgreement::X25519(x25519_dalek::PublicKey::from(sk).to_bytes())
            }
            PrivateKeyAgreement::P256(sk) => PublicKeyAgreement::P256(sk.public_key()),
            PrivateKeyAgreement::K256(sk) => PublicKeyAgreement::K256(sk.public_key()),
        }
    }

    /// The curve of this key.
    pub fn curve(&self) -> Curve {
        match self {
            PrivateKeyAgreement::X25519(_) => Curve::X25519,
            PrivateKeyAgreement::P256(_) => Curve::P256,
            PrivateKeyAgreement::K256(_) => Curve::K256,
        }
    }

    /// Perform ECDH with a public key, returning the raw shared secret bytes.
    pub fn diffie_hellman(
        &self,
        their_public: &PublicKeyAgreement,
    ) -> Result<Vec<u8>, DIDCommError> {
        match (self, their_public) {
            (PrivateKeyAgreement::X25519(sk), PublicKeyAgreement::X25519(pk)) => {
                let pk = x25519_dalek::PublicKey::from(*pk);
                Ok(sk.diffie_hellman(&pk).as_bytes().to_vec())
            }
            (PrivateKeyAgreement::P256(sk), PublicKeyAgreement::P256(pk)) => {
                use p256::ecdh::diffie_hellman;
                let shared = diffie_hellman(sk.to_nonzero_scalar(), pk.as_affine());
                Ok(shared.raw_secret_bytes().to_vec())
            }
            (PrivateKeyAgreement::K256(sk), PublicKeyAgreement::K256(pk)) => {
                use k256::ecdh::diffie_hellman;
                let shared = diffie_hellman(sk.to_nonzero_scalar(), pk.as_affine());
                Ok(shared.raw_secret_bytes().to_vec())
            }
            _ => Err(DIDCommError::KeyAgreement(
                "curve mismatch between private and public keys".into(),
            )),
        }
    }
}

/// An ephemeral key pair for ECDH (generated per-message).
pub struct EphemeralKeyPair {
    pub private: PrivateKeyAgreement,
    pub public: PublicKeyAgreement,
}

impl EphemeralKeyPair {
    /// Generate a new ephemeral key pair on the given curve.
    pub fn generate(curve: Curve) -> Self {
        let private = PrivateKeyAgreement::generate(curve);
        let public = private.public_key();
        Self { private, public }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x25519_ecdh_roundtrip() {
        let alice = PrivateKeyAgreement::generate(Curve::X25519);
        let bob = PrivateKeyAgreement::generate(Curve::X25519);

        let alice_pub = alice.public_key();
        let bob_pub = bob.public_key();

        let shared_ab = alice.diffie_hellman(&bob_pub).unwrap();
        let shared_ba = bob.diffie_hellman(&alice_pub).unwrap();

        assert_eq!(shared_ab, shared_ba);
        assert_eq!(shared_ab.len(), 32);
    }

    #[test]
    fn p256_ecdh_roundtrip() {
        let alice = PrivateKeyAgreement::generate(Curve::P256);
        let bob = PrivateKeyAgreement::generate(Curve::P256);

        let shared_ab = alice.diffie_hellman(&bob.public_key()).unwrap();
        let shared_ba = bob.diffie_hellman(&alice.public_key()).unwrap();

        assert_eq!(shared_ab, shared_ba);
        assert_eq!(shared_ab.len(), 32);
    }

    #[test]
    fn k256_ecdh_roundtrip() {
        let alice = PrivateKeyAgreement::generate(Curve::K256);
        let bob = PrivateKeyAgreement::generate(Curve::K256);

        let shared_ab = alice.diffie_hellman(&bob.public_key()).unwrap();
        let shared_ba = bob.diffie_hellman(&alice.public_key()).unwrap();

        assert_eq!(shared_ab, shared_ba);
        assert_eq!(shared_ab.len(), 32);
    }

    #[test]
    fn curve_mismatch_fails() {
        let alice = PrivateKeyAgreement::generate(Curve::X25519);
        let bob_pub = PrivateKeyAgreement::generate(Curve::P256).public_key();

        assert!(alice.diffie_hellman(&bob_pub).is_err());
    }

    #[test]
    fn jwk_roundtrip_x25519() {
        let key = PrivateKeyAgreement::generate(Curve::X25519);
        let pub_key = key.public_key();
        let jwk = pub_key.to_jwk();
        let parsed = PublicKeyAgreement::from_jwk(&jwk).unwrap();
        assert_eq!(parsed.curve(), Curve::X25519);
    }

    #[test]
    fn jwk_roundtrip_p256() {
        let key = PrivateKeyAgreement::generate(Curve::P256);
        let pub_key = key.public_key();
        let jwk = pub_key.to_jwk();
        let parsed = PublicKeyAgreement::from_jwk(&jwk).unwrap();
        assert_eq!(parsed.curve(), Curve::P256);
    }

    #[test]
    fn jwk_roundtrip_k256() {
        let key = PrivateKeyAgreement::generate(Curve::K256);
        let pub_key = key.public_key();
        let jwk = pub_key.to_jwk();
        let parsed = PublicKeyAgreement::from_jwk(&jwk).unwrap();
        assert_eq!(parsed.curve(), Curve::K256);
    }
}

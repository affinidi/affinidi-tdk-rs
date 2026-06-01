//! Key-agreement curves and keys for JOSE ECDH (X25519, P-256, K-256).
//!
//! Ported from `affinidi-messaging-didcomm` for the #327 centralization.
//! Curve-polymorphic key material is necessarily runtime-dispatched (a
//! DIDComm message selects its curve at runtime), so the public/private
//! keys are enums. Extensibility is preserved by locality: adding a curve
//! is a new variant plus its arms **here only** — every derivation, KDF,
//! key-wrap, and content-encryption path is curve-agnostic (it operates on
//! the raw shared-secret bytes `diffie_hellman` returns), so none of them
//! change. The `Curve` enum doubles as the typed JOSE `crv` wire boundary.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::CryptoError;

/// Supported key-agreement curves (JOSE `crv` identifiers).
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
            PublicKeyAgreement::X25519(bytes) => serde_json::json!({
                "kty": "OKP",
                "crv": "X25519",
                "x": URL_SAFE_NO_PAD.encode(bytes),
            }),
            PublicKeyAgreement::P256(pk) => {
                use p256::elliptic_curve::sec1::ToEncodedPoint;
                let point = pk.to_encoded_point(false);
                serde_json::json!({
                    "kty": "EC",
                    "crv": "P-256",
                    "x": URL_SAFE_NO_PAD.encode(point.x().unwrap()),
                    "y": URL_SAFE_NO_PAD.encode(point.y().unwrap()),
                })
            }
            PublicKeyAgreement::K256(pk) => {
                use k256::elliptic_curve::sec1::ToEncodedPoint;
                let point = pk.to_encoded_point(false);
                serde_json::json!({
                    "kty": "EC",
                    "crv": "secp256k1",
                    "x": URL_SAFE_NO_PAD.encode(point.x().unwrap()),
                    "y": URL_SAFE_NO_PAD.encode(point.y().unwrap()),
                })
            }
        }
    }

    /// Construct from raw bytes and a known curve.
    ///
    /// For X25519: expects 32 bytes. For P-256/K-256: expects a SEC1
    /// encoded point (compressed or uncompressed).
    pub fn from_raw_bytes(curve: Curve, bytes: &[u8]) -> Result<Self, CryptoError> {
        match curve {
            Curve::X25519 => {
                let arr: [u8; 32] = bytes.try_into().map_err(|_| {
                    CryptoError::KeyAgreement("X25519 public key must be 32 bytes".into())
                })?;
                Ok(PublicKeyAgreement::X25519(arr))
            }
            Curve::P256 => {
                let pk = p256::PublicKey::from_sec1_bytes(bytes).map_err(|e| {
                    CryptoError::KeyAgreement(format!("invalid P-256 public key: {e}"))
                })?;
                Ok(PublicKeyAgreement::P256(pk))
            }
            Curve::K256 => {
                let pk = k256::PublicKey::from_sec1_bytes(bytes).map_err(|e| {
                    CryptoError::KeyAgreement(format!("invalid K-256 public key: {e}"))
                })?;
                Ok(PublicKeyAgreement::K256(pk))
            }
        }
    }

    /// Parse from a JWK JSON value.
    pub fn from_jwk(jwk: &Value) -> Result<Self, CryptoError> {
        let crv = jwk["crv"]
            .as_str()
            .ok_or_else(|| CryptoError::KeyAgreement("missing crv in JWK".into()))?;

        match crv {
            "X25519" => {
                let x = jwk["x"]
                    .as_str()
                    .ok_or_else(|| CryptoError::KeyAgreement("missing x in X25519 JWK".into()))?;
                let bytes = URL_SAFE_NO_PAD
                    .decode(x)
                    .map_err(|e| CryptoError::KeyAgreement(format!("invalid x: {e}")))?;
                let arr: [u8; 32] = bytes
                    .try_into()
                    .map_err(|_| CryptoError::KeyAgreement("X25519 key must be 32 bytes".into()))?;
                Ok(PublicKeyAgreement::X25519(arr))
            }
            "P-256" => {
                let point = ec_point_from_jwk(jwk)?;
                let pk = p256::PublicKey::from_sec1_bytes(&point)
                    .map_err(|e| CryptoError::KeyAgreement(format!("invalid P-256 key: {e}")))?;
                Ok(PublicKeyAgreement::P256(pk))
            }
            "secp256k1" => {
                let point = ec_point_from_jwk(jwk)?;
                let pk = k256::PublicKey::from_sec1_bytes(&point)
                    .map_err(|e| CryptoError::KeyAgreement(format!("invalid K-256 key: {e}")))?;
                Ok(PublicKeyAgreement::K256(pk))
            }
            other => Err(CryptoError::UnsupportedKeyType(format!(
                "unsupported key-agreement curve: {other}"
            ))),
        }
    }
}

/// Build an uncompressed SEC1 point (`0x04 || x || y`) from a JWK's `x`/`y`.
fn ec_point_from_jwk(jwk: &Value) -> Result<Vec<u8>, CryptoError> {
    let x = jwk["x"]
        .as_str()
        .ok_or_else(|| CryptoError::KeyAgreement("missing x in EC JWK".into()))?;
    let y = jwk["y"]
        .as_str()
        .ok_or_else(|| CryptoError::KeyAgreement("missing y in EC JWK".into()))?;
    let x_bytes = URL_SAFE_NO_PAD
        .decode(x)
        .map_err(|e| CryptoError::KeyAgreement(format!("invalid x: {e}")))?;
    let y_bytes = URL_SAFE_NO_PAD
        .decode(y)
        .map_err(|e| CryptoError::KeyAgreement(format!("invalid y: {e}")))?;
    let mut point = Vec::with_capacity(1 + x_bytes.len() + y_bytes.len());
    point.push(0x04);
    point.extend_from_slice(&x_bytes);
    point.extend_from_slice(&y_bytes);
    Ok(point)
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
    /// For X25519: expects 32 bytes (clamped scalar). For P-256/K-256:
    /// expects the scalar bytes.
    pub fn from_raw_bytes(curve: Curve, bytes: &[u8]) -> Result<Self, CryptoError> {
        match curve {
            Curve::X25519 => {
                let arr: [u8; 32] = bytes.try_into().map_err(|_| {
                    CryptoError::KeyAgreement("X25519 private key must be 32 bytes".into())
                })?;
                Ok(PrivateKeyAgreement::X25519(
                    x25519_dalek::StaticSecret::from(arr),
                ))
            }
            Curve::P256 => {
                let sk = p256::SecretKey::from_slice(bytes).map_err(|e| {
                    CryptoError::KeyAgreement(format!("invalid P-256 private key: {e}"))
                })?;
                Ok(PrivateKeyAgreement::P256(sk))
            }
            Curve::K256 => {
                let sk = k256::SecretKey::from_slice(bytes).map_err(|e| {
                    CryptoError::KeyAgreement(format!("invalid K-256 private key: {e}"))
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

    /// Perform ECDH with a public key, returning the raw shared-secret bytes.
    pub fn diffie_hellman(
        &self,
        their_public: &PublicKeyAgreement,
    ) -> Result<Vec<u8>, CryptoError> {
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
            _ => Err(CryptoError::KeyAgreement(
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

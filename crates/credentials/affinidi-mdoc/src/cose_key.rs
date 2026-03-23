/*!
 * Typed COSE_Key support per RFC 9052 §7.
 *
 * Provides a typed wrapper around COSE_Key CBOR structures with validation
 * for key type, curve parameters, and coordinate sizes.
 *
 * # COSE_Key Structure
 *
 * ```text
 * COSE_Key = {
 *   1 => kty: int,           ; Key Type (2=EC2, 1=OKP)
 *  -1 => crv: int,           ; Curve
 *  -2 => x: bstr,            ; X coordinate / public key
 *  -3 => y: bstr,            ; Y coordinate (EC2 only)
 *  -4 => d: bstr,            ; Private key (optional)
 *   2 => kid: bstr,          ; Key ID (optional)
 *   3 => alg: int,           ; Algorithm (optional)
 *   4 => key_ops: [+ int],   ; Key operations (optional)
 * }
 * ```
 *
 * # Supported Key Types
 *
 * - **EC2** (kty=2): P-256 (crv=1), P-384 (crv=2), P-521 (crv=3)
 * - **OKP** (kty=1): Ed25519 (crv=6), X25519 (crv=4)
 */

use crate::error::{MdocError, Result};

/// COSE Key Type values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyType {
    /// Octet Key Pair (kty=1) — Ed25519, X25519.
    Okp = 1,
    /// Elliptic Curve (kty=2) — P-256, P-384, P-521.
    Ec2 = 2,
}

/// COSE Curve identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Curve {
    /// P-256 (crv=1).
    P256 = 1,
    /// P-384 (crv=2).
    P384 = 2,
    /// P-521 (crv=3).
    P521 = 3,
    /// X25519 (crv=4).
    X25519 = 4,
    /// Ed25519 (crv=6).
    Ed25519 = 6,
}

/// COSE Key operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyOp {
    /// Sign (1).
    Sign = 1,
    /// Verify (2).
    Verify = 2,
    /// Encrypt (3).
    Encrypt = 3,
    /// Decrypt (4).
    Decrypt = 4,
    /// Key Wrap (5).
    WrapKey = 5,
    /// Key Unwrap (6).
    UnwrapKey = 6,
    /// Derive Key (7).
    DeriveKey = 7,
    /// Derive Bits (8).
    DeriveBits = 8,
    /// MAC Create (9).
    MacCreate = 9,
    /// MAC Verify (10).
    MacVerify = 10,
}

/// A typed, validated COSE_Key.
///
/// Wraps the raw CBOR representation with type-safe accessors and
/// validation for key type, curve, and coordinate sizes.
#[derive(Debug, Clone)]
pub struct CoseKey {
    /// Key type (EC2 or OKP).
    pub kty: KeyType,
    /// Curve identifier.
    pub crv: Curve,
    /// X coordinate (EC2) or public key bytes (OKP).
    pub x: Vec<u8>,
    /// Y coordinate (EC2 only, None for OKP).
    pub y: Option<Vec<u8>>,
    /// Private key (optional).
    pub d: Option<Vec<u8>>,
    /// Key identifier (optional).
    pub kid: Option<Vec<u8>>,
    /// Algorithm restriction (optional).
    pub alg: Option<i64>,
    /// Key operations (optional).
    pub key_ops: Option<Vec<KeyOp>>,
}

impl CoseKey {
    /// Create a new P-256 public key.
    pub fn new_p256(x: Vec<u8>, y: Vec<u8>) -> Result<Self> {
        let key = Self {
            kty: KeyType::Ec2,
            crv: Curve::P256,
            x,
            y: Some(y),
            d: None,
            kid: None,
            alg: None,
            key_ops: None,
        };
        key.validate()?;
        Ok(key)
    }

    /// Create a new P-384 public key.
    pub fn new_p384(x: Vec<u8>, y: Vec<u8>) -> Result<Self> {
        let key = Self {
            kty: KeyType::Ec2,
            crv: Curve::P384,
            x,
            y: Some(y),
            d: None,
            kid: None,
            alg: None,
            key_ops: None,
        };
        key.validate()?;
        Ok(key)
    }

    /// Create a new P-521 public key.
    pub fn new_p521(x: Vec<u8>, y: Vec<u8>) -> Result<Self> {
        let key = Self {
            kty: KeyType::Ec2,
            crv: Curve::P521,
            x,
            y: Some(y),
            d: None,
            kid: None,
            alg: None,
            key_ops: None,
        };
        key.validate()?;
        Ok(key)
    }

    /// Create a new Ed25519 public key.
    pub fn new_ed25519(x: Vec<u8>) -> Result<Self> {
        let key = Self {
            kty: KeyType::Okp,
            crv: Curve::Ed25519,
            x,
            y: None,
            d: None,
            kid: None,
            alg: None,
            key_ops: None,
        };
        key.validate()?;
        Ok(key)
    }

    /// Create a new X25519 public key.
    pub fn new_x25519(x: Vec<u8>) -> Result<Self> {
        let key = Self {
            kty: KeyType::Okp,
            crv: Curve::X25519,
            x,
            y: None,
            d: None,
            kid: None,
            alg: None,
            key_ops: None,
        };
        key.validate()?;
        Ok(key)
    }

    /// Set a key identifier.
    pub fn with_kid(mut self, kid: Vec<u8>) -> Self {
        self.kid = Some(kid);
        self
    }

    /// Set an algorithm restriction.
    pub fn with_alg(mut self, alg: i64) -> Self {
        self.alg = Some(alg);
        self
    }

    /// Set key operations.
    pub fn with_key_ops(mut self, ops: Vec<KeyOp>) -> Self {
        self.key_ops = Some(ops);
        self
    }

    /// Expected coordinate size for the curve.
    pub fn coordinate_size(&self) -> usize {
        match self.crv {
            Curve::P256 => 32,
            Curve::P384 => 48,
            Curve::P521 => 66,
            Curve::X25519 | Curve::Ed25519 => 32,
        }
    }

    /// Validate key material sizes match the curve.
    pub fn validate(&self) -> Result<()> {
        let expected = self.coordinate_size();

        // Validate x coordinate size
        if self.x.len() != expected {
            return Err(MdocError::Cose(format!(
                "x coordinate must be {} bytes for {:?}, got {}",
                expected,
                self.crv,
                self.x.len()
            )));
        }

        // Validate y for EC2 keys
        match self.kty {
            KeyType::Ec2 => {
                let y = self
                    .y
                    .as_ref()
                    .ok_or_else(|| MdocError::Cose("EC2 key requires y coordinate".into()))?;
                if y.len() != expected {
                    return Err(MdocError::Cose(format!(
                        "y coordinate must be {} bytes for {:?}, got {}",
                        expected,
                        self.crv,
                        y.len()
                    )));
                }
            }
            KeyType::Okp => {
                if self.y.is_some() {
                    return Err(MdocError::Cose("OKP key must not have y coordinate".into()));
                }
            }
        }

        // Validate private key size if present
        if let Some(ref d) = self.d {
            if d.len() != expected {
                return Err(MdocError::Cose(format!(
                    "private key must be {} bytes for {:?}, got {}",
                    expected,
                    self.crv,
                    d.len()
                )));
            }
        }

        // Validate kty matches crv
        match self.crv {
            Curve::P256 | Curve::P384 | Curve::P521 => {
                if self.kty != KeyType::Ec2 {
                    return Err(MdocError::Cose(format!(
                        "curve {:?} requires kty=EC2",
                        self.crv
                    )));
                }
            }
            Curve::Ed25519 | Curve::X25519 => {
                if self.kty != KeyType::Okp {
                    return Err(MdocError::Cose(format!(
                        "curve {:?} requires kty=OKP",
                        self.crv
                    )));
                }
            }
        }

        Ok(())
    }

    /// Encode as a CBOR Value (integer-keyed map per RFC 9052).
    pub fn to_cbor_value(&self) -> ciborium::Value {
        let mut entries: Vec<(ciborium::Value, ciborium::Value)> = vec![
            // kty (1)
            (
                ciborium::Value::Integer(1.into()),
                ciborium::Value::Integer((self.kty as i64).into()),
            ),
            // crv (-1)
            (
                ciborium::Value::Integer((-1).into()),
                ciborium::Value::Integer((self.crv as i64).into()),
            ),
            // x (-2)
            (
                ciborium::Value::Integer((-2).into()),
                ciborium::Value::Bytes(self.x.clone()),
            ),
        ];

        // y (-3) for EC2
        if let Some(ref y) = self.y {
            entries.push((
                ciborium::Value::Integer((-3).into()),
                ciborium::Value::Bytes(y.clone()),
            ));
        }

        // d (-4) if present
        if let Some(ref d) = self.d {
            entries.push((
                ciborium::Value::Integer((-4).into()),
                ciborium::Value::Bytes(d.clone()),
            ));
        }

        // kid (2) if present
        if let Some(ref kid) = self.kid {
            entries.push((
                ciborium::Value::Integer(2.into()),
                ciborium::Value::Bytes(kid.clone()),
            ));
        }

        // alg (3) if present
        if let Some(alg) = self.alg {
            entries.push((
                ciborium::Value::Integer(3.into()),
                ciborium::Value::Integer(alg.into()),
            ));
        }

        // key_ops (4) if present
        if let Some(ref ops) = self.key_ops {
            let ops_arr: Vec<ciborium::Value> = ops
                .iter()
                .map(|op| ciborium::Value::Integer((*op as i64).into()))
                .collect();
            entries.push((
                ciborium::Value::Integer(4.into()),
                ciborium::Value::Array(ops_arr),
            ));
        }

        ciborium::Value::Map(entries)
    }

    /// Parse from a CBOR Value (integer-keyed map).
    pub fn from_cbor_value(value: &ciborium::Value) -> Result<Self> {
        let entries = match value {
            ciborium::Value::Map(m) => m,
            _ => return Err(MdocError::Cose("COSE_Key must be a CBOR map".into())),
        };

        let get_int = |label: i64| -> Option<i128> {
            entries.iter().find_map(|(k, v)| {
                if let ciborium::Value::Integer(ki) = k {
                    let ki_val: i128 = (*ki).into();
                    if ki_val == label as i128 {
                        if let ciborium::Value::Integer(vi) = v {
                            return Some((*vi).into());
                        }
                    }
                }
                None
            })
        };

        let get_bytes = |label: i64| -> Option<Vec<u8>> {
            entries.iter().find_map(|(k, v)| {
                if let ciborium::Value::Integer(ki) = k {
                    let ki_val: i128 = (*ki).into();
                    if ki_val == label as i128 {
                        if let ciborium::Value::Bytes(b) = v {
                            return Some(b.clone());
                        }
                    }
                }
                None
            })
        };

        // Parse kty (1) — required
        let kty_val =
            get_int(1).ok_or_else(|| MdocError::Cose("COSE_Key missing kty (1)".into()))?;
        let kty = match kty_val {
            1 => KeyType::Okp,
            2 => KeyType::Ec2,
            _ => return Err(MdocError::Cose(format!("unsupported kty: {kty_val}"))),
        };

        // Parse crv (-1) — required
        let crv_val =
            get_int(-1).ok_or_else(|| MdocError::Cose("COSE_Key missing crv (-1)".into()))?;
        let crv = match crv_val {
            1 => Curve::P256,
            2 => Curve::P384,
            3 => Curve::P521,
            4 => Curve::X25519,
            6 => Curve::Ed25519,
            _ => return Err(MdocError::Cose(format!("unsupported crv: {crv_val}"))),
        };

        // Parse x (-2) — required
        let x = get_bytes(-2).ok_or_else(|| MdocError::Cose("COSE_Key missing x (-2)".into()))?;

        // Parse y (-3) — optional (required for EC2)
        let y = get_bytes(-3);

        // Parse d (-4) — optional
        let d = get_bytes(-4);

        // Parse kid (2) — optional
        let kid = get_bytes(2);

        // Parse alg (3) — optional
        let alg = get_int(3).map(|v| v as i64);

        // Parse key_ops (4) — optional
        let key_ops = entries.iter().find_map(|(k, v)| {
            if let ciborium::Value::Integer(ki) = k {
                let ki_val: i128 = (*ki).into();
                if ki_val == 4 {
                    if let ciborium::Value::Array(arr) = v {
                        let ops: Vec<KeyOp> = arr
                            .iter()
                            .filter_map(|item| {
                                if let ciborium::Value::Integer(vi) = item {
                                    let val: i128 = (*vi).into();
                                    KeyOp::from_i64(val as i64)
                                } else {
                                    None
                                }
                            })
                            .collect();
                        if !ops.is_empty() {
                            return Some(ops);
                        }
                    }
                }
            }
            None
        });

        let key = Self {
            kty,
            crv,
            x,
            y,
            d,
            kid,
            alg,
            key_ops,
        };
        key.validate()?;
        Ok(key)
    }

    /// Encode to CBOR bytes.
    pub fn to_cbor_bytes(&self) -> Result<Vec<u8>> {
        let value = self.to_cbor_value();
        let mut buf = Vec::new();
        ciborium::into_writer(&value, &mut buf)
            .map_err(|e| MdocError::Cbor(format!("COSE_Key encoding: {e}")))?;
        Ok(buf)
    }

    /// Parse from CBOR bytes.
    pub fn from_cbor_bytes(bytes: &[u8]) -> Result<Self> {
        let value: ciborium::Value = ciborium::from_reader(bytes)
            .map_err(|e| MdocError::Cbor(format!("COSE_Key decode: {e}")))?;
        Self::from_cbor_value(&value)
    }

    /// Check if this key has a private component.
    pub fn is_private(&self) -> bool {
        self.d.is_some()
    }

    /// Get the COSE algorithm that matches this key's curve.
    pub fn default_algorithm(&self) -> Option<coset::iana::Algorithm> {
        match self.crv {
            Curve::P256 => Some(coset::iana::Algorithm::ES256),
            Curve::P384 => Some(coset::iana::Algorithm::ES384),
            Curve::P521 => Some(coset::iana::Algorithm::ES512),
            Curve::Ed25519 => Some(coset::iana::Algorithm::EdDSA),
            Curve::X25519 => None, // Key agreement, not signing
        }
    }
}

impl KeyOp {
    fn from_i64(val: i64) -> Option<Self> {
        match val {
            1 => Some(KeyOp::Sign),
            2 => Some(KeyOp::Verify),
            3 => Some(KeyOp::Encrypt),
            4 => Some(KeyOp::Decrypt),
            5 => Some(KeyOp::WrapKey),
            6 => Some(KeyOp::UnwrapKey),
            7 => Some(KeyOp::DeriveKey),
            8 => Some(KeyOp::DeriveBits),
            9 => Some(KeyOp::MacCreate),
            10 => Some(KeyOp::MacVerify),
            _ => None,
        }
    }
}

impl Curve {
    /// Human-readable name for the curve.
    pub fn name(&self) -> &'static str {
        match self {
            Curve::P256 => "P-256",
            Curve::P384 => "P-384",
            Curve::P521 => "P-521",
            Curve::X25519 => "X25519",
            Curve::Ed25519 => "Ed25519",
        }
    }
}

impl KeyType {
    /// Human-readable name for the key type.
    pub fn name(&self) -> &'static str {
        match self {
            KeyType::Okp => "OKP",
            KeyType::Ec2 => "EC2",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_p256_key() {
        let key = CoseKey::new_p256(vec![0xaa; 32], vec![0xbb; 32]).unwrap();
        assert_eq!(key.kty, KeyType::Ec2);
        assert_eq!(key.crv, Curve::P256);
        assert_eq!(key.x.len(), 32);
        assert_eq!(key.y.as_ref().unwrap().len(), 32);
        assert_eq!(key.coordinate_size(), 32);
    }

    #[test]
    fn create_p384_key() {
        let key = CoseKey::new_p384(vec![0xaa; 48], vec![0xbb; 48]).unwrap();
        assert_eq!(key.crv, Curve::P384);
        assert_eq!(key.coordinate_size(), 48);
    }

    #[test]
    fn create_p521_key() {
        let key = CoseKey::new_p521(vec![0xaa; 66], vec![0xbb; 66]).unwrap();
        assert_eq!(key.crv, Curve::P521);
        assert_eq!(key.coordinate_size(), 66);
    }

    #[test]
    fn create_ed25519_key() {
        let key = CoseKey::new_ed25519(vec![0xaa; 32]).unwrap();
        assert_eq!(key.kty, KeyType::Okp);
        assert_eq!(key.crv, Curve::Ed25519);
        assert!(key.y.is_none());
    }

    #[test]
    fn create_x25519_key() {
        let key = CoseKey::new_x25519(vec![0xaa; 32]).unwrap();
        assert_eq!(key.kty, KeyType::Okp);
        assert_eq!(key.crv, Curve::X25519);
    }

    #[test]
    fn wrong_x_size_fails() {
        let result = CoseKey::new_p256(vec![0xaa; 16], vec![0xbb; 32]);
        assert!(result.is_err());
    }

    #[test]
    fn wrong_y_size_fails() {
        let result = CoseKey::new_p256(vec![0xaa; 32], vec![0xbb; 16]);
        assert!(result.is_err());
    }

    #[test]
    fn ed25519_with_y_fails() {
        let key = CoseKey {
            kty: KeyType::Okp,
            crv: Curve::Ed25519,
            x: vec![0xaa; 32],
            y: Some(vec![0xbb; 32]),
            d: None,
            kid: None,
            alg: None,
            key_ops: None,
        };
        assert!(key.validate().is_err());
    }

    #[test]
    fn cbor_roundtrip() {
        let key = CoseKey::new_p256(vec![0xaa; 32], vec![0xbb; 32])
            .unwrap()
            .with_kid(b"test-key-id".to_vec())
            .with_alg(-7); // ES256

        let bytes = key.to_cbor_bytes().unwrap();
        let parsed = CoseKey::from_cbor_bytes(&bytes).unwrap();

        assert_eq!(parsed.kty, KeyType::Ec2);
        assert_eq!(parsed.crv, Curve::P256);
        assert_eq!(parsed.x, vec![0xaa; 32]);
        assert_eq!(parsed.y, Some(vec![0xbb; 32]));
        assert_eq!(parsed.kid, Some(b"test-key-id".to_vec()));
        assert_eq!(parsed.alg, Some(-7));
    }

    #[test]
    fn cbor_value_roundtrip() {
        let key = CoseKey::new_ed25519(vec![0xcc; 32]).unwrap();
        let val = key.to_cbor_value();
        let parsed = CoseKey::from_cbor_value(&val).unwrap();
        assert_eq!(parsed.crv, Curve::Ed25519);
        assert_eq!(parsed.x, vec![0xcc; 32]);
    }

    #[test]
    fn parse_invalid_type_fails() {
        let result = CoseKey::from_cbor_value(&ciborium::Value::Text("bad".into()));
        assert!(result.is_err());
    }

    #[test]
    fn parse_missing_kty_fails() {
        let val = ciborium::Value::Map(vec![(
            ciborium::Value::Integer((-1).into()),
            ciborium::Value::Integer(1.into()),
        )]);
        assert!(CoseKey::from_cbor_value(&val).is_err());
    }

    #[test]
    fn parse_unsupported_kty_fails() {
        let val = ciborium::Value::Map(vec![
            (
                ciborium::Value::Integer(1.into()),
                ciborium::Value::Integer(99.into()),
            ),
            (
                ciborium::Value::Integer((-1).into()),
                ciborium::Value::Integer(1.into()),
            ),
            (
                ciborium::Value::Integer((-2).into()),
                ciborium::Value::Bytes(vec![0; 32]),
            ),
        ]);
        assert!(CoseKey::from_cbor_value(&val).is_err());
    }

    #[test]
    fn default_algorithm() {
        let p256 = CoseKey::new_p256(vec![0; 32], vec![0; 32]).unwrap();
        assert_eq!(
            p256.default_algorithm(),
            Some(coset::iana::Algorithm::ES256)
        );

        let p384 = CoseKey::new_p384(vec![0; 48], vec![0; 48]).unwrap();
        assert_eq!(
            p384.default_algorithm(),
            Some(coset::iana::Algorithm::ES384)
        );

        let ed = CoseKey::new_ed25519(vec![0; 32]).unwrap();
        assert_eq!(ed.default_algorithm(), Some(coset::iana::Algorithm::EdDSA));

        let x = CoseKey::new_x25519(vec![0; 32]).unwrap();
        assert_eq!(x.default_algorithm(), None); // Key agreement only
    }

    #[test]
    fn is_private() {
        let mut key = CoseKey::new_p256(vec![0; 32], vec![0; 32]).unwrap();
        assert!(!key.is_private());

        key.d = Some(vec![0; 32]);
        assert!(key.is_private());
    }

    #[test]
    fn with_key_ops() {
        let key = CoseKey::new_p256(vec![0; 32], vec![0; 32])
            .unwrap()
            .with_key_ops(vec![KeyOp::Sign, KeyOp::Verify]);

        let val = key.to_cbor_value();
        let parsed = CoseKey::from_cbor_value(&val).unwrap();
        let ops = parsed.key_ops.unwrap();
        assert_eq!(ops.len(), 2);
        assert_eq!(ops[0], KeyOp::Sign);
        assert_eq!(ops[1], KeyOp::Verify);
    }

    #[test]
    fn curve_names() {
        assert_eq!(Curve::P256.name(), "P-256");
        assert_eq!(Curve::P384.name(), "P-384");
        assert_eq!(Curve::P521.name(), "P-521");
        assert_eq!(Curve::Ed25519.name(), "Ed25519");
        assert_eq!(Curve::X25519.name(), "X25519");
    }
}

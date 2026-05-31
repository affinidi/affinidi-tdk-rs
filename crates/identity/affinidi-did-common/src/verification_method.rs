//! DID Verification Method Definition
//! <https://www.w3.org/TR/cid-1.0/#verification-methods>
use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::Url;

use crate::DocumentError;

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct VerificationMethod {
    pub id: Url,

    #[serde(rename = "type")]
    pub type_: String,

    pub controller: Url,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked: Option<String>,

    /// Each Service can have multiple other properties
    #[serde(flatten)]
    pub property_set: HashMap<String, Value>,
}

impl VerificationMethod {
    /// Attempts to extract Public Key Bytes from the Verification Method
    /// WARN: This function only supports Multikey VM types for now
    pub fn get_public_key_bytes(&self) -> Result<Vec<u8>, DocumentError> {
        match self.type_.as_str() {
            "Multikey" => {
                // PublicKeyMultibase encoded
                if let Some(key) = self.property_set.get("publicKeyMultibase")
                    && let Some(key) = key.as_str()
                {
                    Ok(affinidi_encoding::decode_multikey(key)?)
                } else {
                    Err(DocumentError::VM(
                        "Multikey type, but does not include the `publicKeyMultibase` attribute"
                            .to_string(),
                    ))
                }
            }
            _ => Err(DocumentError::VM(format!(
                "VerificationMethod type ({}) isn't supported!",
                self.type_
            ))),
        }
    }

    /// Extract this verification method's public key as a
    /// `(multicodec, raw-bytes)` pair, handling **both**
    /// `publicKeyMultibase` (Multikey) and `publicKeyJwk`.
    ///
    /// The multicodec is one of [`affinidi_encoding`]'s `*_PUB`
    /// constants; the bytes are the raw public key (32 octets for
    /// Ed25519/X25519, an SEC1 point for the EC curves). This is the
    /// single place that turns DID verification material into key bytes,
    /// so the messaging SDK and DID-authentication layers map *one*
    /// result onto their key types instead of each re-parsing JWK /
    /// multibase (which previously drifted — see the ECDH-1PU interop
    /// work).
    pub fn decode_public_key(&self) -> Result<(u64, Vec<u8>), DocumentError> {
        // Prefer an explicit multibase Multikey; fall back to JWK.
        if let Some(mb) = self
            .property_set
            .get("publicKeyMultibase")
            .and_then(Value::as_str)
        {
            return affinidi_encoding::decode_multikey_with_codec(mb)
                .map_err(|e| DocumentError::VM(format!("invalid publicKeyMultibase: {e}")));
        }

        if let Some(jwk_value) = self.property_set.get("publicKeyJwk") {
            let jwk: affinidi_crypto::JWK = serde_json::from_value(jwk_value.clone())
                .map_err(|e| DocumentError::VM(format!("invalid publicKeyJwk: {e}")))?;
            return Self::jwk_to_codec_bytes(&jwk);
        }

        Err(DocumentError::VM(
            "verification method has neither publicKeyMultibase nor publicKeyJwk".to_string(),
        ))
    }

    /// Map an [`affinidi_crypto::JWK`] to `(multicodec, raw-bytes)`.
    /// OKP `x` is the raw 32-octet key; EC `(x, y)` becomes an
    /// uncompressed SEC1 point (`0x04 || x || y`).
    fn jwk_to_codec_bytes(jwk: &affinidi_crypto::JWK) -> Result<(u64, Vec<u8>), DocumentError> {
        use affinidi_crypto::{KeyType, Params};
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

        let b64 = |s: &str| {
            URL_SAFE_NO_PAD
                .decode(s)
                .map_err(|e| DocumentError::VM(format!("invalid base64url in JWK: {e}")))
        };
        let sec1 = |x: &[u8], y: &[u8]| {
            let mut v = Vec::with_capacity(1 + x.len() + y.len());
            v.push(0x04);
            v.extend_from_slice(x);
            v.extend_from_slice(y);
            v
        };

        match (&jwk.params, jwk.key_type()) {
            (Params::OKP(p), KeyType::Ed25519) => Ok((affinidi_encoding::ED25519_PUB, b64(&p.x)?)),
            (Params::OKP(p), KeyType::X25519) => Ok((affinidi_encoding::X25519_PUB, b64(&p.x)?)),
            (Params::EC(p), KeyType::P256) => {
                Ok((affinidi_encoding::P256_PUB, sec1(&b64(&p.x)?, &b64(&p.y)?)))
            }
            (Params::EC(p), KeyType::P384) => {
                Ok((affinidi_encoding::P384_PUB, sec1(&b64(&p.x)?, &b64(&p.y)?)))
            }
            (Params::EC(p), KeyType::Secp256k1) => Ok((
                affinidi_encoding::SECP256K1_PUB,
                sec1(&b64(&p.x)?, &b64(&p.y)?),
            )),
            (_, kt) => Err(DocumentError::VM(format!(
                "unsupported JWK key type for public key extraction: {kt:?}"
            ))),
        }
    }
}

/// https://www.w3.org/TR/cid-1.0/#verification-relationships
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(untagged)]
pub enum VerificationRelationship {
    /// Reference to a Verification Method (may be an absolute DID URL or a
    /// relative fragment like `"#0"`, so we keep it as a plain `String`).
    Reference(String),
    /// Embedded Verification Method
    VerificationMethod(Box<VerificationMethod>),
}

impl VerificationRelationship {
    /// Returns the id of the verification-method
    pub fn get_id(&self) -> &str {
        match self {
            VerificationRelationship::Reference(url) => url.as_str(),
            VerificationRelationship::VerificationMethod(map) => map.id.as_str(),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::verification_method::{VerificationMethod, VerificationRelationship};
    use std::collections::HashMap;
    use url::Url;

    #[test]
    pub fn test_multikey_vm_get_public_key_bytes() {
        let vm: VerificationMethod = serde_json::from_str(
            r#"{ "controller": "did:example:1234",
                "id": "did:example:1234#key-0",
                "publicKeyMultibase": "z6MkwdwKx2P9X13goHtcowBBrPFRwqPNcnX1qWd39CnS4yjx",
                "type": "Multikey"
            }"#,
        )
        .unwrap();

        let bytes: [u8; 32] = [
            255, 82, 230, 245, 93, 184, 94, 85, 34, 131, 163, 26, 149, 85, 166, 94, 166, 248, 49,
            62, 250, 157, 214, 128, 22, 212, 174, 75, 199, 252, 34, 131,
        ];
        let result = vm.get_public_key_bytes().unwrap();

        assert_eq!(bytes, result.as_slice());
    }

    #[test]
    fn decode_public_key_multibase_ed25519() {
        let vm: VerificationMethod = serde_json::from_str(
            r#"{ "controller": "did:example:1234",
                "id": "did:example:1234#key-0",
                "publicKeyMultibase": "z6MkwdwKx2P9X13goHtcowBBrPFRwqPNcnX1qWd39CnS4yjx",
                "type": "Multikey"
            }"#,
        )
        .unwrap();

        let (codec, bytes) = vm.decode_public_key().unwrap();
        assert_eq!(codec, affinidi_encoding::ED25519_PUB);
        assert_eq!(bytes.len(), 32);
    }

    #[test]
    fn decode_public_key_jwk_ed25519() {
        // OKP/Ed25519 JWK → 32 raw octets, ED25519 multicodec.
        let vm: VerificationMethod = serde_json::from_str(
            r#"{ "controller": "did:example:1234",
                "id": "did:example:1234#key-0",
                "type": "JsonWebKey2020",
                "publicKeyJwk": {
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "x": "Xx4_L89E6RsyvDTzN9wuN3cDwgifPkXMgFJv_HMIxdk"
                }
            }"#,
        )
        .unwrap();

        let (codec, bytes) = vm.decode_public_key().unwrap();
        assert_eq!(codec, affinidi_encoding::ED25519_PUB);
        assert_eq!(bytes.len(), 32);
    }

    #[test]
    fn decode_public_key_jwk_p256_is_uncompressed_sec1() {
        // EC/P-256 JWK → uncompressed SEC1 point (0x04 || x || y).
        let vm: VerificationMethod = serde_json::from_str(
            r#"{ "controller": "did:example:1234",
                "id": "did:example:1234#key-0",
                "type": "JsonWebKey2020",
                "publicKeyJwk": {
                    "kty": "EC",
                    "crv": "P-256",
                    "x": "sl56LMzaiR5efwwWU1jzC_dfbxQ8gzyLj_N1q2cJmkE",
                    "y": "UnAimUtlHMPj_T_wIDVPoJAolKHy8DoXXTb8wch4hgU"
                }
            }"#,
        )
        .unwrap();

        let (codec, bytes) = vm.decode_public_key().unwrap();
        assert_eq!(codec, affinidi_encoding::P256_PUB);
        assert_eq!(bytes.len(), 65, "uncompressed SEC1 point is 65 octets");
        assert_eq!(bytes[0], 0x04, "uncompressed SEC1 marker");
    }

    #[test]
    fn decode_public_key_missing_material_errors() {
        let vm = VerificationMethod {
            id: Url::parse("did:example:123#key-0").unwrap(),
            type_: "JsonWebKey2020".to_string(),
            controller: Url::parse("did:example:123").unwrap(),
            expires: None,
            revoked: None,
            property_set: HashMap::new(),
        };
        assert!(vm.decode_public_key().is_err());
    }

    #[test]
    fn get_public_key_bytes_unsupported_type() {
        let vm = VerificationMethod {
            id: Url::parse("did:example:123#key-0").unwrap(),
            type_: "JsonWebKey2020".to_string(),
            controller: Url::parse("did:example:123").unwrap(),
            expires: None,
            revoked: None,
            property_set: HashMap::new(),
        };
        assert!(vm.get_public_key_bytes().is_err());
    }

    #[test]
    fn get_public_key_bytes_multikey_missing_attribute() {
        let vm = VerificationMethod {
            id: Url::parse("did:example:123#key-0").unwrap(),
            type_: "Multikey".to_string(),
            controller: Url::parse("did:example:123").unwrap(),
            expires: None,
            revoked: None,
            property_set: HashMap::new(),
        };
        assert!(vm.get_public_key_bytes().is_err());
    }

    #[test]
    fn get_id_reference() {
        let rel = VerificationRelationship::Reference("did:test:1234#key-1".to_string());
        assert_eq!(rel.get_id(), "did:test:1234#key-1");
    }

    #[test]
    fn get_id_embedded() {
        let vm = VerificationMethod {
            id: Url::parse("did:test:1234#key-2").unwrap(),
            type_: "Multikey".to_string(),
            controller: Url::parse("did:test:1234").unwrap(),
            expires: None,
            revoked: None,
            property_set: HashMap::new(),
        };
        let rel = VerificationRelationship::VerificationMethod(Box::new(vm));
        assert_eq!(rel.get_id(), "did:test:1234#key-2");
    }

    #[test]
    fn verification_method_serde_roundtrip() {
        let json = r#"{
            "id": "did:example:123#key-0",
            "type": "Multikey",
            "controller": "did:example:123",
            "publicKeyMultibase": "z6MkwdwKx2P9X13goHtcowBBrPFRwqPNcnX1qWd39CnS4yjx"
        }"#;
        let vm: VerificationMethod = serde_json::from_str(json).unwrap();
        let serialized = serde_json::to_string(&vm).unwrap();
        let back: VerificationMethod = serde_json::from_str(&serialized).unwrap();
        assert_eq!(vm, back);
    }

    #[test]
    fn verification_relationship_reference_serde() {
        let rel = VerificationRelationship::Reference("did:test:1234#key-1".to_string());
        let json = serde_json::to_string(&rel).unwrap();
        assert_eq!(json, "\"did:test:1234#key-1\"");
        let back: VerificationRelationship = serde_json::from_str(&json).unwrap();
        assert_eq!(rel, back);
    }

    #[test]
    fn verification_relationship_embedded_serde() {
        let vm = VerificationMethod {
            id: Url::parse("did:test:1234#key-1").unwrap(),
            type_: "Multikey".to_string(),
            controller: Url::parse("did:test:1234").unwrap(),
            expires: None,
            revoked: None,
            property_set: HashMap::new(),
        };
        let rel = VerificationRelationship::VerificationMethod(Box::new(vm));
        let json = serde_json::to_string(&rel).unwrap();
        let back: VerificationRelationship = serde_json::from_str(&json).unwrap();
        assert_eq!(rel, back);
    }

    #[test]
    fn verification_method_with_optional_fields() {
        let json = r#"{
            "id": "did:example:123#key-0",
            "type": "Multikey",
            "controller": "did:example:123",
            "expires": "2025-12-31T00:00:00Z",
            "revoked": "2025-06-01T00:00:00Z"
        }"#;
        let vm: VerificationMethod = serde_json::from_str(json).unwrap();
        assert_eq!(vm.expires.as_deref(), Some("2025-12-31T00:00:00Z"));
        assert_eq!(vm.revoked.as_deref(), Some("2025-06-01T00:00:00Z"));
    }
}

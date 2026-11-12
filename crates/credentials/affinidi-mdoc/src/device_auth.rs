/*!
 * Device Authentication per ISO 18013-5 §9.1.3.
 *
 * ```text
 * DeviceAuthentication = [
 *   "DeviceAuthentication",       ; context string
 *   SessionTranscript,            ; session binding
 *   DocType,                      ; tstr
 *   DeviceNameSpacesBytes         ; Tag24<DeviceNameSpaces>
 * ]
 *
 * DeviceNameSpaces = Map<namespace, DeviceSignedItems>
 * DeviceSignedItems = Map<elementIdentifier, elementValue>
 *
 * DeviceSigned = {
 *   "nameSpaces": Tag24<DeviceNameSpaces>,
 *   "deviceAuth": DeviceAuth
 * }
 *
 * DeviceAuth = {
 *   ? "deviceSignature": COSE_Sign1,   ; for device signature
 *   ? "deviceMac": COSE_Mac0           ; for device MAC
 * }
 * ```
 *
 * The device proves possession of its private key by signing or MACing
 * the `DeviceAuthenticationBytes = Tag24<DeviceAuthentication>`.
 * The COSE_Sign1 / COSE_Mac0 use a **detached payload** — the payload
 * field is `None`, and the actual signed data is the external aad.
 */

use std::collections::BTreeMap;

use coset::{CoseSign1, CoseSign1Builder, HeaderBuilder};
// `new_from_slice` moved from `Mac` to `KeyInit` in the digest 0.11 generation.
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

use crate::cose::{CoseSigner, CoseVerifier};
use crate::error::{MdocError, Result};
use crate::session_transcript::SessionTranscript;

type HmacSha256 = Hmac<Sha256>;

/// Device-signed namespaces: `Map<namespace, Map<identifier, value>>`.
pub type DeviceNameSpaces = BTreeMap<String, BTreeMap<String, ciborium::Value>>;

/// Device Authentication structure per ISO 18013-5 §9.1.3.6.
///
/// Encoded as a CBOR array:
/// `["DeviceAuthentication", SessionTranscript, DocType, DeviceNameSpacesBytes]`
#[derive(Debug, Clone)]
pub struct DeviceAuthentication {
    /// The session transcript binding this authentication to the session.
    pub session_transcript: SessionTranscript,
    /// The document type (must match MSO docType).
    pub doc_type: String,
    /// Device-signed namespaces (typically empty for mDL).
    pub device_namespaces: DeviceNameSpaces,
}

/// Device-signed data included in a DeviceResponse.
///
/// Contains optional device namespaces and the device's authentication
/// proof (signature or MAC).
#[derive(Debug, Clone)]
pub struct DeviceSigned {
    /// Tag24-wrapped device namespaces (usually empty).
    pub namespaces_bytes: Vec<u8>,
    /// The device authentication proof.
    pub device_auth: DeviceAuth,
}

/// Device authentication proof — either a COSE_Sign1 signature or COSE_Mac0.
///
/// Exactly one of these must be present.
#[derive(Debug, Clone)]
pub enum DeviceAuth {
    /// COSE_Sign1 with detached payload (DeviceAuthenticationBytes as external aad).
    Signature(Box<CoseSign1>),
    /// COSE_Mac0 with detached payload (HMAC-SHA-256 over DeviceAuthenticationBytes).
    ///
    /// Per ISO 18013-5, the MAC key is derived from ECDH between the device key
    /// and the reader's ephemeral key. The tag is HMAC-SHA-256 (32 bytes).
    Mac(CoseMac0Tag),
}

/// COSE_Mac0 tag for device MAC authentication.
///
/// Simplified representation since coset doesn't expose CoseMac0 directly.
/// Contains the HMAC-SHA-256 tag computed over the COSE_Mac0 structure
/// with `DeviceAuthenticationBytes` as external additional authenticated data.
#[derive(Debug, Clone)]
pub struct CoseMac0Tag {
    /// The protected header bytes (CBOR-encoded).
    pub protected: Vec<u8>,
    /// The HMAC-SHA-256 tag (32 bytes).
    pub tag: Vec<u8>,
}

impl DeviceAuthentication {
    /// Create a new DeviceAuthentication.
    ///
    /// # Arguments
    ///
    /// * `session_transcript` — The session transcript for this session
    /// * `doc_type` — The document type (e.g., "org.iso.18013.5.1.mDL")
    /// * `device_namespaces` — Device-signed data (usually empty)
    pub fn new(
        session_transcript: SessionTranscript,
        doc_type: impl Into<String>,
        device_namespaces: DeviceNameSpaces,
    ) -> Self {
        Self {
            session_transcript,
            doc_type: doc_type.into(),
            device_namespaces,
        }
    }

    /// Encode DeviceAuthentication as a CBOR Value (array).
    ///
    /// ```text
    /// ["DeviceAuthentication", SessionTranscript, DocType, DeviceNameSpacesBytes]
    /// ```
    pub fn to_cbor_value(&self) -> Result<ciborium::Value> {
        let ns_bytes = encode_namespaces_bytes(&self.device_namespaces)?;
        self.to_cbor_value_with_namespaces(&ns_bytes)
    }

    /// The `DeviceAuthentication` array around already-encoded
    /// `DeviceNameSpaces` bytes, so a verifier signs over what it received.
    fn to_cbor_value_with_namespaces(&self, ns_bytes: &[u8]) -> Result<ciborium::Value> {
        let transcript_val = self.session_transcript.to_cbor_value()?;

        Ok(ciborium::Value::Array(vec![
            ciborium::Value::Text("DeviceAuthentication".to_string()),
            transcript_val,
            ciborium::Value::Text(self.doc_type.clone()),
            ciborium::Value::Tag(24, Box::new(ciborium::Value::Bytes(ns_bytes.to_vec()))),
        ]))
    }

    /// Produce `DeviceAuthenticationBytes` — the Tag24-wrapped CBOR encoding.
    ///
    /// This is the data that gets signed or MACed for device authentication.
    pub fn to_device_authentication_bytes(&self) -> Result<Vec<u8>> {
        let ns_bytes = encode_namespaces_bytes(&self.device_namespaces)?;
        self.device_authentication_bytes_with_namespaces(&ns_bytes)
    }

    fn device_authentication_bytes_with_namespaces(&self, ns_bytes: &[u8]) -> Result<Vec<u8>> {
        let value = self.to_cbor_value_with_namespaces(ns_bytes)?;
        let mut inner_bytes = Vec::new();
        ciborium::into_writer(&value, &mut inner_bytes)
            .map_err(|e| MdocError::DeviceAuth(format!("DeviceAuthentication encoding: {e}")))?;

        // Wrap in Tag24
        let tagged = ciborium::Value::Tag(24, Box::new(ciborium::Value::Bytes(inner_bytes)));
        let mut buf = Vec::new();
        ciborium::into_writer(&tagged, &mut buf)
            .map_err(|e| MdocError::DeviceAuth(format!("Tag24 wrapping: {e}")))?;
        Ok(buf)
    }
}

impl DeviceSigned {
    /// Create a DeviceSigned by signing DeviceAuthenticationBytes with COSE_Sign1.
    ///
    /// The COSE_Sign1 uses a **detached payload**: the payload field is empty,
    /// and `DeviceAuthenticationBytes` is passed as external additional authenticated data.
    pub fn sign(device_auth: &DeviceAuthentication, signer: &dyn CoseSigner) -> Result<Self> {
        let auth_bytes = device_auth.to_device_authentication_bytes()?;
        let namespaces_bytes = encode_namespaces_bytes(&device_auth.device_namespaces)?;

        // Build COSE_Sign1 with detached payload
        let protected = HeaderBuilder::new().algorithm(signer.algorithm()).build();

        let sign1 = CoseSign1Builder::new()
            .protected(protected)
            // No payload — detached
            .try_create_detached_signature(&auth_bytes, &[], |data| signer.sign(data))
            .map_err(|e| MdocError::DeviceAuth(format!("signing failed: {e}")))?
            .build();

        Ok(DeviceSigned {
            namespaces_bytes,
            device_auth: DeviceAuth::Signature(Box::new(sign1)),
        })
    }

    /// Create a DeviceSigned by MACing DeviceAuthenticationBytes with HMAC-SHA-256.
    ///
    /// Per ISO 18013-5 §9.1.3, the MAC key is derived from ECDH between
    /// the device key and the reader's ephemeral key. The caller provides
    /// the pre-derived symmetric key.
    ///
    /// # Arguments
    ///
    /// * `device_auth` — The DeviceAuthentication structure
    /// * `mac_key` — 32-byte HMAC-SHA-256 key (derived from ECDH); a reader
    ///   derives the same key with [`derive_emac_key`]
    pub fn mac(device_auth: &DeviceAuthentication, mac_key: &[u8; 32]) -> Result<Self> {
        let auth_bytes = device_auth.to_device_authentication_bytes()?;
        let namespaces_bytes = encode_namespaces_bytes(&device_auth.device_namespaces)?;

        // Build protected header: alg = HMAC 256/256 (5)
        let protected = HeaderBuilder::new()
            .algorithm(coset::iana::Algorithm::HMAC_256_256)
            .build();
        let mut protected_bytes = Vec::new();
        let protected_serialized = coset::ProtectedHeader {
            original_data: None,
            header: protected,
        };
        // Serialize the protected header to CBOR
        let protected_cbor = protected_serialized
            .cbor_bstr()
            .map_err(|e| MdocError::DeviceAuth(format!("protected header encoding: {e}")))?;
        ciborium::into_writer(&protected_cbor, &mut protected_bytes)
            .map_err(|e| MdocError::DeviceAuth(format!("protected header CBOR: {e}")))?;

        // Construct MAC_structure = ["MAC0", protected, external_aad, payload]
        // For detached payload: payload is the DeviceAuthenticationBytes
        let mac_structure = ciborium::Value::Array(vec![
            ciborium::Value::Text("MAC0".to_string()),
            protected_cbor,
            ciborium::Value::Bytes(vec![]), // external_aad (empty)
            ciborium::Value::Bytes(auth_bytes),
        ]);

        let mut tbs = Vec::new();
        ciborium::into_writer(&mac_structure, &mut tbs)
            .map_err(|e| MdocError::DeviceAuth(format!("MAC_structure encoding: {e}")))?;

        // Compute HMAC-SHA-256
        let mut hmac = HmacSha256::new_from_slice(mac_key)
            .map_err(|e| MdocError::DeviceAuth(format!("HMAC init: {e}")))?;
        hmac.update(&tbs);
        let tag = hmac.finalize().into_bytes().to_vec();

        Ok(DeviceSigned {
            namespaces_bytes,
            device_auth: DeviceAuth::Mac(CoseMac0Tag {
                protected: protected_bytes,
                tag,
            }),
        })
    }

    /// The `DeviceNameSpaces` carried in [`Self::namespaces_bytes`].
    ///
    /// Strict: anything other than a map of text keys to maps of text keys is
    /// an error rather than being skipped.
    pub fn device_namespaces(&self) -> Result<DeviceNameSpaces> {
        decode_device_namespaces(&self.namespaces_bytes)
    }

    /// `DeviceAuthenticationBytes` over the received namespace bytes, after
    /// checking they carry the namespaces `device_auth` names.
    fn received_authentication_bytes(&self, device_auth: &DeviceAuthentication) -> Result<Vec<u8>> {
        if self.device_namespaces()? != device_auth.device_namespaces {
            return Err(MdocError::DeviceAuth(
                "device-signed namespaces differ from the ones being verified".into(),
            ));
        }
        device_auth.device_authentication_bytes_with_namespaces(&self.namespaces_bytes)
    }

    /// Verify a COSE_Sign1 device signature.
    ///
    /// Pass a `CoseVerifier` built from the device key in the verified MSO
    /// (`deviceKeyInfo.deviceKey`, see [`crate::CoseKey::to_verifier`]). The
    /// signature covers the namespace bytes as received, and the protected
    /// `alg` must be present and agree with the verifier. MAC-based device
    /// authentication goes through [`Self::verify_mac`].
    pub fn verify(
        &self,
        device_auth: &DeviceAuthentication,
        verifier: &dyn CoseVerifier,
    ) -> Result<bool> {
        let auth_bytes = self.received_authentication_bytes(device_auth)?;

        match &self.device_auth {
            DeviceAuth::Signature(sign1) => {
                crate::cose::checked_algorithm(&sign1.protected.header, verifier, None)
                    .map_err(MdocError::DeviceAuth)?;
                sign1
                    .verify_detached_signature(&auth_bytes, &[], |signature, tbs_data| {
                        match verifier.verify(tbs_data, signature) {
                            Ok(true) => Ok(()),
                            Ok(false) => Err(MdocError::DeviceAuth("signature invalid".into())),
                            Err(e) => Err(e),
                        }
                    })
                    .map_err(|e| MdocError::DeviceAuth(format!("verification failed: {e}")))?;
                Ok(true)
            }
            DeviceAuth::Mac(_) => Err(MdocError::DeviceAuth(
                "use verify_mac() for MAC-based device auth".into(),
            )),
        }
    }

    /// Verify MAC-based device authentication.
    ///
    /// # Arguments
    ///
    /// * `device_auth` — The DeviceAuthentication structure
    /// * `mac_key` — 32-byte HMAC-SHA-256 key (same as used for creation)
    pub fn verify_mac(
        &self,
        device_auth: &DeviceAuthentication,
        mac_key: &[u8; 32],
    ) -> Result<bool> {
        let mac_tag = match &self.device_auth {
            DeviceAuth::Mac(tag) => tag,
            DeviceAuth::Signature(_) => {
                return Err(MdocError::DeviceAuth("expected MAC, got signature".into()));
            }
        };

        let auth_bytes = self.received_authentication_bytes(device_auth)?;

        // Reconstruct protected header for MAC_structure
        let protected = HeaderBuilder::new()
            .algorithm(coset::iana::Algorithm::HMAC_256_256)
            .build();
        let protected_serialized = coset::ProtectedHeader {
            original_data: None,
            header: protected,
        };
        let protected_cbor = protected_serialized
            .cbor_bstr()
            .map_err(|e| MdocError::DeviceAuth(format!("protected header encoding: {e}")))?;

        // Reconstruct MAC_structure
        let mac_structure = ciborium::Value::Array(vec![
            ciborium::Value::Text("MAC0".to_string()),
            protected_cbor,
            ciborium::Value::Bytes(vec![]),
            ciborium::Value::Bytes(auth_bytes),
        ]);

        let mut tbs = Vec::new();
        ciborium::into_writer(&mac_structure, &mut tbs)
            .map_err(|e| MdocError::DeviceAuth(format!("MAC_structure encoding: {e}")))?;

        // Verify HMAC-SHA-256
        let mut hmac = HmacSha256::new_from_slice(mac_key)
            .map_err(|e| MdocError::DeviceAuth(format!("HMAC init: {e}")))?;
        hmac.update(&tbs);
        hmac.verify_slice(&mac_tag.tag)
            .map_err(|_| MdocError::DeviceAuth("MAC verification failed".into()))?;

        Ok(true)
    }
}

/// Encode device namespaces to CBOR bytes.
fn encode_namespaces_bytes(namespaces: &DeviceNameSpaces) -> Result<Vec<u8>> {
    let ns_cbor = encode_device_namespaces(namespaces)?;
    let mut bytes = Vec::new();
    ciborium::into_writer(&ns_cbor, &mut bytes)
        .map_err(|e| MdocError::DeviceAuth(format!("DeviceNameSpaces encoding: {e}")))?;
    Ok(bytes)
}

/// Derive the `EMacKey` a reader uses to check a `deviceMac`, per
/// ISO/IEC 18013-5 §9.1.3.5:
///
/// ```text
/// Zab     = ECDH(EReaderKey.priv, SDeviceKey.pub)
/// EMacKey = HKDF-SHA-256(IKM = Zab, salt = SHA-256(SessionTranscriptBytes),
///                        info = "EMacKey", L = 32)
/// ```
///
/// `device_key` must be the device key from the **verified MSO**
/// (`deviceKeyInfo.deviceKey`), not the ephemeral key from device engagement:
/// that is what ties the MAC to the issuer-signed credential.
/// `reader_ephemeral_private_key` is the reader's ephemeral private scalar
/// (big-endian) for this session. P-256 (feature `es256`) and P-384
/// (`es384`) are supported; any other curve is an error.
pub fn derive_emac_key(
    device_key: &crate::cose_key::CoseKey,
    reader_ephemeral_private_key: &[u8],
    session_transcript: &SessionTranscript,
) -> Result<[u8; 32]> {
    let shared_secret = ecdh_shared_secret(device_key, reader_ephemeral_private_key)?;
    let transcript_bytes = session_transcript.to_cbor_bytes()?;
    let tagged = ciborium::Value::Tag(24, Box::new(ciborium::Value::Bytes(transcript_bytes)));
    let mut session_transcript_bytes = Vec::new();
    ciborium::into_writer(&tagged, &mut session_transcript_bytes)
        .map_err(|e| MdocError::DeviceAuth(format!("SessionTranscriptBytes encoding: {e}")))?;
    let salt = {
        use sha2::Digest;
        Sha256::digest(&session_transcript_bytes)
    };
    let mut key = [0u8; 32];
    hkdf::Hkdf::<Sha256>::new(Some(&salt), &shared_secret)
        .expand(b"EMacKey", &mut key)
        .map_err(|e| MdocError::DeviceAuth(format!("EMacKey derivation: {e}")))?;
    Ok(key)
}

#[allow(unused_variables)]
fn ecdh_shared_secret(
    device_key: &crate::cose_key::CoseKey,
    reader_ephemeral_private_key: &[u8],
) -> Result<Vec<u8>> {
    device_key.validate()?;
    match device_key.crv {
        #[cfg(feature = "es256")]
        crate::cose_key::Curve::P256 => {
            let secret = p256::SecretKey::from_slice(reader_ephemeral_private_key)
                .map_err(|_| MdocError::DeviceAuth("invalid P-256 reader key".into()))?;
            let public = p256::PublicKey::from_sec1_bytes(&uncompressed_point(device_key))
                .map_err(|_| MdocError::DeviceAuth("invalid P-256 device key".into()))?;
            let shared = p256::ecdh::diffie_hellman(secret.to_nonzero_scalar(), public.as_affine());
            Ok(shared.raw_secret_bytes().to_vec())
        }
        #[cfg(feature = "es384")]
        crate::cose_key::Curve::P384 => {
            let secret = p384::SecretKey::from_slice(reader_ephemeral_private_key)
                .map_err(|_| MdocError::DeviceAuth("invalid P-384 reader key".into()))?;
            let public = p384::PublicKey::from_sec1_bytes(&uncompressed_point(device_key))
                .map_err(|_| MdocError::DeviceAuth("invalid P-384 device key".into()))?;
            let shared = p384::ecdh::diffie_hellman(secret.to_nonzero_scalar(), public.as_affine());
            Ok(shared.raw_secret_bytes().to_vec())
        }
        other => Err(MdocError::DeviceAuth(format!(
            "no EMacKey derivation for {other:?} in this build"
        ))),
    }
}

#[cfg(any(feature = "es256", feature = "es384"))]
fn uncompressed_point(key: &crate::cose_key::CoseKey) -> Vec<u8> {
    let mut point = vec![0x04];
    point.extend_from_slice(&key.x);
    point.extend_from_slice(key.y.as_deref().unwrap_or_default());
    point
}

/// Decode `DeviceNameSpaces` bytes, refusing anything that is not a map of
/// text keys to maps of text keys.
pub(crate) fn decode_device_namespaces(bytes: &[u8]) -> Result<DeviceNameSpaces> {
    let value: ciborium::Value = ciborium::from_reader(bytes)
        .map_err(|e| MdocError::DeviceAuth(format!("DeviceNameSpaces decode: {e}")))?;
    let ciborium::Value::Map(entries) = value else {
        return Err(MdocError::DeviceAuth(
            "DeviceNameSpaces must be a CBOR map".into(),
        ));
    };
    let mut namespaces = BTreeMap::new();
    for (ns_key, items_value) in entries {
        let ciborium::Value::Text(ns) = ns_key else {
            return Err(MdocError::DeviceAuth(
                "DeviceNameSpaces keys must be text".into(),
            ));
        };
        let ciborium::Value::Map(item_entries) = items_value else {
            return Err(MdocError::DeviceAuth(format!(
                "DeviceSignedItems for `{ns}` must be a CBOR map"
            )));
        };
        let mut items = BTreeMap::new();
        for (item_key, item_value) in item_entries {
            let ciborium::Value::Text(identifier) = item_key else {
                return Err(MdocError::DeviceAuth(format!(
                    "DeviceSignedItems keys in `{ns}` must be text"
                )));
            };
            if items.insert(identifier, item_value).is_some() {
                return Err(MdocError::DeviceAuth(format!(
                    "duplicate device-signed element in `{ns}`"
                )));
            }
        }
        if namespaces.insert(ns, items).is_some() {
            return Err(MdocError::DeviceAuth(
                "duplicate namespace in DeviceNameSpaces".into(),
            ));
        }
    }
    Ok(namespaces)
}

/// Encode DeviceNameSpaces as a CBOR map of maps.
fn encode_device_namespaces(namespaces: &DeviceNameSpaces) -> Result<ciborium::Value> {
    let entries: Vec<(ciborium::Value, ciborium::Value)> = namespaces
        .iter()
        .map(|(ns, items)| {
            let item_entries: Vec<(ciborium::Value, ciborium::Value)> = items
                .iter()
                .map(|(k, v)| (ciborium::Value::Text(k.clone()), v.clone()))
                .collect();
            (
                ciborium::Value::Text(ns.clone()),
                ciborium::Value::Map(item_entries),
            )
        })
        .collect();
    Ok(ciborium::Value::Map(entries))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cose::test_utils::{TestSigner, TestVerifier};
    use crate::device_engagement::DeviceEngagement;
    use crate::session_transcript::SessionTranscript;

    fn test_cose_key() -> ciborium::Value {
        ciborium::Value::Map(vec![
            (
                ciborium::Value::Integer(1.into()),
                ciborium::Value::Integer(2.into()),
            ),
            (
                ciborium::Value::Integer((-1).into()),
                ciborium::Value::Integer(1.into()),
            ),
            (
                ciborium::Value::Integer((-2).into()),
                ciborium::Value::Bytes(vec![0xaa; 32]),
            ),
            (
                ciborium::Value::Integer((-3).into()),
                ciborium::Value::Bytes(vec![0xbb; 32]),
            ),
        ])
    }

    fn test_transcript() -> SessionTranscript {
        let de = DeviceEngagement::new(test_cose_key()).unwrap();
        SessionTranscript::new_qr(&de, test_cose_key()).unwrap()
    }

    #[test]
    fn device_authentication_cbor_structure() {
        let da =
            DeviceAuthentication::new(test_transcript(), "org.iso.18013.5.1.mDL", BTreeMap::new());

        let value = da.to_cbor_value().unwrap();
        match value {
            ciborium::Value::Array(arr) => {
                assert_eq!(arr.len(), 4);
                // First element is context string
                assert_eq!(
                    arr[0],
                    ciborium::Value::Text("DeviceAuthentication".to_string())
                );
                // Third is docType
                assert_eq!(
                    arr[2],
                    ciborium::Value::Text("org.iso.18013.5.1.mDL".to_string())
                );
            }
            _ => panic!("expected array"),
        }
    }

    #[test]
    fn device_authentication_bytes_has_tag24() {
        let da =
            DeviceAuthentication::new(test_transcript(), "org.iso.18013.5.1.mDL", BTreeMap::new());

        let bytes = da.to_device_authentication_bytes().unwrap();
        // Should start with Tag24 marker: 0xd8 0x18
        assert_eq!(bytes[0], 0xd8);
        assert_eq!(bytes[1], 24);
    }

    #[test]
    fn sign_and_verify_device_auth() {
        let key = b"test-device-key-for-auth-tests!";
        let signer = TestSigner::new(key);
        let verifier = TestVerifier::new(key);

        let da =
            DeviceAuthentication::new(test_transcript(), "org.iso.18013.5.1.mDL", BTreeMap::new());

        let device_signed = DeviceSigned::sign(&da, &signer).unwrap();
        assert!(device_signed.verify(&da, &verifier).unwrap());
    }

    #[test]
    fn wrong_key_fails_device_auth() {
        let signer = TestSigner::new(b"correct-key-for-device-signing!");
        let wrong_verifier = TestVerifier::new(b"wrong-key-should-fail-verify!!!");

        let da =
            DeviceAuthentication::new(test_transcript(), "org.iso.18013.5.1.mDL", BTreeMap::new());

        let device_signed = DeviceSigned::sign(&da, &signer).unwrap();
        let result = device_signed.verify(&da, &wrong_verifier);
        assert!(result.is_err());
    }

    #[test]
    fn different_transcript_fails_verification() {
        let key = b"test-device-key-for-auth-tests!";
        let signer = TestSigner::new(key);
        let verifier = TestVerifier::new(key);

        let da =
            DeviceAuthentication::new(test_transcript(), "org.iso.18013.5.1.mDL", BTreeMap::new());

        let device_signed = DeviceSigned::sign(&da, &signer).unwrap();

        // Verify with a different doc_type — should fail
        let da_different =
            DeviceAuthentication::new(test_transcript(), "different.doctype", BTreeMap::new());

        let result = device_signed.verify(&da_different, &verifier);
        assert!(result.is_err());
    }

    #[test]
    fn device_auth_with_namespaces() {
        let key = b"test-device-key-for-auth-tests!";
        let signer = TestSigner::new(key);
        let verifier = TestVerifier::new(key);

        let mut namespaces = BTreeMap::new();
        let mut items = BTreeMap::new();
        items.insert(
            "device_location".to_string(),
            ciborium::Value::Text("Berlin".to_string()),
        );
        namespaces.insert("org.iso.18013.5.1".to_string(), items);

        let da = DeviceAuthentication::new(test_transcript(), "org.iso.18013.5.1.mDL", namespaces);

        let device_signed = DeviceSigned::sign(&da, &signer).unwrap();
        assert!(device_signed.verify(&da, &verifier).unwrap());
    }

    #[test]
    fn mac_and_verify_device_auth() {
        let mac_key = [0x42u8; 32];

        let da =
            DeviceAuthentication::new(test_transcript(), "org.iso.18013.5.1.mDL", BTreeMap::new());

        let device_signed = DeviceSigned::mac(&da, &mac_key).unwrap();
        assert!(matches!(device_signed.device_auth, DeviceAuth::Mac(_)));
        assert!(device_signed.verify_mac(&da, &mac_key).unwrap());
    }

    #[test]
    fn mac_wrong_key_fails() {
        let mac_key = [0x42u8; 32];
        let wrong_key = [0x43u8; 32];

        let da =
            DeviceAuthentication::new(test_transcript(), "org.iso.18013.5.1.mDL", BTreeMap::new());

        let device_signed = DeviceSigned::mac(&da, &mac_key).unwrap();
        let result = device_signed.verify_mac(&da, &wrong_key);
        assert!(result.is_err());
    }

    #[test]
    fn mac_different_transcript_fails() {
        let mac_key = [0x42u8; 32];

        let da =
            DeviceAuthentication::new(test_transcript(), "org.iso.18013.5.1.mDL", BTreeMap::new());

        let device_signed = DeviceSigned::mac(&da, &mac_key).unwrap();

        let da_different =
            DeviceAuthentication::new(test_transcript(), "different.doctype", BTreeMap::new());

        let result = device_signed.verify_mac(&da_different, &mac_key);
        assert!(result.is_err());
    }

    #[test]
    fn mac_verify_on_signature_fails() {
        let key = b"test-device-key-for-auth-tests!";
        let signer = TestSigner::new(key);
        let mac_key = [0x42u8; 32];

        let da =
            DeviceAuthentication::new(test_transcript(), "org.iso.18013.5.1.mDL", BTreeMap::new());

        let device_signed = DeviceSigned::sign(&da, &signer).unwrap();
        // Trying verify_mac on a signature-based DeviceSigned should fail
        let result = device_signed.verify_mac(&da, &mac_key);
        assert!(result.is_err());
    }

    #[test]
    fn device_authentication_bytes_deterministic() {
        let da1 =
            DeviceAuthentication::new(test_transcript(), "org.iso.18013.5.1.mDL", BTreeMap::new());
        let da2 =
            DeviceAuthentication::new(test_transcript(), "org.iso.18013.5.1.mDL", BTreeMap::new());

        assert_eq!(
            da1.to_device_authentication_bytes().unwrap(),
            da2.to_device_authentication_bytes().unwrap()
        );
    }
}

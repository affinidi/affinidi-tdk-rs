/*!
 * Session Transcript per ISO 18013-5 §9.1.5.1.
 *
 * ```text
 * SessionTranscript = [
 *   DeviceEngagementBytes,   ; Tag24<DeviceEngagement> or null
 *   EReaderKeyBytes,         ; Tag24<COSE_Key> or null
 *   Handover
 * ]
 * ```
 *
 * The session transcript binds together the device engagement, reader key,
 * and handover data. Its CBOR-encoded bytes serve as:
 * - The salt for HKDF session key derivation
 * - Part of the context for DeviceAuthentication and ReaderAuthentication
 *
 * # Handover Variants
 *
 * - **QR**: `Handover = null` (no handover data)
 * - **NFC**: `Handover = [handoverSelect, ?handoverRequest]`
 * - **OID4VP**: `Handover = [clientId, responseUri, nonce, mdocGeneratedNonce]`
 */

use crate::device_engagement::DeviceEngagement;
use crate::error::{MdocError, Result};
use crate::session::SessionKeys;
use crate::tag24::Tag24;

/// Session Transcript per ISO 18013-5 §9.1.5.1.
///
/// Binds device engagement, reader key, and handover into a single
/// context used for key derivation and authentication.
#[derive(Debug, Clone)]
pub struct SessionTranscript {
    /// Tag24-wrapped DeviceEngagement bytes, or None for OID4VP flows.
    pub device_engagement_bytes: Option<Vec<u8>>,
    /// Tag24-wrapped reader ephemeral public key (COSE_Key), or None for OID4VP flows.
    pub e_reader_key_bytes: Option<Vec<u8>>,
    /// Handover data (transport-specific).
    pub handover: Handover,
}

/// Handover data per ISO 18013-5 or OID4VP.
#[derive(Debug, Clone)]
pub enum Handover {
    /// QR code engagement — no handover data (null).
    Qr,
    /// NFC handover.
    Nfc {
        /// Handover Select message bytes.
        handover_select: Vec<u8>,
        /// Optional Handover Request message bytes.
        handover_request: Option<Vec<u8>>,
    },
    /// OID4VP handover per ISO 18013-7 / OpenID4VP.
    Oid4vp {
        client_id: String,
        response_uri: String,
        nonce: String,
        mdoc_generated_nonce: String,
    },
}

impl SessionTranscript {
    /// Create a session transcript for QR code engagement.
    pub fn new_qr(
        device_engagement: &DeviceEngagement,
        e_reader_key: ciborium::Value,
    ) -> Result<Self> {
        let de_bytes = device_engagement.to_cbor_bytes()?;
        let e_reader_tag = Tag24::new(e_reader_key)?;

        Ok(Self {
            device_engagement_bytes: Some(de_bytes),
            e_reader_key_bytes: Some(e_reader_tag.inner_bytes),
            handover: Handover::Qr,
        })
    }

    /// Create a session transcript for NFC engagement.
    pub fn new_nfc(
        device_engagement: &DeviceEngagement,
        e_reader_key: ciborium::Value,
        handover_select: Vec<u8>,
        handover_request: Option<Vec<u8>>,
    ) -> Result<Self> {
        let de_bytes = device_engagement.to_cbor_bytes()?;
        let e_reader_tag = Tag24::new(e_reader_key)?;

        Ok(Self {
            device_engagement_bytes: Some(de_bytes),
            e_reader_key_bytes: Some(e_reader_tag.inner_bytes),
            handover: Handover::Nfc {
                handover_select,
                handover_request,
            },
        })
    }

    /// Create a session transcript for OID4VP.
    pub fn new_oid4vp(
        client_id: impl Into<String>,
        response_uri: impl Into<String>,
        nonce: impl Into<String>,
        mdoc_generated_nonce: impl Into<String>,
    ) -> Self {
        Self {
            device_engagement_bytes: None,
            e_reader_key_bytes: None,
            handover: Handover::Oid4vp {
                client_id: client_id.into(),
                response_uri: response_uri.into(),
                nonce: nonce.into(),
                mdoc_generated_nonce: mdoc_generated_nonce.into(),
            },
        }
    }

    /// Encode the session transcript as a CBOR Value (array).
    pub fn to_cbor_value(&self) -> Result<ciborium::Value> {
        // DeviceEngagementBytes: Tag24 wrapping or null
        let de_val = match &self.device_engagement_bytes {
            Some(bytes) => {
                ciborium::Value::Tag(24, Box::new(ciborium::Value::Bytes(bytes.clone())))
            }
            None => ciborium::Value::Null,
        };

        // EReaderKeyBytes: Tag24 wrapping or null
        let ek_val = match &self.e_reader_key_bytes {
            Some(bytes) => {
                ciborium::Value::Tag(24, Box::new(ciborium::Value::Bytes(bytes.clone())))
            }
            None => ciborium::Value::Null,
        };

        // Handover
        let handover_val = match &self.handover {
            Handover::Qr => ciborium::Value::Null,
            Handover::Nfc {
                handover_select,
                handover_request,
            } => {
                let mut arr = vec![ciborium::Value::Bytes(handover_select.clone())];
                if let Some(req) = handover_request {
                    arr.push(ciborium::Value::Bytes(req.clone()));
                }
                ciborium::Value::Array(arr)
            }
            Handover::Oid4vp {
                client_id,
                response_uri,
                nonce,
                mdoc_generated_nonce,
            } => ciborium::Value::Array(vec![
                ciborium::Value::Text(client_id.clone()),
                ciborium::Value::Text(response_uri.clone()),
                ciborium::Value::Text(nonce.clone()),
                ciborium::Value::Text(mdoc_generated_nonce.clone()),
            ]),
        };

        Ok(ciborium::Value::Array(vec![de_val, ek_val, handover_val]))
    }

    /// Encode to CBOR bytes.
    ///
    /// These bytes are used as the HKDF salt for session key derivation
    /// and as context in DeviceAuthentication / ReaderAuthentication.
    pub fn to_cbor_bytes(&self) -> Result<Vec<u8>> {
        let value = self.to_cbor_value()?;
        let mut buf = Vec::new();
        ciborium::into_writer(&value, &mut buf)
            .map_err(|e| MdocError::SessionTranscript(format!("encoding: {e}")))?;
        Ok(buf)
    }

    /// Derive session keys from an ECDH shared secret and this transcript.
    ///
    /// Convenience method that computes transcript CBOR bytes and passes
    /// them to `SessionKeys::derive()`.
    pub fn derive_session_keys(&self, shared_secret: &[u8]) -> Result<SessionKeys> {
        let transcript_bytes = self.to_cbor_bytes()?;
        SessionKeys::derive(shared_secret, &transcript_bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device_engagement::DeviceEngagement;

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

    #[test]
    fn qr_transcript_is_array() {
        let de = DeviceEngagement::new(test_cose_key()).unwrap();
        let transcript = SessionTranscript::new_qr(&de, test_cose_key()).unwrap();
        let value = transcript.to_cbor_value().unwrap();

        match value {
            ciborium::Value::Array(arr) => {
                assert_eq!(arr.len(), 3);
                // Handover is null for QR
                assert!(matches!(arr[2], ciborium::Value::Null));
            }
            _ => panic!("expected array"),
        }
    }

    #[test]
    fn nfc_transcript_has_handover() {
        let de = DeviceEngagement::new(test_cose_key()).unwrap();
        let transcript = SessionTranscript::new_nfc(
            &de,
            test_cose_key(),
            vec![0x01, 0x02],
            Some(vec![0x03, 0x04]),
        )
        .unwrap();

        let value = transcript.to_cbor_value().unwrap();
        match value {
            ciborium::Value::Array(arr) => {
                assert_eq!(arr.len(), 3);
                match &arr[2] {
                    ciborium::Value::Array(handover) => {
                        assert_eq!(handover.len(), 2);
                    }
                    _ => panic!("expected handover array"),
                }
            }
            _ => panic!("expected array"),
        }
    }

    #[test]
    fn oid4vp_transcript() {
        let transcript = SessionTranscript::new_oid4vp(
            "client_id_123",
            "https://example.com/response",
            "nonce_abc",
            "mdoc_nonce_xyz",
        );

        let value = transcript.to_cbor_value().unwrap();
        match value {
            ciborium::Value::Array(arr) => {
                assert_eq!(arr.len(), 3);
                // DeviceEngagement is null for OID4VP
                assert!(matches!(arr[0], ciborium::Value::Null));
                // EReaderKey is null for OID4VP
                assert!(matches!(arr[1], ciborium::Value::Null));
                // Handover is 4-element array
                match &arr[2] {
                    ciborium::Value::Array(handover) => {
                        assert_eq!(handover.len(), 4);
                    }
                    _ => panic!("expected handover array"),
                }
            }
            _ => panic!("expected array"),
        }
    }

    #[test]
    fn cbor_bytes_deterministic() {
        let de = DeviceEngagement::new(test_cose_key()).unwrap();
        let t1 = SessionTranscript::new_qr(&de, test_cose_key()).unwrap();
        let t2 = SessionTranscript::new_qr(&de, test_cose_key()).unwrap();

        assert_eq!(t1.to_cbor_bytes().unwrap(), t2.to_cbor_bytes().unwrap());
    }

    #[test]
    fn derive_session_keys_from_transcript() {
        let de = DeviceEngagement::new(test_cose_key()).unwrap();
        let transcript = SessionTranscript::new_qr(&de, test_cose_key()).unwrap();

        let keys = transcript
            .derive_session_keys(b"shared-secret-from-ecdh-key-agreement")
            .unwrap();

        assert_eq!(keys.sk_device.len(), 32);
        assert_eq!(keys.sk_reader.len(), 32);
        assert_ne!(keys.sk_device, keys.sk_reader);
    }
}

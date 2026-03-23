/*!
 * Reader Authentication per ISO 18013-5 §9.1.4.
 *
 * ```text
 * ReaderAuthentication = [
 *   "ReaderAuthentication",        ; context string
 *   SessionTranscript,
 *   ItemsRequestBytes              ; Tag24<ItemsRequest>
 * ]
 *
 * ItemsRequest = {
 *   "docType": tstr,
 *   "nameSpaces": ItemsRequestNameSpaces
 * }
 *
 * ItemsRequestNameSpaces = Map<namespace, Map<identifier, intent_to_retain: bool>>
 * ```
 *
 * The reader proves its identity by signing `ReaderAuthenticationBytes`
 * with COSE_Sign1, including its X.509 certificate chain.
 */

use std::collections::BTreeMap;

use coset::{CoseSign1, CoseSign1Builder, HeaderBuilder};

use crate::cose::{CoseSigner, CoseVerifier};
use crate::error::{MdocError, Result};
use crate::session_transcript::SessionTranscript;

/// Items request from a reader/verifier per ISO 18013-5.
///
/// Specifies which attributes the reader is requesting and whether
/// it intends to retain them.
#[derive(Debug, Clone)]
pub struct ItemsRequest {
    /// The document type being requested.
    pub doc_type: String,
    /// Requested namespaces: `Map<namespace, Map<identifier, intent_to_retain>>`.
    pub namespaces: BTreeMap<String, BTreeMap<String, bool>>,
}

/// Reader Authentication structure per ISO 18013-5 §9.1.4.
///
/// Encoded as a CBOR array:
/// `["ReaderAuthentication", SessionTranscript, ItemsRequestBytes]`
#[derive(Debug, Clone)]
pub struct ReaderAuthentication {
    /// The session transcript binding this to the session.
    pub session_transcript: SessionTranscript,
    /// The items request from the reader.
    pub items_request: ItemsRequest,
}

impl ItemsRequest {
    /// Create a new ItemsRequest.
    pub fn new(doc_type: impl Into<String>) -> Self {
        Self {
            doc_type: doc_type.into(),
            namespaces: BTreeMap::new(),
        }
    }

    /// Add a requested attribute with intent_to_retain flag.
    pub fn add_attribute(
        mut self,
        namespace: &str,
        identifier: &str,
        intent_to_retain: bool,
    ) -> Self {
        self.namespaces
            .entry(namespace.to_string())
            .or_default()
            .insert(identifier.to_string(), intent_to_retain);
        self
    }

    /// Add multiple attributes for a namespace, all with the same intent_to_retain.
    pub fn add_namespace(
        mut self,
        namespace: &str,
        identifiers: &[&str],
        intent_to_retain: bool,
    ) -> Self {
        let ns = self.namespaces.entry(namespace.to_string()).or_default();
        for id in identifiers {
            ns.insert(id.to_string(), intent_to_retain);
        }
        self
    }

    /// Encode as a CBOR Value (map).
    pub fn to_cbor_value(&self) -> ciborium::Value {
        let ns_entries: Vec<(ciborium::Value, ciborium::Value)> = self
            .namespaces
            .iter()
            .map(|(ns, attrs)| {
                let attr_entries: Vec<(ciborium::Value, ciborium::Value)> = attrs
                    .iter()
                    .map(|(id, retain)| {
                        (
                            ciborium::Value::Text(id.clone()),
                            ciborium::Value::Bool(*retain),
                        )
                    })
                    .collect();
                (
                    ciborium::Value::Text(ns.clone()),
                    ciborium::Value::Map(attr_entries),
                )
            })
            .collect();

        ciborium::Value::Map(vec![
            (
                ciborium::Value::Text("docType".to_string()),
                ciborium::Value::Text(self.doc_type.clone()),
            ),
            (
                ciborium::Value::Text("nameSpaces".to_string()),
                ciborium::Value::Map(ns_entries),
            ),
        ])
    }

    /// Encode to CBOR bytes.
    pub fn to_cbor_bytes(&self) -> Result<Vec<u8>> {
        let value = self.to_cbor_value();
        let mut buf = Vec::new();
        ciborium::into_writer(&value, &mut buf)
            .map_err(|e| MdocError::ReaderAuth(format!("ItemsRequest encoding: {e}")))?;
        Ok(buf)
    }
}

impl ReaderAuthentication {
    /// Create a new ReaderAuthentication.
    pub fn new(session_transcript: SessionTranscript, items_request: ItemsRequest) -> Self {
        Self {
            session_transcript,
            items_request,
        }
    }

    /// Encode as a CBOR Value (array).
    ///
    /// ```text
    /// ["ReaderAuthentication", SessionTranscript, ItemsRequestBytes]
    /// ```
    pub fn to_cbor_value(&self) -> Result<ciborium::Value> {
        let transcript_val = self.session_transcript.to_cbor_value()?;
        let items_bytes = self.items_request.to_cbor_bytes()?;

        Ok(ciborium::Value::Array(vec![
            ciborium::Value::Text("ReaderAuthentication".to_string()),
            transcript_val,
            ciborium::Value::Tag(24, Box::new(ciborium::Value::Bytes(items_bytes))),
        ]))
    }

    /// Produce `ReaderAuthenticationBytes` — Tag24-wrapped CBOR encoding.
    ///
    /// This is the data that gets signed for reader authentication.
    pub fn to_reader_authentication_bytes(&self) -> Result<Vec<u8>> {
        let value = self.to_cbor_value()?;
        let mut inner_bytes = Vec::new();
        ciborium::into_writer(&value, &mut inner_bytes)
            .map_err(|e| MdocError::ReaderAuth(format!("ReaderAuthentication encoding: {e}")))?;

        // Wrap in Tag24
        let tagged = ciborium::Value::Tag(24, Box::new(ciborium::Value::Bytes(inner_bytes)));
        let mut buf = Vec::new();
        ciborium::into_writer(&tagged, &mut buf)
            .map_err(|e| MdocError::ReaderAuth(format!("Tag24 wrapping: {e}")))?;
        Ok(buf)
    }
}

/// Sign a ReaderAuthentication with COSE_Sign1 (detached payload).
///
/// The reader's X.509 certificate chain (if provided by the signer)
/// is included in the unprotected header as `x5chain` (label 33).
pub fn sign_reader_auth(
    reader_auth: &ReaderAuthentication,
    signer: &dyn CoseSigner,
) -> Result<CoseSign1> {
    let auth_bytes = reader_auth.to_reader_authentication_bytes()?;

    let protected = HeaderBuilder::new().algorithm(signer.algorithm()).build();

    let mut unprotected_builder = HeaderBuilder::new();
    if let Some(chain) = signer.x5chain() {
        if chain.len() == 1 {
            unprotected_builder =
                unprotected_builder.value(33, coset::cbor::Value::Bytes(chain[0].clone()));
        } else if chain.len() > 1 {
            let certs: Vec<coset::cbor::Value> =
                chain.into_iter().map(coset::cbor::Value::Bytes).collect();
            unprotected_builder = unprotected_builder.value(33, coset::cbor::Value::Array(certs));
        }
    }
    let unprotected = unprotected_builder.build();

    let sign1 = CoseSign1Builder::new()
        .protected(protected)
        .unprotected(unprotected)
        .try_create_detached_signature(&auth_bytes, &[], |data| signer.sign(data))
        .map_err(|e| MdocError::ReaderAuth(format!("signing failed: {e}")))?
        .build();

    Ok(sign1)
}

/// Verify a reader's COSE_Sign1 signature against ReaderAuthenticationBytes.
pub fn verify_reader_auth(
    sign1: &CoseSign1,
    reader_auth: &ReaderAuthentication,
    verifier: &dyn CoseVerifier,
) -> Result<bool> {
    let auth_bytes = reader_auth.to_reader_authentication_bytes()?;

    sign1
        .verify_detached_signature(&auth_bytes, &[], |signature, tbs_data| {
            match verifier.verify(tbs_data, signature) {
                Ok(true) => Ok(()),
                Ok(false) => Err(MdocError::ReaderAuth("signature invalid".into())),
                Err(e) => Err(e),
            }
        })
        .map_err(|e| MdocError::ReaderAuth(format!("verification failed: {e}")))?;

    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cose::test_utils::{TestSigner, TestVerifier};
    use crate::device_engagement::DeviceEngagement;
    use crate::namespace::MDL_NAMESPACE;
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
    fn items_request_builder() {
        let req = ItemsRequest::new("org.iso.18013.5.1.mDL")
            .add_attribute(MDL_NAMESPACE, "family_name", false)
            .add_attribute(MDL_NAMESPACE, "birth_date", true)
            .add_namespace(MDL_NAMESPACE, &["portrait"], false);

        assert_eq!(req.doc_type, "org.iso.18013.5.1.mDL");
        assert_eq!(req.namespaces[MDL_NAMESPACE].len(), 3);
        assert!(!req.namespaces[MDL_NAMESPACE]["family_name"]);
        assert!(req.namespaces[MDL_NAMESPACE]["birth_date"]);
    }

    #[test]
    fn reader_authentication_cbor_structure() {
        let req = ItemsRequest::new("org.iso.18013.5.1.mDL").add_attribute(
            MDL_NAMESPACE,
            "family_name",
            false,
        );

        let ra = ReaderAuthentication::new(test_transcript(), req);
        let value = ra.to_cbor_value().unwrap();

        match value {
            ciborium::Value::Array(arr) => {
                assert_eq!(arr.len(), 3);
                assert_eq!(
                    arr[0],
                    ciborium::Value::Text("ReaderAuthentication".to_string())
                );
            }
            _ => panic!("expected array"),
        }
    }

    #[test]
    fn reader_authentication_bytes_has_tag24() {
        let req = ItemsRequest::new("org.iso.18013.5.1.mDL").add_attribute(
            MDL_NAMESPACE,
            "family_name",
            false,
        );

        let ra = ReaderAuthentication::new(test_transcript(), req);
        let bytes = ra.to_reader_authentication_bytes().unwrap();

        assert_eq!(bytes[0], 0xd8);
        assert_eq!(bytes[1], 24);
    }

    #[test]
    fn sign_and_verify_reader_auth() {
        let key = b"test-reader-key-for-auth-tests!";
        let signer = TestSigner::new(key);
        let verifier = TestVerifier::new(key);

        let req = ItemsRequest::new("org.iso.18013.5.1.mDL")
            .add_attribute(MDL_NAMESPACE, "family_name", false)
            .add_attribute(MDL_NAMESPACE, "birth_date", true);

        let ra = ReaderAuthentication::new(test_transcript(), req);
        let sign1 = sign_reader_auth(&ra, &signer).unwrap();

        assert!(verify_reader_auth(&sign1, &ra, &verifier).unwrap());
    }

    #[test]
    fn wrong_key_fails_reader_auth() {
        let signer = TestSigner::new(b"correct-key-for-reader-signing!");
        let wrong_verifier = TestVerifier::new(b"wrong-key-should-fail-verify!!!");

        let req = ItemsRequest::new("org.iso.18013.5.1.mDL").add_attribute(
            MDL_NAMESPACE,
            "family_name",
            false,
        );

        let ra = ReaderAuthentication::new(test_transcript(), req);
        let sign1 = sign_reader_auth(&ra, &signer).unwrap();

        let result = verify_reader_auth(&sign1, &ra, &wrong_verifier);
        assert!(result.is_err());
    }

    #[test]
    fn different_request_fails_verification() {
        let key = b"test-reader-key-for-auth-tests!";
        let signer = TestSigner::new(key);
        let verifier = TestVerifier::new(key);

        let req1 = ItemsRequest::new("org.iso.18013.5.1.mDL").add_attribute(
            MDL_NAMESPACE,
            "family_name",
            false,
        );

        let ra1 = ReaderAuthentication::new(test_transcript(), req1);
        let sign1 = sign_reader_auth(&ra1, &signer).unwrap();

        // Different request
        let req2 = ItemsRequest::new("org.iso.18013.5.1.mDL").add_attribute(
            MDL_NAMESPACE,
            "portrait",
            true,
        );

        let ra2 = ReaderAuthentication::new(test_transcript(), req2);
        let result = verify_reader_auth(&sign1, &ra2, &verifier);
        assert!(result.is_err());
    }

    #[test]
    fn items_request_cbor_roundtrip() {
        let req = ItemsRequest::new("org.iso.18013.5.1.mDL").add_namespace(
            MDL_NAMESPACE,
            &["family_name", "given_name", "birth_date"],
            false,
        );

        let bytes = req.to_cbor_bytes().unwrap();
        let value: ciborium::Value = ciborium::from_reader(&bytes[..]).unwrap();

        match value {
            ciborium::Value::Map(entries) => {
                assert_eq!(entries.len(), 2);
            }
            _ => panic!("expected map"),
        }
    }
}

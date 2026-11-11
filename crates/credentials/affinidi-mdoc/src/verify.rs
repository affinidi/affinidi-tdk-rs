/*!
 * Reader-side verification of a [`DeviceResponse`] — ISO/IEC 18013-5 §9.3.
 *
 * [`DeviceResponse::verify`] runs every check a reader needs, in order, and
 * returns the disclosed elements only when all of them pass:
 *
 * 1. the response status is OK;
 * 2. the `issuerAuth` protected `alg` is in the allowed list;
 * 3. the issuer key is obtained, either a verifier the caller already trusts
 *    or one the caller builds from the `x5chain` after validating it against
 *    its trust anchors;
 * 4. the `issuerAuth` signature verifies, and the MSO is taken from that
 *    verified payload (the decoded `mso` field is not trusted);
 * 5. the document's `docType`, the MSO `docType` and the expected `docType`
 *    are equal;
 * 6. `validityInfo` covers `now`, with the given leeway;
 * 7. every disclosed item hashes, as received, to its MSO digest;
 * 8. device authentication verifies against the device key from the MSO
 *    (`deviceKeyInfo.deviceKey`), unless the caller explicitly opts out.
 *
 * The piecemeal methods on [`DeviceResponse`] and [`crate::IssuerSigned`]
 * stay available for callers that need a different composition.
 */

use std::collections::BTreeMap;

use coset::iana::Algorithm;

use crate::cose::{CoseVerifier, checked_algorithm, verify_issuer_auth, x5chain};
use crate::cose_key::CoseKey;
use crate::device_auth::{DeviceAuth, DeviceAuthentication, DeviceNameSpaces};
use crate::error::{MdocError, Result};
use crate::issuer_signed::{DeviceResponse, verify_disclosed_digests};
use crate::mso::MobileSecurityObject;
use crate::session_transcript::SessionTranscript;

/// What the issuer resolver is given: the unverified `issuerAuth` headers.
#[derive(Debug)]
pub struct IssuerAuthHeaders<'a> {
    /// The protected `alg`, already checked against the allowed list.
    pub algorithm: Algorithm,
    /// The `x5chain`, leaf first, DER-encoded. Empty when absent. Unverified:
    /// the resolver must validate it against its trust anchors.
    pub x5chain: &'a [Vec<u8>],
    /// The unprotected `kid`, if any.
    pub kid: Option<&'a [u8]>,
}

/// Signature over a resolver closure: validate the chain (or look up the
/// `kid`) and return a verifier for the issuer key, or an error.
pub type IssuerResolver<'a> =
    &'a (dyn Fn(&IssuerAuthHeaders<'_>) -> Result<Box<dyn CoseVerifier>> + Send + Sync);

/// How the issuer key is obtained.
pub enum IssuerKey<'a> {
    /// A verifier for an issuer key the caller already trusts.
    Trusted(&'a dyn CoseVerifier),
    /// A resolver that validates the `x5chain` (or looks up the `kid`) and
    /// returns a verifier for the leaf key. Returning an error stops
    /// verification.
    Resolve(IssuerResolver<'a>),
}

/// Whether, and how, holder binding is checked.
pub enum DeviceBinding<'a> {
    /// Require `deviceSigned` and verify it against the device key in the
    /// verified MSO over this session transcript. A `deviceSignature` is
    /// verified with that key; a `deviceMac` needs `mac_key`, the
    /// EMacKey the reader derived for this session, and fails without it.
    Required {
        /// The transcript of this session.
        session_transcript: &'a SessionTranscript,
        /// The session's EMacKey, for `deviceMac` responses.
        mac_key: Option<&'a [u8; 32]>,
    },
    /// Do not check holder binding. The result reports
    /// `device_authenticated: false`. Only for issuer-data checks where the
    /// presenter's possession of the device key does not matter.
    NotChecked,
}

/// Inputs to [`DeviceResponse::verify`].
pub struct VerifyOptions<'a> {
    /// How the issuer key is obtained.
    pub issuer_key: IssuerKey<'a>,
    /// COSE algorithms accepted for `issuerAuth` and `deviceSignature`.
    pub allowed_algorithms: Vec<Algorithm>,
    /// The `docType` the reader asked for.
    pub expected_doc_type: String,
    /// The time to check `validityInfo` against.
    pub now: time::OffsetDateTime,
    /// Clock-skew allowance for `validityInfo`.
    pub leeway: time::Duration,
    /// Holder-binding policy.
    pub device_binding: DeviceBinding<'a>,
}

impl<'a> VerifyOptions<'a> {
    /// Options with the default algorithm list (ES256, ES384, EdDSA) and no
    /// leeway. Every argument is a decision the caller has to make.
    pub fn new(
        issuer_key: IssuerKey<'a>,
        expected_doc_type: impl Into<String>,
        now: time::OffsetDateTime,
        device_binding: DeviceBinding<'a>,
    ) -> Self {
        Self {
            issuer_key,
            allowed_algorithms: vec![Algorithm::ES256, Algorithm::ES384, Algorithm::EdDSA],
            expected_doc_type: expected_doc_type.into(),
            now,
            leeway: time::Duration::ZERO,
            device_binding,
        }
    }

    /// Replace the accepted COSE algorithms.
    pub fn allowed_algorithms(mut self, algorithms: Vec<Algorithm>) -> Self {
        self.allowed_algorithms = algorithms;
        self
    }

    /// Set the clock-skew allowance for `validityInfo`.
    pub fn leeway(mut self, leeway: time::Duration) -> Self {
        self.leeway = leeway;
        self
    }
}

/// The outcome of a successful [`DeviceResponse::verify`].
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct VerifiedMdoc {
    /// The verified document type.
    pub doc_type: String,
    /// The MSO from the verified `issuerAuth` payload.
    pub mso: MobileSecurityObject,
    /// The `issuerAuth` algorithm.
    pub issuer_algorithm: Algorithm,
    /// The `x5chain` the issuer key was resolved from (empty when absent).
    pub x5chain: Vec<Vec<u8>>,
    /// Disclosed issuer-signed elements: namespace → identifier → value.
    pub elements: BTreeMap<String, BTreeMap<String, ciborium::Value>>,
    /// Device-signed elements, when device authentication was checked.
    pub device_elements: DeviceNameSpaces,
    /// `true` only when holder binding was required and verified.
    pub device_authenticated: bool,
}

impl DeviceResponse {
    /// Verify this response as an ISO 18013-5 reader must, and return the
    /// disclosed elements. See the [`crate::verify`] module for the checks.
    ///
    /// Any failed check is an error; there is no partially verified result.
    pub fn verify(&self, options: &VerifyOptions<'_>) -> Result<VerifiedMdoc> {
        if self.status != 0 {
            return Err(MdocError::InvalidMso(format!(
                "response status is {}, not OK",
                self.status
            )));
        }

        let chain = x5chain(&self.issuer_auth)?;
        let resolved;
        let issuer_verifier: &dyn CoseVerifier = match &options.issuer_key {
            IssuerKey::Trusted(verifier) => *verifier,
            IssuerKey::Resolve(resolve) => {
                let algorithm = header_algorithm(&self.issuer_auth.protected.header)?;
                if !options.allowed_algorithms.contains(&algorithm) {
                    return Err(MdocError::Cose(format!(
                        "issuerAuth alg {algorithm:?} is not in the allowed list"
                    )));
                }
                let kid = crate::cose::extract_kid(&self.issuer_auth);
                resolved = resolve(&IssuerAuthHeaders {
                    algorithm,
                    x5chain: &chain,
                    kid,
                })?;
                resolved.as_ref()
            }
        };
        let issuer_algorithm = checked_algorithm(
            &self.issuer_auth.protected.header,
            issuer_verifier,
            Some(&options.allowed_algorithms),
        )
        .map_err(|e| MdocError::Cose(format!("issuerAuth: {e}")))?;

        let mso = verify_issuer_auth(&self.issuer_auth, issuer_verifier)?;

        if mso.doc_type != self.doc_type {
            return Err(MdocError::InvalidMso(format!(
                "document docType `{}` differs from the signed MSO docType `{}`",
                self.doc_type, mso.doc_type
            )));
        }
        if mso.doc_type != options.expected_doc_type {
            return Err(MdocError::InvalidMso(format!(
                "docType `{}` is not the requested `{}`",
                mso.doc_type, options.expected_doc_type
            )));
        }

        mso.validity_info
            .check_with_leeway(options.now, options.leeway)?;

        if !verify_disclosed_digests(&mso, &self.disclosed)? {
            return Err(MdocError::DigestMismatch(
                "a disclosed item does not match its MSO digest".into(),
            ));
        }

        let mut elements: BTreeMap<String, BTreeMap<String, ciborium::Value>> = BTreeMap::new();
        for (ns, items) in &self.disclosed {
            let ns_elements = elements.entry(ns.clone()).or_default();
            for item in items {
                if ns_elements
                    .insert(
                        item.inner.element_identifier.clone(),
                        item.inner.element_value.clone(),
                    )
                    .is_some()
                {
                    return Err(MdocError::InvalidNamespace(format!(
                        "element `{}` disclosed twice in `{ns}`",
                        item.inner.element_identifier
                    )));
                }
            }
        }

        let (device_elements, device_authenticated) = match &options.device_binding {
            DeviceBinding::NotChecked => (BTreeMap::new(), false),
            DeviceBinding::Required {
                session_transcript,
                mac_key,
            } => (
                self.verify_device_binding(&mso, session_transcript, *mac_key, options)?,
                true,
            ),
        };

        Ok(VerifiedMdoc {
            doc_type: mso.doc_type.clone(),
            mso,
            issuer_algorithm,
            x5chain: chain,
            elements,
            device_elements,
            device_authenticated,
        })
    }

    fn verify_device_binding(
        &self,
        mso: &MobileSecurityObject,
        session_transcript: &SessionTranscript,
        mac_key: Option<&[u8; 32]>,
        options: &VerifyOptions<'_>,
    ) -> Result<DeviceNameSpaces> {
        let device_signed = self.device_signed.as_ref().ok_or_else(|| {
            MdocError::DeviceAuth("holder binding required but no deviceSigned present".into())
        })?;
        let device_namespaces = device_signed.device_namespaces()?;
        let device_auth = DeviceAuthentication::new(
            session_transcript.clone(),
            &mso.doc_type,
            device_namespaces.clone(),
        );

        let verified = match &device_signed.device_auth {
            DeviceAuth::Signature(sign1) => {
                let device_key = CoseKey::from_cbor_value(&mso.device_key_info.device_key)
                    .map_err(|e| MdocError::DeviceAuth(format!("deviceKey: {e}")))?;
                let device_verifier = device_key
                    .to_verifier()
                    .map_err(|e| MdocError::DeviceAuth(format!("deviceKey: {e}")))?;
                checked_algorithm(
                    &sign1.protected.header,
                    device_verifier.as_ref(),
                    Some(&options.allowed_algorithms),
                )
                .map_err(|e| MdocError::DeviceAuth(format!("deviceSignature: {e}")))?;
                device_signed.verify(&device_auth, device_verifier.as_ref())?
            }
            DeviceAuth::Mac(_) => {
                let mac_key = mac_key.ok_or_else(|| {
                    MdocError::DeviceAuth("deviceMac present but no session MAC key given".into())
                })?;
                device_signed.verify_mac(&device_auth, mac_key)?
            }
        };
        if !verified {
            return Err(MdocError::DeviceAuth("device authentication failed".into()));
        }
        Ok(device_namespaces)
    }
}

fn header_algorithm(protected: &coset::Header) -> Result<Algorithm> {
    match &protected.alg {
        Some(coset::RegisteredLabelWithPrivate::Assigned(alg)) => Ok(*alg),
        Some(other) => Err(MdocError::Cose(format!(
            "unsupported issuerAuth alg {other:?}"
        ))),
        None => Err(MdocError::Cose(
            "issuerAuth carries no protected alg".into(),
        )),
    }
}

#[cfg(all(test, feature = "es256"))]
mod tests {
    use super::*;
    use crate::cose::{CoseSigner, sign_mso};
    use crate::device_engagement::DeviceEngagement;
    use crate::es256_cose::{Es256CoseSigner, Es256CoseVerifier};
    use crate::issuer_signed::{IssuerSigned, MdocBuilder};
    use crate::issuer_signed_item::IssuerSignedItem;
    use crate::mso::{DeviceKeyInfo, ValidityInfo};
    use crate::tag24::Tag24;
    use ciborium::Value;

    const DOC_TYPE: &str = "eu.europa.ec.eudi.pid.1";
    const NS: &str = "eu.europa.ec.eudi.pid.1";

    fn validity() -> ValidityInfo {
        ValidityInfo {
            signed: "2026-01-01T00:00:00Z".into(),
            valid_from: "2026-01-01T00:00:00Z".into(),
            valid_until: "2027-01-01T00:00:00Z".into(),
        }
    }

    fn at(text: &str) -> time::OffsetDateTime {
        time::OffsetDateTime::parse(text, &time::format_description::well_known::Rfc3339).unwrap()
    }

    fn now() -> time::OffsetDateTime {
        at("2026-06-01T00:00:00Z")
    }

    fn cose_key_of(signer: &Es256CoseSigner) -> Value {
        let point = signer.public_key_bytes();
        CoseKey::new_p256(point[1..33].to_vec(), point[33..65].to_vec())
            .unwrap()
            .to_cbor_value()
    }

    fn transcript() -> SessionTranscript {
        let de = DeviceEngagement::new(Value::Map(vec![])).unwrap();
        SessionTranscript::new_qr(&de, Value::Map(vec![])).unwrap()
    }

    struct Fixture {
        issuer: Es256CoseSigner,
        device: Es256CoseSigner,
        mdoc: IssuerSigned,
    }

    fn fixture() -> Fixture {
        let issuer = Es256CoseSigner::generate();
        let device = Es256CoseSigner::generate();
        let mdoc = MdocBuilder::new(DOC_TYPE)
            .validity(validity())
            .device_key(cose_key_of(&device))
            .add_attribute(NS, "family_name", Value::Text("Doe".into()))
            .add_attribute(NS, "age_over_18", Value::Bool(true))
            .build(&issuer)
            .unwrap();
        Fixture {
            issuer,
            device,
            mdoc,
        }
    }

    fn requested() -> BTreeMap<String, Vec<String>> {
        BTreeMap::from([(NS.to_string(), vec!["age_over_18".to_string()])])
    }

    fn presented(fixture: &Fixture) -> DeviceResponse {
        let response = DeviceResponse::create_with_device_auth(
            &fixture.mdoc,
            &requested(),
            &transcript(),
            &fixture.device,
            None,
        )
        .unwrap();
        DeviceResponse::from_cbor_bytes(&response.to_cbor_bytes().unwrap()).unwrap()
    }

    fn issuer_verifier(fixture: &Fixture) -> Es256CoseVerifier {
        Es256CoseVerifier::from_bytes(&fixture.issuer.public_key_bytes()).unwrap()
    }

    #[test]
    fn a_valid_presentation_verifies_with_holder_binding() {
        let fixture = fixture();
        let response = presented(&fixture);
        let verifier = issuer_verifier(&fixture);
        let transcript = transcript();
        let options = VerifyOptions::new(
            IssuerKey::Trusted(&verifier),
            DOC_TYPE,
            now(),
            DeviceBinding::Required {
                session_transcript: &transcript,
                mac_key: None,
            },
        );

        let verified = response.verify(&options).expect("verifies");
        assert!(verified.device_authenticated);
        assert_eq!(verified.issuer_algorithm, Algorithm::ES256);
        assert_eq!(verified.elements[NS]["age_over_18"], Value::Bool(true));
        assert!(!verified.elements[NS].contains_key("family_name"));
    }

    #[test]
    fn holder_binding_uses_the_device_key_from_the_signed_mso() {
        let fixture = fixture();
        let other_device = Es256CoseSigner::generate();
        let response = DeviceResponse::create_with_device_auth(
            &fixture.mdoc,
            &requested(),
            &transcript(),
            &other_device,
            None,
        )
        .unwrap();
        let verifier = issuer_verifier(&fixture);
        let transcript = transcript();
        let options = VerifyOptions::new(
            IssuerKey::Trusted(&verifier),
            DOC_TYPE,
            now(),
            DeviceBinding::Required {
                session_transcript: &transcript,
                mac_key: None,
            },
        );
        assert!(matches!(
            response.verify(&options),
            Err(MdocError::DeviceAuth(_))
        ));
    }

    #[test]
    fn holder_binding_required_without_device_signed_is_an_error() {
        let fixture = fixture();
        let response = DeviceResponse::create(&fixture.mdoc, &requested()).unwrap();
        let verifier = issuer_verifier(&fixture);
        let transcript = transcript();
        let required = VerifyOptions::new(
            IssuerKey::Trusted(&verifier),
            DOC_TYPE,
            now(),
            DeviceBinding::Required {
                session_transcript: &transcript,
                mac_key: None,
            },
        );
        assert!(matches!(
            response.verify(&required),
            Err(MdocError::DeviceAuth(_))
        ));

        let waived = VerifyOptions::new(
            IssuerKey::Trusted(&verifier),
            DOC_TYPE,
            now(),
            DeviceBinding::NotChecked,
        );
        let verified = response.verify(&waived).expect("issuer data verifies");
        assert!(!verified.device_authenticated);
    }

    #[test]
    fn a_different_session_transcript_fails_holder_binding() {
        let fixture = fixture();
        let response = presented(&fixture);
        let verifier = issuer_verifier(&fixture);
        let de = DeviceEngagement::new(Value::Map(vec![])).unwrap();
        let other = SessionTranscript::new_qr(
            &de,
            Value::Map(vec![(Value::Integer(1.into()), Value::Null)]),
        )
        .unwrap();
        let options = VerifyOptions::new(
            IssuerKey::Trusted(&verifier),
            DOC_TYPE,
            now(),
            DeviceBinding::Required {
                session_transcript: &other,
                mac_key: None,
            },
        );
        assert!(response.verify(&options).is_err());
    }

    #[test]
    fn an_unexpected_doc_type_is_rejected() {
        let fixture = fixture();
        let response = presented(&fixture);
        let verifier = issuer_verifier(&fixture);
        let options = VerifyOptions::new(
            IssuerKey::Trusted(&verifier),
            "org.iso.18013.5.1.mDL",
            now(),
            DeviceBinding::NotChecked,
        );
        assert!(matches!(
            response.verify(&options),
            Err(MdocError::InvalidMso(_))
        ));
    }

    #[test]
    fn a_document_doc_type_that_differs_from_the_mso_is_rejected() {
        let fixture = fixture();
        let mut response = presented(&fixture);
        let verifier = issuer_verifier(&fixture);
        let options = VerifyOptions::new(
            IssuerKey::Trusted(&verifier),
            DOC_TYPE,
            now(),
            DeviceBinding::NotChecked,
        );
        response.doc_type = "org.iso.18013.5.1.mDL".into();
        assert!(response.verify(&options).is_err());

        let bytes = response.to_cbor_bytes().unwrap();
        assert!(matches!(
            DeviceResponse::from_cbor_bytes(&bytes),
            Err(MdocError::InvalidMso(_))
        ));
    }

    #[test]
    fn an_algorithm_outside_the_allowed_list_is_rejected() {
        let fixture = fixture();
        let response = presented(&fixture);
        let verifier = issuer_verifier(&fixture);
        let options = VerifyOptions::new(
            IssuerKey::Trusted(&verifier),
            DOC_TYPE,
            now(),
            DeviceBinding::NotChecked,
        )
        .allowed_algorithms(vec![Algorithm::EdDSA]);
        assert!(matches!(response.verify(&options), Err(MdocError::Cose(_))));
    }

    #[test]
    fn validity_is_checked_with_leeway() {
        let fixture = fixture();
        let response = presented(&fixture);
        let verifier = issuer_verifier(&fixture);
        let late = at("2027-01-01T00:01:00Z");
        let strict = VerifyOptions::new(
            IssuerKey::Trusted(&verifier),
            DOC_TYPE,
            late,
            DeviceBinding::NotChecked,
        );
        assert!(matches!(
            response.verify(&strict),
            Err(MdocError::Expired(_))
        ));

        let lenient = VerifyOptions::new(
            IssuerKey::Trusted(&verifier),
            DOC_TYPE,
            late,
            DeviceBinding::NotChecked,
        )
        .leeway(time::Duration::minutes(5));
        response.verify(&lenient).expect("within leeway");
    }

    #[test]
    fn digests_are_checked_against_the_signed_mso_not_the_mso_field() {
        let fixture = fixture();
        let mut response = presented(&fixture);
        let verifier = issuer_verifier(&fixture);

        let replaced = IssuerSignedItem::new(1, "age_over_18", Value::Bool(false))
            .to_tagged()
            .unwrap();
        response.mso.value_digests.get_mut(NS).unwrap().insert(
            1,
            serde_bytes::ByteBuf::from(replaced.digest("SHA-256").unwrap()),
        );
        response.disclosed.insert(NS.to_string(), vec![replaced]);
        assert!(
            response.verify_digests().unwrap(),
            "the piecemeal check trusts the mso field"
        );

        let options = VerifyOptions::new(
            IssuerKey::Trusted(&verifier),
            DOC_TYPE,
            now(),
            DeviceBinding::NotChecked,
        );
        assert!(matches!(
            response.verify(&options),
            Err(MdocError::DigestMismatch(_))
        ));
    }

    #[test]
    fn the_resolver_is_given_the_x5chain_and_can_refuse() {
        let issuer = Es256CoseSigner::generate()
            .with_x5chain(vec![b"leaf-der".to_vec(), b"intermediate-der".to_vec()]);
        let public_key = issuer.public_key_bytes();
        let mdoc = MdocBuilder::new(DOC_TYPE)
            .validity(validity())
            .add_attribute(NS, "age_over_18", Value::Bool(true))
            .build(&issuer)
            .unwrap();
        let response = DeviceResponse::create(&mdoc, &requested()).unwrap();
        assert_eq!(
            response.x5chain().unwrap(),
            vec![b"leaf-der".to_vec(), b"intermediate-der".to_vec()]
        );

        let accept = move |headers: &IssuerAuthHeaders<'_>| -> Result<Box<dyn CoseVerifier>> {
            assert_eq!(headers.algorithm, Algorithm::ES256);
            assert_eq!(headers.x5chain[0], b"leaf-der");
            Ok(Box::new(Es256CoseVerifier::from_bytes(&public_key)?))
        };
        let options = VerifyOptions::new(
            IssuerKey::Resolve(&accept),
            DOC_TYPE,
            now(),
            DeviceBinding::NotChecked,
        );
        let verified = response.verify(&options).expect("resolver accepts");
        assert_eq!(verified.x5chain.len(), 2);

        let refuse = |_: &IssuerAuthHeaders<'_>| -> Result<Box<dyn CoseVerifier>> {
            Err(MdocError::Cose("chain not trusted".into()))
        };
        let options = VerifyOptions::new(
            IssuerKey::Resolve(&refuse),
            DOC_TYPE,
            now(),
            DeviceBinding::NotChecked,
        );
        assert!(response.verify(&options).is_err());
    }

    /// Signs with ES256 but labels the signature with another algorithm.
    struct MislabelledSigner {
        inner: Es256CoseSigner,
        label: Algorithm,
    }

    impl CoseSigner for MislabelledSigner {
        fn algorithm(&self) -> Algorithm {
            self.label
        }
        fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
            self.inner.sign(data)
        }
    }

    #[test]
    fn piecemeal_issuer_auth_refuses_an_alg_the_verifier_does_not_implement() {
        let fixture = fixture();
        let signer = MislabelledSigner {
            inner: Es256CoseSigner::from_bytes(&[7u8; 32]).unwrap(),
            label: Algorithm::EdDSA,
        };
        let verifier = Es256CoseVerifier::from_bytes(&signer.inner.public_key_bytes()).unwrap();
        let sign1 = sign_mso(&fixture.mdoc.mso, &signer).unwrap();
        assert!(crate::cose::verify_issuer_auth(&sign1, &verifier).is_err());
    }

    #[test]
    fn piecemeal_issuer_auth_refuses_a_missing_alg() {
        let fixture = fixture();
        let mut sign1 = fixture.mdoc.issuer_auth.clone();
        sign1.protected = coset::ProtectedHeader::default();
        let verifier = issuer_verifier(&fixture);
        assert!(crate::cose::verify_issuer_auth(&sign1, &verifier).is_err());
    }

    /// An `IssuerSignedItem` as another encoder may write it: keys in a
    /// different order and `digestID` as a four-byte integer.
    fn foreign_item_bytes(digest_id: u32) -> Vec<u8> {
        let mut bytes = vec![0xa4];
        let text = |value: &str, out: &mut Vec<u8>| {
            out.push(0x60 | value.len() as u8);
            out.extend_from_slice(value.as_bytes());
        };
        text("elementValue", &mut bytes);
        bytes.push(0xf5);
        text("elementIdentifier", &mut bytes);
        text("age_over_18", &mut bytes);
        text("random", &mut bytes);
        bytes.push(0x50);
        bytes.extend_from_slice(&[0x5a; 16]);
        text("digestID", &mut bytes);
        bytes.push(0x1a);
        bytes.extend_from_slice(&digest_id.to_be_bytes());
        bytes
    }

    #[test]
    fn items_from_another_encoder_verify_over_their_received_bytes() {
        let issuer = Es256CoseSigner::generate();
        let raw = foreign_item_bytes(3);
        let wire = Value::Tag(24, Box::new(Value::Bytes(raw.clone())));
        let item: Tag24<IssuerSignedItem> = wire.deserialized().unwrap();
        assert_eq!(item.inner.digest_id, 3);
        assert_eq!(item.inner_bytes, raw);
        assert_ne!(
            item.inner.compute_digest("SHA-256").unwrap(),
            item.digest("SHA-256").unwrap(),
            "the fixture must differ from this crate's own encoding"
        );

        let mso = MobileSecurityObject {
            version: "1.0".into(),
            digest_algorithm: "SHA-256".into(),
            value_digests: BTreeMap::from([(
                NS.to_string(),
                BTreeMap::from([(
                    3,
                    serde_bytes::ByteBuf::from(item.digest("SHA-256").unwrap()),
                )]),
            )]),
            device_key_info: DeviceKeyInfo {
                device_key: Value::Map(vec![]),
            },
            doc_type: DOC_TYPE.into(),
            validity_info: validity(),
        };
        let issuer_auth = sign_mso(&mso, &issuer).unwrap();
        let issued = IssuerSigned {
            doc_type: DOC_TYPE.into(),
            mso,
            namespaces: BTreeMap::from([(NS.to_string(), vec![item])]),
            issuer_auth,
        };
        let decoded = IssuerSigned::from_cbor_bytes(&issued.to_cbor_bytes().unwrap()).unwrap();
        assert!(decoded.verify_digests().unwrap());

        let response = DeviceResponse::create(&decoded, &requested()).unwrap();
        let response = DeviceResponse::from_cbor_bytes(&response.to_cbor_bytes().unwrap()).unwrap();
        assert!(response.verify_digests().unwrap());
        let verifier = Es256CoseVerifier::from_bytes(&issuer.public_key_bytes()).unwrap();
        let options = VerifyOptions::new(
            IssuerKey::Trusted(&verifier),
            DOC_TYPE,
            now(),
            DeviceBinding::NotChecked,
        );
        let verified = response.verify(&options).expect("foreign item verifies");
        assert_eq!(verified.elements[NS]["age_over_18"], Value::Bool(true));
    }
}

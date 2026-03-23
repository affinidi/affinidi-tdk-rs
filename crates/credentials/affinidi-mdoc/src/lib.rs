/*!
 * ISO/IEC 18013-5 mdoc (Mobile Document) implementation.
 *
 * Implements the mdoc credential format used for mobile driving licences (mDL)
 * and eIDAS 2.0 attestations. This is one of the two mandatory credential
 * formats for eIDAS (the other being SD-JWT VC).
 *
 * # Architecture
 *
 * ```text
 * IssuerSigned
 * ├── nameSpaces: { namespace → [Tag24<IssuerSignedItem>] }
 * │                               ├── digestID: u32
 * │                               ├── random: bstr (32 bytes)
 * │                               ├── elementIdentifier: tstr
 * │                               └── elementValue: any
 * └── issuerAuth: COSE_Sign1(Tag24<MSO>)
 *                        └── MSO (Mobile Security Object)
 *                            ├── version: "1.0"
 *                            ├── digestAlgorithm: "SHA-256"
 *                            ├── valueDigests: { namespace → { digestId → hash } }
 *                            ├── deviceKeyInfo: { deviceKey: COSE_Key }
 *                            ├── docType: "eu.europa.ec.eudi.pid.1"
 *                            └── validityInfo: { signed, validFrom, validUntil }
 *
 * DeviceResponse (presentation)
 * ├── version: "1.0"
 * ├── docType: tstr
 * ├── disclosed: { namespace → [selected Tag24<IssuerSignedItem>] }
 * ├── mso: (for digest verification)
 * ├── issuerAuth: (for signature verification)
 * ├── deviceSigned: (optional holder binding)
 * └── status: 0
 * ```
 *
 * # Encoding
 *
 * All data structures use CBOR encoding. Key points:
 * - `IssuerSignedItem` is always wrapped in `Tag24` (CBOR tag 24)
 * - Digests are computed over the Tag24-wrapped bytes: `SHA-256(CBOR(Tag24(item)))`
 * - The MSO is signed with COSE_Sign1 (X.509 cert chain in unprotected header)
 * - Attributes have random 32-byte salts for selective disclosure
 *
 * # COSE Algorithm Support
 *
 * | Algorithm | COSE ID | Curve | Feature | Signer | Verifier |
 * |-----------|---------|-------|---------|--------|----------|
 * | ES256 | -7 | P-256 | `es256` (default) | [`es256_cose::Es256CoseSigner`] | [`es256_cose::Es256CoseVerifier`] |
 * | ES384 | -35 | P-384 | `es384` | [`es384_cose::Es384CoseSigner`] | [`es384_cose::Es384CoseVerifier`] |
 * | EdDSA | -8 | Ed25519 | `eddsa` | [`eddsa_cose::EdDsaCoseSigner`] | [`eddsa_cose::EdDsaCoseVerifier`] |
 *
 * # Device Authentication
 *
 * Two methods are supported per ISO 18013-5 §9.1.3:
 * - **COSE_Sign1**: Asymmetric device signature (recommended)
 * - **COSE_Mac0**: Symmetric MAC using HMAC-SHA-256 (for ECDH-derived keys)
 *
 * # Modules
 *
 * - [`tag24`] — CBOR Tag 24 wrapper with byte preservation
 * - [`issuer_signed_item`] — IssuerSignedItem structure and digest computation
 * - [`mso`] — Mobile Security Object
 * - [`cose`] — COSE_Sign1 signing/verification traits and functions
 * - [`cose_key`] — Typed COSE_Key with validation (RFC 9052 §7)
 * - [`issuer_signed`] — IssuerSigned, MdocBuilder, DeviceResponse
 * - [`namespace`] — Namespace constants (eIDAS PID, mDL)
 * - [`device_engagement`] — DeviceEngagement for session establishment (§9.1.1.4)
 * - [`session_transcript`] — SessionTranscript binding (§9.1.5.1)
 * - [`device_auth`] — DeviceAuthentication, DeviceSigned, COSE_Mac0 (§9.1.3)
 * - [`reader_auth`] — ReaderAuthentication and ItemsRequest (§9.1.4)
 * - [`session`] — Session key derivation and AES-256-GCM encryption
 * - [`mdl`] — mDL driving privileges and schema validation (feature: `mdl`)
 */

pub mod cose;
pub mod cose_key;
pub mod device_auth;
pub mod device_engagement;
pub mod error;

/// Production ES256 (P-256 ECDSA) signer/verifier for COSE_Sign1.
#[cfg(feature = "es256")]
pub mod es256_cose;

/// Production ES384 (P-384 ECDSA) signer/verifier for COSE_Sign1.
#[cfg(feature = "es384")]
pub mod es384_cose;

/// Production EdDSA (Ed25519) signer/verifier for COSE_Sign1.
#[cfg(feature = "eddsa")]
pub mod eddsa_cose;

pub mod issuer_signed;
pub mod issuer_signed_item;

/// mDL (mobile Driving Licence) support — driving privileges, schema validation.
#[cfg(feature = "mdl")]
pub mod mdl;
pub mod mso;
pub mod namespace;
pub mod reader_auth;
pub mod session;
pub mod session_transcript;
pub mod tag24;

pub use cose::{CoseSigner, CoseVerifier};
pub use cose_key::{CoseKey, Curve, KeyOp, KeyType};
pub use device_auth::{DeviceAuth, DeviceAuthentication, DeviceNameSpaces, DeviceSigned};
pub use device_engagement::DeviceEngagement;
pub use error::MdocError;
pub use issuer_signed::{DeviceResponse, IssuerSigned, MdocBuilder};
pub use issuer_signed_item::{IssuerSignedItem, cbor_to_json, json_to_cbor};
pub use mso::{DeviceKeyInfo, MobileSecurityObject, ValidityInfo};
pub use namespace::{EIDAS_PID_NAMESPACE, MDL_NAMESPACE};
pub use reader_auth::{ItemsRequest, ReaderAuthentication};
pub use session::SessionKeys;
pub use session_transcript::{Handover, SessionTranscript};
pub use tag24::Tag24;

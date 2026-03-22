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
 * # Modules
 *
 * - [`tag24`] — CBOR Tag 24 wrapper with byte preservation
 * - [`issuer_signed_item`] — IssuerSignedItem structure and digest computation
 * - [`mso`] — Mobile Security Object
 * - [`cose`] — COSE_Sign1 signing and verification
 * - [`issuer_signed`] — IssuerSigned, MdocBuilder, DeviceResponse
 * - [`namespace`] — Namespace constants (eIDAS PID, mDL)
 */

pub mod cose;
pub mod error;
pub mod issuer_signed;
pub mod issuer_signed_item;
pub mod mso;
pub mod namespace;
pub mod tag24;

pub use cose::{CoseSigner, CoseVerifier};
pub use error::MdocError;
pub use issuer_signed::{DeviceResponse, IssuerSigned, MdocBuilder};
pub use issuer_signed_item::{IssuerSignedItem, cbor_to_json, json_to_cbor};
pub use mso::{DeviceKeyInfo, MobileSecurityObject, ValidityInfo};
pub use namespace::{EIDAS_PID_NAMESPACE, MDL_NAMESPACE};
pub use tag24::Tag24;

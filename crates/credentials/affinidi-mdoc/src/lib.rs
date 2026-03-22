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
 * ├── nameSpaces: { namespace → [DataElement { random, identifier, value }] }
 * └── issuerAuth: COSE_Sign1(MSO)
 *                        └── MSO (Mobile Security Object)
 *                            ├── digestAlgorithm: "SHA-256"
 *                            ├── valueDigests: { namespace → { digestId → hash } }
 *                            ├── docType: "eu.europa.ec.eudi.pid.1"
 *                            └── validityInfo: { signed, validFrom, validUntil }
 *
 * DeviceResponse (presentation)
 * ├── disclosed: { namespace → [selected DataElements] }
 * └── mso: (for digest verification)
 * ```
 *
 * # Selective Disclosure
 *
 * Each attribute has an independent random salt. The MSO contains only digests
 * (hash of salt + identifier + value). During presentation, the holder reveals
 * selected attributes; the verifier recomputes digests and checks against the MSO.
 *
 * # Modules
 *
 * - [`mso`] — Mobile Security Object (digests, validity)
 * - [`issuer_signed`] — IssuerSigned credential and DeviceResponse presentation
 * - [`namespace`] — Namespace constants (eIDAS PID, mDL)
 */

pub mod error;
pub mod issuer_signed;
pub mod mso;
pub mod namespace;

pub use error::MdocError;
pub use issuer_signed::{DeviceResponse, IssuerSigned};
pub use mso::{DataElement, MobileSecurityObject, ValidityInfo};
pub use namespace::{EIDAS_PID_NAMESPACE, MDL_NAMESPACE};

/*!
 * W3C Verifiable Credentials Data Model implementation.
 *
 * Supports both [VCDM 1.1](https://www.w3.org/TR/vc-data-model/) and
 * [VCDM 2.0](https://www.w3.org/TR/vc-data-model-2.0/).
 *
 * # Overview
 *
 * This crate provides the core data types for Verifiable Credentials:
 *
 * - [`VerifiableCredential`] — the credential itself (issuer, subject, claims)
 * - [`VerifiablePresentation`] — wraps credentials for submission to verifiers
 * - [`CredentialBuilder`] / [`PresentationBuilder`] — ergonomic construction
 * - [`CredentialStatus`] — integration point for revocation/suspension checking
 *
 * # Proof Format Agnostic
 *
 * The data model is independent of the proof/signature format. Credentials
 * can be secured using:
 * - **Data Integrity proofs** (embedded in the `proof` field)
 * - **JWT** (external envelope)
 * - **SD-JWT VC** (selective disclosure with external envelope)
 * - **COSE** (for mdoc/mDL)
 *
 * # Version Detection
 *
 * The VCDM version is automatically detected from the `@context` array:
 * - `https://www.w3.org/2018/credentials/v1` → VCDM 1.1
 * - `https://www.w3.org/ns/credentials/v2` → VCDM 2.0
 */

pub mod context;
pub mod credential;
pub mod error;
pub mod presentation;

pub use context::{CREDENTIALS_V1_CONTEXT, CREDENTIALS_V2_CONTEXT};
pub use credential::{
    ContextValue, CredentialBuilder, CredentialStatus, IssuerValue, SubjectValue,
    VerifiableCredential,
};
pub use error::VcError;
pub use presentation::{PresentationBuilder, VerifiablePresentation};

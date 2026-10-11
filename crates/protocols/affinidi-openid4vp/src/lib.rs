/*!
 * OpenID for Verifiable Presentations (OpenID4VP).
 *
 * Implements the [OpenID4VP 1.0](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html)
 * specification for presenting verifiable credentials to verifiers (Relying Parties).
 *
 * Also includes [Presentation Exchange v2](https://identity.foundation/presentation-exchange/spec/v2.0.0/)
 * types for credential matching.
 *
 * # Verifying with OpenID4VP 1.0
 *
 * - [`ClientId`] — the verifier's prefixed client identifier
 *   (`decentralized_identifier:`, `x509_hash:`, …), which is also the
 *   audience a key-binding proof must name.
 * - [`RequestObject`] — the 1.0 request object, signed as a JAR
 *   (`oauth-authz-req+jwt`) by [`RequestObject::sign`], and the wallet
 *   invocation URI that points at its `request_uri`.
 * - `response::receive_direct_post_jwt` (feature `direct-post-jwt`) — reads
 *   and decrypts what the wallet posts to `response_uri`.
 * - [`DcqlQuery::evaluate_presentation`] — whether the verified presentations
 *   satisfy the query.
 *
 * The types below for Presentation Exchange and the pre-1.0 request and
 * response predate these and are kept for existing callers.
 *
 * # Flow
 *
 * 1. Verifier creates an authorization request with a presentation definition
 * 2. Wallet receives the request (via redirect, QR code, or deep link)
 * 3. Wallet matches available credentials against input descriptors
 * 4. User selects which credentials/claims to disclose
 * 5. Wallet creates a VP token with presentation submission
 * 6. Wallet sends authorization response to verifier
 * 7. Verifier validates the VP token, credentials, and submission
 *
 * # Supported Credential Formats
 *
 * - `vc+sd-jwt` — SD-JWT VC (mandatory for eIDAS)
 * - `mso_mdoc` — ISO mdoc (mandatory for eIDAS)
 * - `jwt_vc_json` — JWT-secured VC
 * - `ldp_vc` — Linked Data Proof VC
 */

pub mod client_id;
pub mod dcql;
pub mod error;
pub mod request_object;
/// Receiving an encrypted `direct_post.jwt` authorization response.
#[cfg(feature = "direct-post-jwt")]
pub mod response;
pub mod types;
pub mod verifier;
pub mod wallet;

pub use client_id::{ClientId, ClientIdPrefix};
pub use request_object::{JarHeader, RequestObject, VerifierClientMetadata};

pub use dcql::{
    CandidateCredential, ClaimPathSegment, ClaimsQuery, CredentialMatch, CredentialQuery,
    CredentialSetQuery, DcqlMatch, DcqlQuery, TrustedAuthoritiesQuery, TrustedAuthorityType,
};
pub use error::Oid4vpError;
pub use types::*;

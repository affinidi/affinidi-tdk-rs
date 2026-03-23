/*!
 * OpenID for Verifiable Presentations (OpenID4VP).
 *
 * Implements the [OpenID4VP 1.0](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html)
 * specification for presenting verifiable credentials to verifiers (Relying Parties).
 *
 * Also includes [Presentation Exchange v2](https://identity.foundation/presentation-exchange/spec/v2.0.0/)
 * types for credential matching.
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

pub mod error;
pub mod types;
pub mod verifier;
pub mod wallet;

pub use error::Oid4vpError;
pub use types::*;

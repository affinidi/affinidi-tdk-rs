/*!
 * OpenID for Verifiable Credential Issuance (OpenID4VCI).
 *
 * Implements the [OpenID4VCI 1.0](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)
 * specification for issuing verifiable credentials to wallet instances.
 *
 * # Flows
 *
 * ## Authorization Code Flow
 * 1. Issuer creates credential offer (QR code / deep link)
 * 2. Wallet discovers issuer metadata
 * 3. Wallet initiates OAuth 2.0 authorization
 * 4. User authenticates at issuer
 * 5. Wallet receives authorization code
 * 6. Wallet exchanges code for access token
 * 7. Wallet requests credential with proof of possession
 * 8. Issuer returns signed credential
 *
 * ## Pre-Authorized Code Flow
 * 1. Issuer creates credential offer with pre-authorized code
 * 2. Wallet discovers issuer metadata
 * 3. Wallet exchanges pre-authorized code (+ optional PIN) for access token
 * 4. Wallet requests credential with proof of possession
 * 5. Issuer returns signed credential
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

pub use error::Oid4vciError;
pub use types::*;

/*!
 * OpenID for Verifiable Credential Issuance (OpenID4VCI).
 *
 * Message types and issuer/wallet helpers modelled on
 * [OpenID4VCI draft 13](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-13.html).
 *
 * **This is not OpenID4VCI 1.0 Final.** The wire types are the draft-13
 * shapes (`format` + `proof` in [`types::CredentialRequest`], a single
 * `credential` + `c_nonce` in [`types::CredentialResponse`],
 * `batch_credential_endpoint` in issuer metadata, `vc+sd-jwt` as the SD-JWT VC
 * format). A 1.0 Final peer cannot exchange these messages with this crate.
 *
 * # Scope
 *
 * The crate covers issuer metadata, credential offers, the credential
 * request/response, a structural request check, deferred responses and the
 * key-binding [`proof`] (build + verify). It does **not** model the OAuth
 * token endpoint (no token request/response types, no PKCE, no `tx_code`
 * verification) or batch issuance: those steps of the flows below are the
 * caller's responsibility.
 *
 * # Flows (for orientation; steps 3–6 / 3 are outside this crate)
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
pub mod issuer;
pub mod proof;
pub mod types;
pub mod wallet;

pub use error::Oid4vciError;
pub use proof::{KeyProof, KeyProofClaims, ProofPolicy, build_key_proof_jwt};
pub use types::*;

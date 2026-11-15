/*!
 * OpenID for Verifiable Credential Issuance (OpenID4VCI).
 *
 * Two versions of the protocol, side by side:
 *
 * | Version | Modules |
 * |---|---|
 * | [OpenID4VCI **1.0 Final**](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html) | [`v1`] ([`v1::types`], [`v1::issuer`], [`v1::wallet`]) |
 * | [OpenID4VCI **draft 13**](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-13.html) | [`types`] (re-exported at the crate root), [`issuer`], [`wallet`] |
 *
 * The key-binding [`proof`] module (`openid4vci-proof+jwt` build + verify) is
 * version-independent and used by both.
 *
 * The two message sets are **not** wire compatible: draft 13 uses `format` +
 * `proof` in [`types::CredentialRequest`], a single `credential` + `c_nonce`
 * in [`types::CredentialResponse`], `batch_credential_endpoint` in issuer
 * metadata and `vc+sd-jwt` as the SD-JWT VC format. 1.0 Final uses
 * `credential_configuration_id` / `credential_identifier` + `proofs`, a
 * `credentials` array, a Nonce Endpoint, `notification_endpoint` /
 * `batch_credential_issuance` metadata and `dc+sd-jwt` — see [`v1`]. Pick the
 * module matching your peer; new integrations should use [`v1`].
 *
 * # Scope
 *
 * **1.0 Final ([`v1`])**: issuer metadata, credential offers (by value / by
 * reference), authorization details, the pre-authorized code Token
 * Request/Response with `tx_code` checks, the Nonce Endpoint, credential
 * request/response with batch `proofs`, deferred issuance, notifications and
 * the error responses; request validation against issuer metadata and `jwt`
 * key proof verification. Not modelled: JWE encryption (§10), signed metadata
 * verification, the Authorization Endpoint / PAR / PKCE, wallet and key
 * attestation evaluation.
 *
 * **Draft 13** (crate root): issuer metadata, credential offers, the
 * credential request/response, a structural request check, deferred
 * responses. No token endpoint types or batch issuance.
 *
 * # Flows (for orientation)
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
 * Steps 3–6 are the caller's OAuth stack in both versions.
 *
 * ## Pre-Authorized Code Flow
 * 1. Issuer creates credential offer with pre-authorized code
 * 2. Wallet discovers issuer metadata
 * 3. Wallet exchanges pre-authorized code (+ optional `tx_code`) for an
 *    access token ([`v1`] has the token request/response and the check)
 * 4. Wallet fetches a `c_nonce` from the Nonce Endpoint (1.0 Final)
 * 5. Wallet requests credential with proof of possession
 * 6. Issuer returns signed credential(s)
 *
 * # Supported Credential Formats
 *
 * - SD-JWT VC — `dc+sd-jwt` in 1.0 Final ([`v1::FORMAT_DC_SD_JWT`]),
 *   `vc+sd-jwt` in draft 13 ([`FORMAT_SD_JWT_VC`])
 * - `mso_mdoc` — ISO mdoc
 * - `jwt_vc_json` — JWT-secured VC
 * - `ldp_vc` — Linked Data Proof VC
 */

pub mod error;
pub mod issuer;
pub mod proof;
pub mod types;
pub mod v1;
pub mod wallet;

pub use error::Oid4vciError;
pub use proof::{KeyProof, KeyProofClaims, ProofPolicy, build_key_proof_jwt};
pub use types::*;

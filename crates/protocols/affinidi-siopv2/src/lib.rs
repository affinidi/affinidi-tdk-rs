/*!
 * Self-Issued OpenID Provider v2 (SIOPv2).
 *
 * Implements [OpenID Connect Self-Issued OP v2](https://openid.net/specs/openid-connect-self-issued-v2-1_0.html)
 * for decentralized authentication where the End-User IS the OpenID Provider.
 *
 * # How It Works
 *
 * In standard OpenID Connect, a third-party OP (Google, etc.) issues ID Tokens.
 * In SIOPv2, the **user's wallet** is the OP — it signs its own ID Token with
 * keys the user controls. The critical invariant: **`iss == sub`**.
 *
 * # Protocol Flow
 *
 * ```text
 * Relying Party                    Self-Issued OP (Wallet)
 *     |                                    |
 *     |--- (1) Authorization Request ----->|  (redirect, QR, deep link)
 *     |                                    |
 *     |                              (2) User authenticates
 *     |                              (3) Wallet creates ID Token
 *     |                                    |
 *     |<-- (4) Authorization Response -----|  (fragment or direct_post)
 *     |        (id_token)                  |
 *     |                                    |
 *     |- (5) Validate ID Token             |
 *     |- (6) Check iss == sub              |
 *     |- (7) Verify signature              |
 * ```
 *
 * # Subject Types
 *
 * - **JWK Thumbprint**: `sub` = base64url(SHA-256(canonical_jwk)),
 *   public key in `sub_jwk` claim
 * - **DID**: `sub` = DID string, key resolved from DID Document
 *
 * # eIDAS 2.0
 *
 * Provides wallet-to-RP authentication for the EUDI Wallet,
 * complementing OpenID4VP for credential presentation.
 */

pub mod error;
pub mod id_token;
pub mod metadata;
pub mod request;

pub use error::SiopError;
pub use id_token::{IdTokenBuilder, SelfIssuedIdToken};
pub use metadata::SiopMetadata;
pub use request::{AuthorizationRequest, AuthorizationResponse};

// Re-export shared types from oid4vc-core for convenience
pub use affinidi_oid4vc_core::{
    ClientMetadata, ResponseMode, ResponseType, SubjectSyntaxType, compute_jwk_thumbprint,
};

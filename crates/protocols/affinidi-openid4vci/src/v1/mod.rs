/*!
 * OpenID4VCI **1.0 Final**.
 *
 * Wire types and issuer/wallet helpers for
 * [OpenID for Verifiable Credential Issuance 1.0](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)
 * (Final, 16 September 2025). The crate-root types ([`crate::types`],
 * [`crate::issuer`], [`crate::wallet`]) remain the **draft 13** shapes; the
 * two sets are independent and do not interoperate on the wire.
 *
 * | Module | Contents |
 * |---|---|
 * | [`types`] | Issuer metadata (§12.2.4), Credential Offer (§4.1), authorization details (§5.1.1), Token Request/Response (§6), Nonce Response (§7.2), Credential Request/Response (§8.2, §8.3), Deferred Credential Request/Response (§9), Notification Request (§11.1), error responses (§6.3, §8.3.1, §9.3, §11.3) |
 * | [`issuer`] | Offer construction, pre-authorized code + `tx_code` check, Credential Request validation, `jwt` key proof verification |
 * | [`wallet`] | Offer parsing (by value / by reference), metadata URL and checks, pre-authorized Token Request, request builders, response checks |
 *
 * What changed from draft 13, in wire terms:
 *
 * - Credential Request: `credential_configuration_id` **or**
 *   `credential_identifier` (no `format` / `vct` / `doctype`); key proofs in
 *   `proofs: { "<proof type>": [..] }` (no single `proof`).
 * - Credential Response: `credentials: [{ "credential": .. }]`,
 *   `transaction_id` + `interval` for deferral, `notification_id`; no
 *   `c_nonce` — nonces come from the Nonce Endpoint (§7).
 * - Issuer metadata: `nonce_endpoint`, `notification_endpoint`,
 *   `batch_credential_issuance`, request/response encryption objects; no
 *   `batch_credential_endpoint`; per-configuration `display` / `claims`
 *   moved under `credential_metadata`; the metadata URL inserts the
 *   well-known segment before the issuer path.
 * - SD-JWT VC format identifier `dc+sd-jwt` ([`types::FORMAT_DC_SD_JWT`]).
 *
 * The key-binding [`crate::proof`] module (`openid4vci-proof+jwt`, Appendix
 * F.1) is shared by both versions.
 *
 * # Not modelled
 *
 * JWE encryption/decryption of requests and responses (§10 — only the
 * parameter types are here), signed issuer metadata verification (§12.2.3),
 * the Authorization Endpoint / PAR / PKCE (§5), wallet attestations
 * (Appendix E), key attestation evaluation (Appendix D), and `di_vp` /
 * `attestation` proof verification (structural checks only).
 */

pub mod issuer;
pub mod types;
pub mod wallet;

pub use types::*;

#[cfg(test)]
mod spec_examples;
#[cfg(test)]
mod tests;

/*!
 * Credential status and revocation management.
 *
 * Implements:
 * - [W3C Bitstring Status List v1.0](https://www.w3.org/TR/vc-bitstring-status-list/)
 * - eIDAS 2.0 Attestation Status List (ASL) — maps to `BitstringStatusList`
 * - eIDAS 2.0 Attestation Revocation List (ARL) — maps to `RevocationList`
 * - [IETF Token Status List](https://datatracker.ietf.org/doc/draft-ietf-oauth-status-list/)
 *   (`draft-ietf-oauth-status-list-21`) — the `statuslist+jwt` that SD-JWT VCs
 *   and the EUDI / swiyu profiles reference, in [`token`]
 *
 * # Choosing a Mechanism
 *
 * | Mechanism | Use Case | Privacy | Lookup |
 * |---|---|---|---|
 * | `BitstringStatusList` | Large-scale, privacy-preserving | Random indices, decoys | O(1) |
 * | `TokenStatusList` | SD-JWT VC, EUDI / swiyu | Random indices | O(1) |
 * | `RevocationList` | Small sets, metadata tracking | Lower (serial numbers exposed) | O(1) HashSet |
 * | Short-lived credentials | Frequently updated | Best (no status check) | N/A |
 *
 * # Privacy Considerations (eIDAS 2.0)
 *
 * - Status lists MUST be downloadable without RP authentication
 * - RPs SHOULD cache lists and NOT request on every presentation
 * - Providers MUST use cryptographically random index assignment
 * - Decoy entries SHOULD be added to obscure actual counts
 * - Lists SHOULD be large enough for herd privacy (minimum 131,072 entries)
 */

pub mod bitstring;
pub mod error;
pub mod revocation_list;
pub mod token;

pub use bitstring::{
    BitstringStatusList, DEFAULT_BITSTRING_SIZE, MIN_BITSTRING_SIZE, StatusListEntry, StatusPurpose,
};
pub use error::StatusListError;
pub use revocation_list::RevocationList;
pub use token::{
    EncodedStatusList, STATUS_LIST_JWT_MEDIA_TYPE, STATUS_LIST_JWT_TYP, StatusListReference,
    TokenStatus, TokenStatusList, VerifiedStatusListToken, VerifyOptions,
    status_list_token_payload,
};

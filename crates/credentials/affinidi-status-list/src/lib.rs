/*!
 * Credential status and revocation management.
 *
 * Implements:
 * - [W3C Bitstring Status List v1.0](https://www.w3.org/TR/vc-bitstring-status-list/)
 * - eIDAS 2.0 Attestation Status List (ASL) — maps to `BitstringStatusList`
 * - eIDAS 2.0 Attestation Revocation List (ARL) — maps to `RevocationList`
 *
 * # Choosing a Mechanism
 *
 * | Mechanism | Use Case | Privacy | Lookup |
 * |---|---|---|---|
 * | `BitstringStatusList` | Large-scale, privacy-preserving | Random indices, decoys | O(1) |
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

pub use bitstring::{
    BitstringStatusList, DEFAULT_BITSTRING_SIZE, MIN_BITSTRING_SIZE, StatusListEntry, StatusPurpose,
};
pub use error::StatusListError;
pub use revocation_list::RevocationList;

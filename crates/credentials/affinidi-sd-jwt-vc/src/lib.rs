/*!
 * # DEPRECATED — moved to [`affinidi-vc`]
 *
 * This crate has been merged into [`affinidi-vc`]. The SD-JWT VC implementation
 * now lives at [`affinidi_vc::sd_jwt_vc`] — a credential *format* belongs with
 * the Verifiable Credentials data model rather than in its own crate.
 *
 * This crate is now a thin re-export kept for one release to ease migration and
 * will be removed in a future version. Update your imports:
 *
 * ```text
 * - use affinidi_sd_jwt_vc::{SdJwtVc, issue, verify_temporal, SdJwtVcError};
 * + use affinidi_vc::sd_jwt_vc::{SdJwtVc, issue, verify_temporal, SdJwtVcError};
 * ```
 *
 * Add `affinidi-vc` to your dependencies and drop `affinidi-sd-jwt-vc`.
 *
 * [`affinidi-vc`]: https://crates.io/crates/affinidi-vc
 */

// Re-export the merged module's full surface so every former
// `affinidi_sd_jwt_vc::*` path keeps resolving for one release:
//   affinidi_sd_jwt_vc::{SdJwtVc, issue, verify_temporal, SdJwtVcError}
pub use affinidi_vc::sd_jwt_vc::*;
//   affinidi_sd_jwt_vc::error::{SdJwtVcError, Result}
pub use affinidi_vc::sd_jwt_vc::error;

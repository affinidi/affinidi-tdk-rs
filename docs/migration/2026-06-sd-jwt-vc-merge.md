# Migration — `affinidi-sd-jwt-vc` merged into `affinidi-vc` (2026-06)

**Task W18b.** SD-JWT VC is a credential *format*, so its implementation now
lives alongside the W3C Verifiable Credentials data model in
[`affinidi-vc`](../../crates/credentials/affinidi-vc) rather than in its own
crate. The former `affinidi-sd-jwt-vc` crate is now a thin re-export kept for
**one release** to ease migration, and will be removed afterwards.

## What changed

| Before | After |
|---|---|
| `affinidi-sd-jwt-vc` crate (`0.1.1`) | `affinidi_vc::sd_jwt_vc` module (in `affinidi-vc` `0.2.0`) |
| `affinidi_sd_jwt_vc::SdJwtVc` | `affinidi_vc::sd_jwt_vc::SdJwtVc` |
| `affinidi_sd_jwt_vc::{issue, verify_temporal}` | `affinidi_vc::sd_jwt_vc::{issue, verify_temporal}` |
| `affinidi_sd_jwt_vc::SdJwtVcError` | `affinidi_vc::sd_jwt_vc::SdJwtVcError` |
| `affinidi_sd_jwt_vc::error::{SdJwtVcError, Result}` | `affinidi_vc::sd_jwt_vc::error::{SdJwtVcError, Result}` |

The module's public surface is **identical** — only the path changed. No
behaviour, signatures, or error variants were modified.

## How to migrate

### Direct consumers of `affinidi-sd-jwt-vc`

1. Add `affinidi-vc = "0.2"` to your `Cargo.toml` (if not already present) and
   remove `affinidi-sd-jwt-vc`.
2. Update imports:

   ```diff
   - use affinidi_sd_jwt_vc::{SdJwtVc, issue, verify_temporal, SdJwtVcError};
   + use affinidi_vc::sd_jwt_vc::{SdJwtVc, issue, verify_temporal, SdJwtVcError};
   ```

Until you migrate, the `affinidi-sd-jwt-vc 0.2.0` re-export shim keeps the old
paths compiling, but it is deprecated and will be removed.

### `affinidi-tdk` facade users

No source change required. `affinidi_tdk::sd_jwt_vc` still resolves (it now
re-exports `affinidi_vc::sd_jwt_vc`), and the `sd-jwt-vc` feature is unchanged —
it now implies the `vc` feature. The `affinidi-tdk` `credentials` feature group
is unaffected.

## Test helpers

The `_test-utils` feature that gated the SD-JWT test signer moved to
`affinidi-vc` (`affinidi-vc/_test-utils` → `affinidi-sd-jwt/_test-utils`). The
`sd_jwt_vc` module's own tests compile under a plain `cargo test -p affinidi-vc`
via a dev-dependency, so no flag is needed for the workspace test run.

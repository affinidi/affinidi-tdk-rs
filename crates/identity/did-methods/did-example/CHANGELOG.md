# did:example

## [0.6.0] - 2026-11-17

**Breaking (R3.6): moves to the new generation of its affinidi dependencies.** affinidi-did-common's `Document` appear in this crate's public API, so it moves a minor even where its own code is unchanged. Part of the coordinated breaking release of #1143 and #1166: affinidi-crypto 0.4, affinidi-encoding 0.2, affinidi-secrets-resolver 0.6, affinidi-did-common 0.5, affinidi-did-resolver-traits 0.2, affinidi-did-web 0.2, affinidi-did-resolver-cache-sdk 0.9 and affinidi-data-integrity 0.9 move together; a crate that mixes two generations does not compile.

## [0.5.10] - 2026-11-15

Workspace lint and dependency housekeeping. No API or behaviour change.

- Dependency versions now come from the root `[workspace.dependencies]`
  for the external crates shared by five or more workspace members
  (#1070). The published manifest still names concrete requirements; the
  resolved dependency graph and every feature selection are unchanged.
- Now inherits the workspace lints (`[lints] workspace = true`, #1064):
  `unsafe_code` is denied and the workspace clippy lints apply.
- Minimum dependency requirements raised to versions already in use across the
  workspace (no new major/minor, Cargo.lock unchanged): `affinidi-did-common`
  0.4 -> 0.4.8.

## Changelog history

## [0.5.9] - 2026-07-19

affinidi-did-common 0.4

- Bumped the `affinidi-did-common` requirement from `"0.3"` to `"0.4"`.
  No functional change to this crate: `Document` gained a typed
  `also_known_as` field, which is additive.

## [0.5.8] - 2026-06-14

non_exhaustive DidExampleError (W7 sweep)

- `DidExampleError` is now `#[non_exhaustive]` (ADR-0003) so new variants land
  additively. Patch bump keeps the `0.5` pin valid; consumers that `match` it
  must add a `_` wildcard arm. No behaviour change.

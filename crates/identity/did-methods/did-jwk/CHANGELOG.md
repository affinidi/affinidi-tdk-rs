# Changelog

## [0.1.3] - 2026-11-15

`resolve_did` and an optional resolver-trait impl

### Added

- `resolve_did(&DID)` (#1153): resolve a parsed `did:jwk` DID (or DID URL)
  from the identifier its `DIDMethod::Jwk` holds, without splitting the DID
  string again. `NotJwk` for another method.
- Feature `resolver-traits` (off by default): `JwkResolver`, an
  `affinidi_did_resolver_traits::Resolver` (and so `AsyncResolver`) that
  resolves did:jwk and declines every other method. A failure is
  `ResolverError::ResolutionFailed`.

## [0.1.2] - 2026-11-15

Workspace lint and dependency housekeeping. No API or behaviour change.

- Dependency versions now come from the root `[workspace.dependencies]`
  for the external crates shared by five or more workspace members
  (#1070). The published manifest still names concrete requirements; the
  resolved dependency graph and every feature selection are unchanged.
- Workspace lints now include `unsafe_code = "deny"` (#1064).
- Minimum dependency requirements raised to versions already in use across the
  workspace (no new major/minor, Cargo.lock unchanged): `affinidi-did-common`
  0.4 -> 0.4.8.

## [0.1.1] - 2026-08-23

dependency refresh

- Bumps `base64` 0.22 → 0.23.
- No source or API change; the bumps are declaration-only and the crate
  compiles unmodified against them. Bumped workspace-wide in the same
  change so no two versions of these crates are compiled side by side.

## [0.1.0] - 2026-08-22

initial release

In-tree replacement for the spruceid `did-jwk` crate, written to drop the
`ssi-*` dependency stack (`im`, `sized-chunks`, `bitmaps`, `smallstr`,
`proc-macro-error`, `derivative` — all unmaintained and archived with no fixed
release — plus `reqwest 0.11` and the vulnerable `h2 0.3.x`).

See `README.md` for scope, conformance and behavioural differences.

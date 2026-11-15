# Affinidi DID Resolver Traits

## [0.1.6] - 2026-11-15

Workspace lint and dependency housekeeping. No API or behaviour change.

- Dependency versions now come from the root `[workspace.dependencies]`
  for the external crates shared by five or more workspace members
  (#1070). The published manifest still names concrete requirements; the
  resolved dependency graph and every feature selection are unchanged.
- Workspace lints now include `unsafe_code = "deny"` (#1064).

## Changelog history

## [0.1.5] - 2026-11-15

`Retry-After`, and the method crates' `NetworkError`

- Added `NetworkFetchError::retry_after` and `with_retry_after`: how long the
  host asked the caller to wait. Additive (`NetworkFetchError` is
  `#[non_exhaustive]`).
- Added `From<affinidi_did_common::NetworkError>` for `NetworkFetchError` and
  for `ResolverError` (to `NetworkFetch`), keeping the URL, status and
  `Retry-After` that did:webs, did:ebsi and did:scid now report (#1043).
- The built-in resolvers match on `DID::method_ref` instead of cloning the
  method.
- Requires `affinidi-did-common` 0.4.8, whose did:peer:0 documents are built
  under the peer DID (#1039): `PeerResolver` returns them as they are.
  Behaviour change for a caller that looked up a did:peer:0 key by its
  `did:key:…` id (R3.6).

## [0.1.4] - 2026-09-16

typed network fetch failures

- Added `ResolverError::NetworkFetch(NetworkFetchError)`. A resolver whose
  fetch fails reports the URL and the HTTP status as data instead of a string,
  so a caller can tell a host that rate-limited it (HTTP 429,
  `NetworkFetchError::is_rate_limited`) from a DID that is invalid.
- `NetworkFetchError` is `#[non_exhaustive]` and built with `new`,
  `with_url` and `with_status`; a `Retry-After` field can be added later
  without a breaking release.
- Additive: `ResolverError` has been `#[non_exhaustive]` since 0.1.2, so a
  new variant breaks no `match`. Patch bump per ADR 0003.

## [0.1.3] - 2026-07-19

affinidi-did-common 0.4

- Bumped the `affinidi-did-common` requirement from `"0.3"` to `"0.4"`.
  No functional change to this crate: `Document` gained a typed
  `also_known_as` field, which is additive.

## [0.1.2] - 2026-06-14

non_exhaustive ResolverError (W7 sweep)

- `ResolverError` is now `#[non_exhaustive]` (ADR-0003) so new variants land
  additively. Patch bump keeps the `0.1` pin valid; consumers that `match` it
  must add a `_` wildcard arm. No behaviour change.

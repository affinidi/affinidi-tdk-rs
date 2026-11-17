# did:scid

## [0.5.0] - 2026-11-17

**Breaking (R3.6): moves to the new generation of its affinidi dependencies.** affinidi-did-common's `Document`, affinidi-did-webs' `WebsResolver` and `didwebvh-rs` types appear in this crate's public API, so it moves a minor even where its own code is unchanged. Part of the coordinated breaking release of #1143 and #1166: affinidi-crypto 0.4, affinidi-encoding 0.2, affinidi-secrets-resolver 0.6, affinidi-did-common 0.5, affinidi-did-resolver-traits 0.2, affinidi-did-web 0.2, affinidi-did-resolver-cache-sdk 0.9 and affinidi-data-integrity 0.9 move together; a crate that mixes two generations does not compile.

- The optional `resolver-traits` feature moves to affinidi-did-resolver-traits 0.2.
- Requires a `didwebvh-rs` release that accepts affinidi-did-common 0.5,
  affinidi-data-integrity 0.9 and affinidi-secrets-resolver 0.6.

## [0.4.11] - 2026-11-15

optional resolver-trait impl

### Added

- Feature `resolver-traits` (off by default) (#1153): `ScidResolver`, an
  `affinidi_did_resolver_traits::AsyncResolver` (name `"ScidResolver"`) that
  resolves did:scid under its `ResolveOptions` (`ScidResolver::with_options`;
  with `did-webs`, `with_webs_resolver` reuses a did:webs resolver for the
  `ke` format) and declines every other method. The source is the DID URL's
  `src`; a peer DID has none here and fails with `MissingPeerSource`. A
  failed fetch is `ResolverError::NetworkFetch` with its URL, status and
  `Retry-After`; anything else is `ResolverError::ResolutionFailed`.

## [0.4.10] - 2026-11-15

Workspace lint and dependency housekeeping. No API or behaviour change.

- Dependency versions now come from the root `[workspace.dependencies]`
  for the external crates shared by five or more workspace members
  (#1070). The published manifest still names concrete requirements; the
  resolved dependency graph and every feature selection are unchanged.
- Now inherits the workspace lints (`[lints] workspace = true`, #1064):
  `unsafe_code` is denied and the workspace clippy lints apply.
- Minimum dependency requirements raised to versions already in use across the
  workspace (no new major/minor, Cargo.lock unchanged): `affinidi-did-webs`
  0.13 -> 0.13.6.

## [0.4.9] - 2026-11-15

builds without `did-webvh`; `ke` honours the options and resolves to the did:scid DID

- **Fixed (#1041):** `didwebvh-rs` is a hard dependency. The public API is
  typed in it (`ResolveOptions`, `DIDSCIDError::WebVHError`) and the crate
  never compiled without it, so `default-features = false, features =
  ["did-webs"]` failed to build. The `did-webvh` feature stays, empty, so a
  consumer naming it still builds.
- **Changed (#1041):** `did:scid:ke` honours `resolve_with_options`'
  `timeout` and `host_policy` (`HostPolicy::AllowPrivate` resolves a local
  did:webs host). Before, it always used a fresh `PublicOnly` did:webs
  resolver with its 20 s default, whatever the options said. New
  `resolve_with_webs_resolver` (feature `did-webs`) resolves `ke` with a
  did:webs resolver the caller holds, reusing its connection pool.
- **Changed (#1041):** `did:scid:ke` resolves to the did:scid DID's own
  document, as `vh` does: its `id` is the bare `did:scid:ke:1:<AID>`, every
  reference the did:webs document makes to itself is under it, and
  `alsoKnownAs` gains `did:scid:ke:1:<AID>?src=<location>` and the
  `did:webs:…` DID. Before, the did:webs document came back unchanged.
- **Changed (#1043):** an unsuccessful HTTP status from a `ke` source fails
  with the new `DIDSCIDError::Network(NetworkError)` (URL, status,
  `Retry-After`) instead of `WebsError("…HTTP …")`. New
  `DIDSCIDError::network_error()` reads that and a did:webvh
  `NetworkError` alike.
- Failed resolutions log at `debug`, not `error`: they are the caller's to
  report, and the DIDs are often untrusted input.
- The `did:scid` parser no longer uses `regex` (dependency removed); it
  accepts exactly what the pattern did.
- Docs (#1045): the crate docs and README no longer offer did:cheqd as a
  `vh` backend (retired in 0.2.6); the README's install line, feature table and
  badge link are current.
- Requires `affinidi-did-common` 0.4.8 and, with `did-webs`,
  `affinidi-did-webs` 0.13.6.
- Compatibility (R3.6): no signature change. A `did:scid:ke` document's `id`
  and key ids are `did:scid:ke:1:…`, not `did:webs:…`; a `ke` lookup that
  ignored a non-public host policy or timeout now follows it; a caller
  matching `WebsError` for an HTTP status now gets `Network`.

## [0.4.8] - 2026-11-12

a deactivated did:scid:ke does not resolve

- **Behaviour:** `resolve` and `resolve_with_options` refuse a `did:scid:ke`
  whose did:webs identifier is deactivated (its last rotation committed to no
  next keys), with the new `DIDSCIDError::Deactivated`. Before, it resolved
  `Ok` with the identifier's last keys, while `did:scid:vh` already refused a
  deactivated did:webvh. The did:webs DID is now resolved with its metadata and
  the deactivation checked here, whichever `affinidi-did-webs` 0.13 release is
  in the build. Compatibility (R3.6): a lookup that returned a document now
  returns an error; `DIDSCIDError` is `#[non_exhaustive]`.

## [0.4.7] - 2026-11-11

affinidi-did-webs 0.13

- **Changed:** the `did-webs` feature moves to `affinidi-did-webs` 0.13, on
  affinidi-keri 0.8: native CESR bodies resolve, keripy's delegated rotations
  verify, and the `EO` and `DND` configuration traits are enforced.

## [0.4.6] - 2026-11-11

affinidi-did-webs 0.12

- **Changed:** the `did-webs` feature moves to `affinidi-did-webs` 0.12, on
  affinidi-keri 0.7: rotations verify as keripy verifies them, and a recovery
  rotation supersedes interaction events and what they anchored.

## [0.4.5] - 2026-11-10

affinidi-did-webs 0.11

- **Changed:** the `did-webs` feature moves to `affinidi-did-webs` 0.11: did:webs
  on KERI 2.0 (alpha). Designations are read for both ACDC versions, a stream
  that leaves out an anchored registry event fails resolution, and a critical
  designation the resolver does not implement fails with
  `unsupportedDesignation`.

## [0.4.4] - 2026-11-10

affinidi-did-webs 0.10

- **Changed:** the `did-webs` feature moves to `affinidi-did-webs` 0.10, on
  affinidi-keri 0.6: rotations now verify in keripy, and thresholds of 10 or
  more are read as hex.

## [0.4.3] - 2026-11-09

affinidi-did-webs 0.9

- **Changed:** the `did-webs` feature moves to `affinidi-did-webs` 0.9, which
  no longer turns on `serde_json`'s `preserve_order` for the whole build.

## [0.4.2] - 2026-11-08

affinidi-did-webs 0.8

- **Changed:** the `did-webs` feature moves to `affinidi-did-webs` 0.8, which
  resolves as the did:webs specification requires: a DID resolves only when its
  AID designates it, signatures are held to the signing threshold, replies are
  ordered by BADA, and the published `did.json` is compared as a whole.

## [0.4.1] - 2026-10-31

the version ids of a resolved log

- **Added:** `ScidResolution::version_ids`, the `versionId` of every log entry
  verified, oldest first. A caller holding a version it verified earlier can
  check that a newer log still contains it: a log that does not is a fork,
  which anyone holding a leaked update key can sign and serve from any host
  under the same did:scid.
- **Added:** `ScidResolution::witness_threshold`, the did:webvh witness
  threshold the latest entry was verified against, or `None` when it is
  unwitnessed.

## [0.4.0] - 2026-10-21

a did:scid resolves to its own document

- **Behaviour (breaking for did:scid callers):** `resolve` and
  `resolve_with_options` now return the did:scid's own document for the `vh`
  format, rather than the did:webvh document that verifies it. Its `id` is the
  bare `did:scid:vh:1:<scid>` DID (`?src=` is a locator, not part of the
  identity), every reference the log makes to itself is under that DID, and
  `alsoKnownAs` lists the did:scid DID URL of the log's location and the
  did:webvh DID. Before, `id` and every key id were the did:webvh DID, which
  DID Core does not allow for a resolved did:scid and which left a verifier
  that looked up a `did:scid:…#key` reference with no key to find. Requires
  `didwebvh-rs` with `did_web::to_scid_did_document`.
- **Added:** `resolve_scid`, returning a `ScidResolution` with the document and
  the source, did:webvh DID and version the log was resolved at, so a caller
  can resolve the bare DID later and refuse an older copy of the log.
- **Added:** `resolve_with_options`, which passes
  `didwebvh_rs::resolve::ResolveOptions` to the did:webvh resolution of the
  `vh` format, so a caller can resolve under its own host policy (for example
  `did:scid:vh:1:<scid>?src=localhost:8000` in a local stack).

## [0.3.0] - 2026-10-01

didwebvh-rs 0.8

**Breaking.** Moves to `didwebvh-rs` 0.8 (on `affinidi-data-integrity` 0.8).
`DIDSCIDError` wraps didwebvh-rs's error type, so this is a public dependency
and moving it is breaking. No behaviour change.

## [0.2.8] - 2026-09-29

a deactivated `did:scid:vh` no longer resolves

- **Behaviour (security):** `resolve` for a `did:scid:vh` DID whose webvh log
  ends in a deactivation now returns `DIDSCIDError::WebVHError` wrapping
  `DIDWebVHError::DeactivatedError`. `didwebvh-rs` resolves such a log `Ok`
  with the last document and flags the deactivation only in metadata, which
  `resolve` discarded, so the retired DID's keys stayed usable. No API change.
  (SEC-4045 / VGI-04.)

## [0.2.7] - 2026-09-12

`didwebvh-rs` 0.7

- Bumps `didwebvh-rs` 0.6 → 0.7. Only the manifest changes.
- **Behaviour:** `resolve` for a `did:scid:vh` DID now contacts public hosts
  only. `didwebvh-rs` 0.7 refuses `localhost`, other special-use names, and
  names that resolve to non-public addresses. A `src` such as `localhost:3000`
  now fails with `DIDSCIDError::WebVHError` wrapping
  `DIDWebVHError::BlockedHost`, and no request is made. `resolve` takes no host
  policy argument, so this crate offers no opt-out.
- `DIDSCIDError::WebVHError` wraps `didwebvh_rs::DIDWebVHError`, so that variant
  now carries the 0.7 type. This is a patch bump per ADR 0003 point 3, as for
  the `didwebvh-rs` 0.5 → 0.6 move.

## [0.2.6] - 2026-09-05

retire did:cheqd resolution

Part of [#760]. A `did:scid` whose `?src=` names a `did:cheqd` still parses, and
`ScidMethod::Cheqd` is unchanged; `resolve` now returns an explanatory
`CheqdError` instead of resolving.

The implementation came from `did-resolver-cheqd`, which pinned `ssi-dids-core
0.1` and — even unbuilt, behind an off-by-default feature — pulled eight
advisories into `Cargo.lock`, including a live `h2` denial-of-service. The crate
publishes no source repository and has a single 2025 release, so there was
nothing to upgrade to and nothing to fork. See
`affinidi-did-resolver-cache-sdk` 0.8.36 for the full accounting.

Nothing was removed from the public API: the `did-cheqd` feature remains (now
empty) and so does the enum variant, so code naming either still compiles.

[#760]: https://github.com/affinidi/affinidi-tdk-rs/issues/760

## [0.2.5] - 2026-08-23

### Changed

- `did-webs` feature now requires `affinidi-did-webs` 0.7.

## [0.2.4] - 2026-08-23

### Changed

- `did-webs` feature now requires `affinidi-did-webs` 0.6.

## [0.2.3] - 2026-08-23

### Fixed

- **`did:scid:ke` was unreachable through `resolve`.** The public entry point
  still opened with `if did.starts_with("did:scid:vh:1")`, so a `ke` DID
  returned `UnsupportedFormat` and never reached the conversion added in 0.2.0.
  The format dispatch was correct; nothing could get to it.

  Every test for `ke` called the private `convert_scid_to_method` directly, so
  the whole suite passed while the feature did not work. `resolve` is now tested
  at the public boundary — including that a `ke` DID gets *past* format dispatch
  — and those tests fail if the gate is put back.

  `did:scid:ke` did not work in 0.2.0, 0.2.1 or 0.2.2.

## [0.2.2] - 2026-08-23

### Changed

- `did-webs` feature now requires `affinidi-did-webs` 0.5.

## [0.2.1] - 2026-08-23

### Changed

- `did-webs` feature now requires `affinidi-did-webs` 0.4, which derives service
  endpoints from signed KERI endpoint authorisations.

## [0.2.0] - 2026-08-23

### Added

- **`did:scid:ke:1` — KERI AIDs via `did:webs`**, behind a new `did-webs`
  feature so the KERI stack stays out of builds that never resolve it.

  ⚠️ The method type registry (Appendix A of the specification) is still marked
  TODO and lists `ke` as a **proposed** entry, not a registered one. It is
  implemented because did:webs is named explicitly as a supported verification
  metadata format, but the code could change before the registry settles.

  Note the SCID's position differs by format: `did:webvh` puts it first,
  `did:webs` puts the AID **last**, because the AID is the final path element of
  the URL its artifacts are served from. Reusing the webvh formatting would
  produce a well-formed DID pointing at the wrong location, so the two are
  derived separately and a test pins both.

- `DIDSCIDError::UnknownFormat` and `DIDSCIDError::UnsupportedVersion`.

### Changed

- **Breaking:** the DID pattern now captures the format and version instead of
  hard-coding `vh:1`, so a well-formed `did:scid` naming an unresolvable format
  reports `UnknownFormat("...")` by name. It previously returned
  `UnsupportedFormat`, indistinguishable from a string that is not a `did:scid`
  at all.
- **Breaking:** `ScidMethod` gains a `Webs` variant and is now
  `#[non_exhaustive]`, since the registry is still open.
- A peer source for one format is no longer accepted for another. They place the
  SCID differently, so crossing them resolved to the wrong location.

## [0.1.13] - 2026-08-02

`ssi-dids-core` becomes an optional dependency, enabled by `did-cheqd` —
the only feature whose code actually uses it. No behavioural change; the
dependency was previously unconditional but only ever referenced under
that gate.

Moves this crate to the **elliptic-curve 0.14** family (`p256` / `k256` /
`p384` / `p521` 0.13 -> 0.14), which brings rand_core 0.10, digest 0.11 and
signature 3 with it.

API changes handled: the sec1 traits were renamed (`ToEncodedPoint` ->
`ToSec1Point`, `FromEncodedPoint` -> `FromSec1Point`), `EncodedPoint` became a
generic alias for `Sec1Point<C>` so it needs a per-module binding, and the
deprecated `SigningKey::random(rng)` is now `Generate::generate()` (system
CSPRNG, panics on failure).

Patch bump, per [ADR 0003](../../../../docs/adr/0003-public-api-semver-policy.md) point 3: `vta-sdk` and `didwebvh-rs` redirect
this crate through `[patch.crates-io]`, and a minor bump breaks the redirect.

Crypto behaviour is unchanged — the golden/KAT vectors (`p256_sign_verify_roundtrip`,
`secp256k1_es256k_golden` RFC 6979, `ecdh_1pu_x25519_kek_golden`,
`concat_kdf_es_golden`, `a256cbc_hs512_golden`) all still pass.

## Changelog history

## [0.1.12] - 2026-07-19

didwebvh-rs 0.6

- Bumped the `didwebvh-rs` requirement from `"0.5"` to `"0.6"`.

  0.6.0 requires `affinidi-did-common "0.4"`. Until now `didwebvh-rs 0.5.7`
  still required `"0.3"`, so the workspace carried **two** copies of
  `affinidi-did-common` (0.3.9 and 0.4.0); it compiled only because no types
  cross the `didwebvh-rs` boundary — `WebvhResolver` builds its own `Document`
  via `serde_json::from_value`. This collapses the graph back to a single
  `affinidi-did-common 0.4.0`.

  0.6.0 is a breaking release (`DIDWebVHError`, `URLType` and
  `LogEntryValidationStatus` became `#[non_exhaustive]`), but no code change was
  needed here: the only use is a `#[from] DIDWebVHError` conversion in
  `did-scid`'s error type, not an exhaustive `match`.

## [0.1.11] - 2026-07-19

affinidi-did-common 0.4

- Bumped the `affinidi-did-common` requirement from `"0.3"` to `"0.4"`.
  No functional change to this crate: `Document` gained a typed
  `also_known_as` field, which is additive.

## [0.1.10] - 2026-06-17

drop `did-cheqd` from default features (no forced `ring` TLS)

- **`did-cheqd` is no longer a default feature.** It pulled `did-resolver-cheqd`,
  whose `tonic 0.12` dependency hardcodes the rustls `ring` backend on
  `tokio-rustls`/`rustls 0.23`. That clashed with downstream binaries selecting
  `aws_lc_rs` (the ecosystem default via `kube`/`reqwest`/`jsonwebtoken`),
  compiling both backends and panicking with "no process-level CryptoProvider
  available" at the first TLS call. `default` is now `["did-webvh"]`.
- **Opt back in** with `features = ["did-cheqd"]` when you need `did:scid`
  anchored on `did:cheqd`; doing so re-enables the `ring` backend, so install a
  `CryptoProvider` in your binary's `main`.
- Patch bump keeps the `0.1` pin valid. No API or behaviour change beyond the
  default feature set.

## [0.1.9] - 2026-06-14

non_exhaustive DIDSCIDError (W7 sweep)

- `DIDSCIDError` is now `#[non_exhaustive]` (ADR-0003) so new variants land
  additively. Patch bump keeps the `0.1` pin valid; consumers that `match` it
  must add a `_` wildcard arm. No behaviour change.

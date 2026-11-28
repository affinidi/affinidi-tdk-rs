# Changelog — `affinidi-tdk`

## [0.51.0] - 2026-11-27

affinidi-messaging-sdk 0.52 (trust-tasks-rs 0.43)

**Breaking:** the `messaging` feature (on by default) re-exports
affinidi-messaging-sdk, which moves to 0.52 for trust-tasks-rs 0.43 and
trust-tasks-build 0.3.0 (optional array members of generated payload types are
now `Option<Vec<T>>`). Every other re-exported crate is unchanged. No source
change.

## [0.50.0] - 2026-11-24

affinidi-messaging-sdk 0.51 (trust-tasks-rs 0.41)

**Breaking:** the `messaging` feature (on by default) re-exports
affinidi-messaging-sdk, which moves to 0.51 for trust-tasks-rs 0.41. Every
other re-exported crate is unchanged. No source change.

## [0.49.0] - 2026-11-17

**Breaking (R3.6): moves to the new generation of its affinidi dependencies.** The re-exported crates (affinidi-crypto, did-scid, did-ebsi, the messaging SDK and others) appear in this crate's public API, so it moves a minor even where its own code is unchanged. Part of the coordinated breaking release of #1143 and #1166: affinidi-crypto 0.4, affinidi-encoding 0.2, affinidi-secrets-resolver 0.6, affinidi-did-common 0.5, affinidi-did-resolver-traits 0.2, affinidi-did-web 0.2, affinidi-did-resolver-cache-sdk 0.9 and affinidi-data-integrity 0.9 move together; a crate that mixes two generations does not compile.

## [0.48.1] - 2026-11-15

Workspace lint and dependency housekeeping. No API or behaviour change.

- Dependency versions now come from the root `[workspace.dependencies]`
  for the external crates shared by five or more workspace members
  (#1070). The published manifest still names concrete requirements; the
  resolved dependency graph and every feature selection are unchanged.
- Workspace lints now include `unsafe_code = "deny"` (#1064); this crate
  keeps its stricter `#![forbid(unsafe_code)]`.
- Minimum dependency requirements raised to versions already in use across the
  workspace (no new major/minor, Cargo.lock unchanged): `affinidi-crypto` 0.3
  -> 0.3.2, `affinidi-data-integrity` 0.8.7 -> 0.8.9,
  `affinidi-did-authentication` 0.3.16 -> 0.3.17, `affinidi-did-common` 0.4.7
  -> 0.4.8, `affinidi-did-resolver-cache-sdk` 0.8.53 -> 0.8.55,
  `affinidi-did-webs` 0.13.4 -> 0.13.6, `affinidi-messaging-didcomm` 0.15.14
  -> 0.15.15, `affinidi-oid4vc-core` 0.1.11 -> 0.1.12,
  `affinidi-secrets-resolver` 0.5.18 -> 0.5.19, `affinidi-tdk-common` 0.7 ->
  0.7.2, `did-ebsi` 0.1 -> 0.1.8, `did-scid` 0.4 -> 0.4.9.

## [0.48.0] - 2026-11-15

affinidi-status-list 0.2

- **Changed (breaking):** requires `affinidi-status-list` 0.2, which it
  re-exports as `status_list` (`status-list` feature). In 0.2 the issuer's
  index allocation moved to `StatusListAllocator` (persist it with the list),
  `add_decoys` returns a `Result`, `StatusPurpose` gained `Refresh`,
  `Message` and `Other(String)` and is `#[non_exhaustive]` (no longer `Copy`),
  and `encodedList` is emitted with the multibase `u` prefix — a wire change
  for status list credentials (older lists still decode). See the
  `affinidi-status-list` changelog.
- **Docs:** the `sd-jwt-vc` feature row names `affinidi-vc` (the
  `affinidi-sd-jwt-vc` crate is removed from the workspace; the feature
  already re-exported `affinidi_vc::sd_jwt_vc`).

## [0.47.0] - 2026-11-15

affinidi-messaging-sdk 0.49

- **Changed (breaking):** requires `affinidi-messaging-sdk` 0.49, which it
  re-exports. The SDK's inbound message channel is now a bounded `mpsc`,
  `live_stream_get` takes `Option<Duration>`, and send/receive behaviour
  changes (R3.6); see that crate's changelog. No source change.
  `affinidi-messaging-helpers` and `affinidi-messaging-text-client` require
  this version.

## [0.46.0] - 2026-11-15

affinidi-messaging-sdk 0.48 and affinidi-tsp 0.4

- **Changed (breaking):** requires `affinidi-messaging-sdk` 0.48 and
  `affinidi-tsp` 0.4, whose types it re-exports. A TSP `ReceivedMessage` has a
  new `confidential` field and `TspError::Cesr` is gone; see those crates'
  changelogs. `affinidi-messaging-helpers` and `affinidi-messaging-text-client`
  require this version.


## [0.45.0] - 2026-11-14

affinidi-messaging-sdk 0.47 and trust-tasks 0.39

- **Changed (breaking):** requires `affinidi-messaging-sdk` 0.47
  (`trust-tasks-rs` / `trust-tasks-proof` 0.39), whose types it re-exports.
- 0.44.0 (affinidi-crypto 0.3, below) was never published; it ships in this release.
  `affinidi-messaging-helpers` and `affinidi-messaging-text-client` require this version.

## [0.44.0] - 2026-11-13

affinidi-crypto 0.3

- **Changed (breaking):** `affinidi_tdk::affinidi_crypto` re-exports
  `affinidi-crypto` 0.3. Its key pairs wipe themselves when dropped, so their
  fields can no longer be moved out (use `into_parts()`), and its derived
  secrets come back in `Zeroizing` buffers. See the `affinidi-crypto`
  CHANGELOG for the migration. `affinidi-messaging-helpers` and
  `affinidi-messaging-text-client` require this version.

## [0.43.0] - 2026-11-13

affinidi-messaging-sdk 0.46

- **Changed (breaking):** the `messaging` feature re-exports
  `affinidi-messaging-sdk` 0.46 (`trust-tasks-rs` 0.38). See its CHANGELOG.
  `affinidi-messaging-helpers` and `affinidi-messaging-text-client` require
  this version.

## [0.42.0] - 2026-11-13

affinidi-mdoc 0.6

- **Changed:** the `mdoc` feature moves to `affinidi-mdoc` 0.6: proximity
  session keys are derived as ISO/IEC 18013-5 specifies (different keys from
  0.5), and `MdocBuilder::build` requires a device key and a validity window.
  See that crate's CHANGELOG.

## [0.41.0] - 2026-11-12

affinidi-sd-jwt 0.2, affinidi-vc 0.3

- **Changed:** the `sd-jwt` feature moves to `affinidi-sd-jwt` 0.2: key binding
  is checked under the credential's `cnf.jwk`, and `aud`, `nonce` and `iat`
  are required when it is requested. `verify` drops its `holder_verifier`
  argument. The `vc` and `sd-jwt-vc` features move to `affinidi-vc` 0.3. See
  those crates' CHANGELOGs.

## [0.40.0] - 2026-11-12

affinidi-siopv2 0.2

- **Changed:** the `siopv2` feature moves to `affinidi-siopv2` 0.2: ID Tokens
  are signed with `SelfIssuedIdToken::sign` and checked with
  `verify_id_token`; the claims-only check is renamed `validate_claims`. See
  that crate's CHANGELOG.

## [0.39.0] - 2026-11-12

affinidi-trust-lists 0.2

- **Changed:** the `trust` feature moves to `affinidi-trust-lists` 0.2: chain
  validation verifies certificate signatures, and parsed XML lists must be
  released with `assume_authenticated()` and are refused when stale. See that
  crate's CHANGELOG for the API changes.
## [0.38.0] - 2026-11-12

affinidi-mdoc 0.5

- **Changed:** the `mdoc` feature moves to `affinidi-mdoc` 0.5: item digests
  are checked over the bytes as received, `DeviceResponse::verify` runs the
  full reader check set, and COSE `alg` headers are checked. Stricter
  verification is a behaviour change for callers of the re-exported crate.

## [0.37.6] - 2026-11-11

affinidi-did-webs 0.13

- **Changed:** the `did-webs` feature moves to `affinidi-did-webs` 0.13, on
  affinidi-keri 0.8: native CESR bodies resolve, keripy's delegated rotations
  verify, and the `EO` and `DND` configuration traits are enforced.

## [0.37.5] - 2026-11-11

affinidi-did-webs 0.12

- **Changed:** the `did-webs` feature moves to `affinidi-did-webs` 0.12, on
  affinidi-keri 0.7: rotations verify as keripy verifies them, and a recovery
  rotation supersedes interaction events and what they anchored.

## [0.37.4] - 2026-11-10

affinidi-did-webs 0.11

- **Changed:** the `did-webs` feature moves to `affinidi-did-webs` 0.11: did:webs
  on KERI 2.0 (alpha). Designations are read for both ACDC versions, a stream
  that leaves out an anchored registry event fails resolution, and a critical
  designation the resolver does not implement fails with
  `unsupportedDesignation`.

## [0.37.3] - 2026-11-10

affinidi-did-webs 0.10

- **Changed:** the `did-webs` feature moves to `affinidi-did-webs` 0.10, on
  affinidi-keri 0.6: rotations now verify in keripy, and thresholds of 10 or
  more are read as hex.

## [0.37.2] - 2026-11-09

affinidi-did-webs 0.9

- **Changed:** the `did-webs` feature moves to `affinidi-did-webs` 0.9, which
  no longer turns on `serde_json`'s `preserve_order` for the whole build.

## [0.37.1] - 2026-11-08

affinidi-did-webs 0.8

- **Changed:** the `did-webs` feature moves to `affinidi-did-webs` 0.8, which
  resolves as the did:webs specification requires: a DID resolves only when its
  AID designates it, signatures are held to the signing threshold, replies are
  ordered by BADA, and the published `did.json` is compared as a whole.

## [0.37.0] - 2026-11-04

SDK 0.45

The facade re-exports `affinidi-messaging-sdk`, which moves to 0.45 (`trust-tasks-rs` 0.37). So this crate moves a minor. No source change.

## [0.36.0] - 2026-10-28

SDK 0.44

The facade re-exports `affinidi-messaging-sdk`, which moves to 0.44: `trust-tasks-rs` 0.36, and `decode_monitor_event` returns the `messaging/monitor/event` 0.2 type. So this crate moves a minor. No source change.

## [0.35.0] - 2026-10-27

SDK 0.43

The facade re-exports `affinidi-messaging-sdk`, which moves to 0.43: seven messaging tasks are spoken at 0.2 and their methods return the 0.2 types. So this crate moves a minor. No source change.

## [0.34.0] - 2026-10-27

SDK 0.42

The facade re-exports `affinidi-messaging-sdk`, which moves to 0.42: its Trust Task types are generated at build time and live at `affinidi_messaging_sdk::tasks`. So this crate moves a minor. No source change.

## [0.33.0] - 2026-10-27

SDK 0.41

The facade re-exports `affinidi-messaging-sdk`, which moves to 0.41 for `trust-tasks-rs` 0.35. So this crate moves a minor. No source change.

## [0.32.0] - 2026-10-24

SDK 0.40

The facade re-exports `affinidi-messaging-sdk`, which moves to 0.40 for `trust-tasks-rs` 0.34. So this crate moves a minor. No source change.

## [0.31.0] - 2026-10-22

TSP 1.0, SDK 0.39

The facade re-exports `affinidi-tsp` (feature `tsp`), which moves to 0.3 and
TSP 1.0 (`YTSP-BAA`) — not wire-compatible with the 0.2.x (Rev 3) it
re-exported before — and `affinidi-messaging-sdk`, which moves to 0.39 with it.
So this crate moves a minor. No source change.

## [0.30.0] - 2026-10-21

did-scid 0.4

Moves the re-exported `did_scid` (feature `did-scid`) to 0.4, whose `resolve`
returns a did:scid's own document (bare `did:scid:vh:1:<scid>` as `id`, keys
under it) rather than the did:webvh document that verifies it. The re-export
makes that a breaking change here.

## [0.29.0] - 2026-10-21

mdoc 0.4

The facade re-exports `affinidi-mdoc` (feature `mdoc`), which moves to 0.4
(OpenID4VP 1.0 Final handovers, breaking), so this crate moves a minor with it.
No source change.

## [0.28.0] - 2026-10-21

SDK 0.38

The facade re-exports `affinidi-messaging-sdk`, which moves to 0.38 (`trust-tasks-rs` 0.33), so this crate moves a minor with it. No source change.

## [0.27.0] - 2026-10-18

SDK 0.37

The facade re-exports `affinidi-messaging-sdk`, which moves to 0.37 (`trust-tasks-rs` 0.32), so this crate moves a minor with it. No source change.

## [0.26.0] - 2026-10-13

SDK 0.36

The facade re-exports `affinidi-messaging-sdk`, which moves to 0.36 (`trust-tasks-rs` 0.31), so this crate moves a minor with it. No source change.

## [0.25.0] - 2026-10-11

SDK 0.35

The facade re-exports `affinidi-messaging-sdk`, which moves to 0.35 (`trust-tasks-rs` 0.30), so this crate moves a minor with it. No source change.

## [0.24.0] - 2026-10-11

SDK 0.34

The facade re-exports `affinidi-messaging-sdk`, which moves to 0.34 (`trust-tasks-rs` 0.28), so this crate moves a minor with it. No source change.

## [0.23.0] - 2026-10-03

SDK 0.33

The facade re-exports `affinidi-messaging-sdk`, which moves to 0.33 (`trust-tasks-rs` 0.27), so this crate moves a minor with it. No source change.

## [0.22.0] - 2026-10-01

`affinidi-data-integrity` 0.8, SDK 0.32, did-scid 0.3

The facade re-exports `affinidi-data-integrity` 0.8 (the correctly versioned re-release of 0.7.14, on `affinidi-bbs` 0.4), `affinidi-tdk-common` 0.7, `affinidi-messaging-sdk` 0.32, `affinidi-meeting-place` 0.5 and `did-scid` 0.3 (`didwebvh-rs` 0.8). All of them move a minor, so this crate moves a minor with them. `did-scid` is taken by workspace path again: 0.21.1's registry pin is undone. No source change.

## [0.21.1] - 2026-10-01

`did-scid` from crates.io, pending 0.22

No API or behaviour change. The workspace's `did-scid` moved to 0.3
(`didwebvh-rs` 0.8), and because this crate re-exports `did_scid`, following it
would be breaking. This release keeps the optional `did-scid` dependency on
0.2.8, now taken from crates.io instead of the workspace path. 0.22.0 moves to
did-scid 0.3 together with `affinidi-data-integrity` 0.8 and SDK 0.32, so
there is one breaking tdk release, not two.

## [0.21.0] - 2026-09-30

SDK 0.31

The facade re-exports the messaging SDK, which moves a minor for trust-tasks-rs 0.25, so this crate moves a minor with it. No source change.

## [0.20.0] - 2026-09-27

SDK 0.30

The facade re-exports the messaging SDK, which moves a minor for trust-tasks-rs 0.24, so this crate moves a minor with it. No source change.

## [0.19.0] - 2026-09-27

SDK 0.29

The facade re-exports the messaging SDK, which removes the legacy mediator admin senders in 0.29, so this crate moves a minor with it. No source change.

## [0.18.0] - 2026-09-26

trust-tasks-rs 0.23

Carries the messaging crates' move to trust-tasks-rs 0.23: a pin on a bumped 0.x crate does not admit its new line, so this crate moves a minor with it.

## [0.17.0] - 2026-09-23

`trust-tasks-rs` 0.21

The facade re-exports the messaging family, so it moves with it. A re-export
makes the re-exported crate's version part of this crate's public API — which
is precisely why this is a minor and not a patch.

**trust-tasks-rs 0.22.** Carried through from the messaging crates, which move
a minor for it — `trust_tasks_rs` types cross their API, so a consumer has to
move in step rather than resolve two versions. No code change here; the pins
follow.

## [0.15.0] - 2026-09-15

TSP Rev 3

Breaking: the facade now re-exports `affinidi-tsp` 0.2, which speaks Trust
Spanning Protocol Rev 3 and **cannot interoperate with a Rev 2 peer in either
direction**. There is no compatibility mode to opt out of. Consumers enabling
the `tsp` feature move with it, and the whole deployment moves together — a
mixed fleet does not degrade, it goes silent.

See `affinidi-tsp`'s changelog for the wire changes and `docs/tsp/` for the
migration status.

## [0.14.0] - 2026-09-10

`trust-tasks-rs` 0.20

- Bumps `trust-tasks-rs` 0.19 → 0.20. **No source change** — only manifests.
  0.20 is additive for everything this crate uses: its one breaking change is a
  `process-attestation` schema tightening (digest floor 16 → 43 base64url
  characters, a category correction, a dropped duplicate member), and no crate
  in this workspace references that spec.
- **Moves because it is the path, not because its own code changed.** This crate
  re-exports `affinidi-messaging-sdk`, so a consumer reaching a generated type
  through the facade sees the same API change. Leaving it unbumped would publish
  a move that never arrives — and the version guard cannot see it, because only
  its manifest changed.

All notable changes to this crate are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this crate
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

For the full code history see `git log` on `crates/tdk/affinidi-tdk`.

## [0.12.0] - 2026-09-06

- Re-exports `affinidi-messaging-sdk` 0.22.0, whose move to `trust-tasks-rs`
  0.18 is breaking for consumers: the SDK's public API carries generated types
  (`TrustTasks::account_update` takes an `account::update::v0_1::MediatorAcl`),
  so two `trust-tasks-rs` versions in one graph fail to compile rather than
  warn. A consumer must move to 0.18 in the same change.

## [0.11.0] - 2026-09-01

### Changed

- `mdoc` feature now re-exports `affinidi-mdoc` 0.3, which moves to `coset` 0.4.
- **Breaking for consumers of the `mdoc` feature.** `coset` sits in
  `affinidi-mdoc`'s public API (`IssuerSigned::issuer_auth` is a
  `coset::CoseSign1`), so a consumer that names those types moves in the same
  change; two `coset` versions in one graph fail to compile rather than warn.
  Minor rather than patch for that reason.
- No source change in this crate. Bumped because the published manifest's
  requirement is itself what changed: a consumer resolving `affinidi-tdk` 0.10.0
  from crates.io stays pinned to `affinidi-mdoc` 0.2 and can never reach 0.3.

## [0.10.0] - 2026-08-27

### Changed

- `messaging` feature now re-exports `affinidi-messaging-sdk` 0.21, which moves
  to `trust-tasks-rs` 0.17.
- **Breaking for consumers of the `messaging` feature.** 0.17 marks the
  generated payload, response and component types `#[non_exhaustive]`, so a
  consumer that builds one with a struct literal — with or without
  `..Default::default()` — must move to the generated builder. As before, a
  consumer must move to 0.17 in the same change; two `trust-tasks-rs` versions
  in one graph fail to compile rather than warn. Minor rather than patch for
  that reason.
- No source change in this crate. Bumped because the published manifest's
  requirement is itself what changed: a consumer resolving `affinidi-tdk` 0.9.0
  from crates.io stays pinned to the SDK's 0.20 line and can never reach 0.17.

## [0.9.0] - 2026-08-26

### Changed

- `messaging` feature now re-exports `affinidi-messaging-sdk` 0.20, which moves
  to `trust-tasks-rs` 0.12.
- **Breaking for consumers of the `messaging` feature.** The re-exported SDK
  carries `trust-tasks-rs` types in its public API, so a consumer must move to
  0.12 in the same change; two versions in one graph fail to compile rather
  than warn. Minor rather than patch for that reason.
- The dependency is now declared with a `path` alongside its version. It was a
  bare registry requirement, so this facade re-exported the *published* SDK
  rather than the one beside it in this workspace — which is how a stale
  `trust-tasks-rs` node survived the 0.12 move.

## [0.8.14] - 2026-08-23

### Changed

- `did-webs` feature now re-exports `affinidi-did-webs` 0.7.

## [0.8.13] - 2026-08-23

### Changed

- `did-webs` feature now re-exports `affinidi-did-webs` 0.6.

## [0.8.12] - 2026-08-23

### Changed

- `did-scid` feature now re-exports `did-scid` 0.2.3.

## [0.8.11] - 2026-08-23

### Changed

- `did-webs` feature now re-exports `affinidi-did-webs` 0.5.

## [0.8.10] - 2026-08-23

### Changed

- `did-webs` feature now re-exports `affinidi-did-webs` 0.4.
- `did-scid` feature now re-exports `did-scid` 0.2.

## [0.8.7] - 2026-08-23

### Changed

- `did-webs` feature now re-exports `affinidi-did-webs` 0.2.
## [0.8.8] - 2026-08-23

### Changed

- `did-webs` feature now re-exports `affinidi-did-webs` 0.3.

## [0.8.6] - 2026-08-23

### Added

- `did-webs` feature, re-exporting `affinidi-did-webs` as `did_webs` and joining
  the `did-methods` group.

## [0.8.5] - 2026-08-05

> **BREAKING CHANGE (inherited), shipped as a patch — read this before
> upgrading.** This crate re-exports the messaging SDK
> wholesale — `pub use affinidi_messaging_sdk as messaging;`, under the
> default-on `messaging` feature — so `affinidi-messaging-sdk` 0.19.0's breaking
> changes reach every consumer of this facade:
>
> - **Behavioural:** `messaging::ATM::unpack` (and the message-pickup delivery
>   drain) now reject non-authenticated envelopes by default — only
>   `authcrypt(plaintext)`, `authcrypt(sign(plaintext))` and
>   `anoncrypt(authcrypt(plaintext))` are accepted, with message-layer addressing
>   consistency enforced. Code that previously received anoncrypt, plaintext or
>   signed-only messages will start seeing `ATMError::UnexpectedEnvelope` /
>   `AddressingMismatch`.
> - **Compile:** `messaging::messages::compat::UnpackMetadata` gains two public
>   fields and is now `#[non_exhaustive]`, so downstream struct-literal
>   construction of it stops compiling.
>
> **Why this is a patch and not `0.9.0`.** On the merits it should be a minor
> bump: a `^0.8` consumer picks this up on a routine `cargo update` and inherits
> both breaks with no opportunity to opt in. It ships as a patch anyway, under
> ADR 0003 point 3, because `vta-sdk` — an external crates.io crate this
> workspace itself depends on (via the mediator and `mediator-setup`) — pins
> `affinidi-tdk = "0.8"`. Our root `[patch.crates-io]` redirect only applies
> while the local version satisfies that pin, so `0.9.0` breaks the redirect and
> cargo resolves a *second*, registry copy of `affinidi-tdk` (and transitively of
> `affinidi-messaging-sdk`) into the graph — the duplicate-type failure the
> workspace-duplicates guard catches. This was tried and rejected on exactly
> that evidence, not assumed.
>
> A true `0.9.0` therefore requires **first** releasing a `vta-sdk` that depends
> on `affinidi-tdk` `0.9`, then bumping here — the coordination ADR 0003 point 3
> calls for. Until then the version number cannot carry the warning, so this note
> has to: **treat this patch as a breaking upgrade.**
>
> (`affinidi-messaging-sdk` is not caught by the same constraint even though
> `vta-sdk` also pins it at `"0.18"` — that dependency is optional and is not
> activated in this workspace's feature graph, whereas the `affinidi-tdk` one is.
> Hence the SDK can take its honest `0.19.0` minor while the facade cannot.)
>
> **Migration:** pin `affinidi-tdk = "=0.8.4"` if you are not ready, and see the
> `affinidi-messaging-sdk` 0.19.0 changelog for how to restore the previous
> acceptance behaviour via `ATMConfigBuilder::with_unpack_policy(..)` if a
> protocol legitimately expects an unauthenticated wrapping.

### Changed

- Track `affinidi-messaging-sdk` 0.19.0 (secure-by-default `unpack`). No source
  change in this crate, but the re-export makes the SDK's breaking changes
  observable through `affinidi_tdk::messaging` — see above.

## [0.8.4] - 2026-07-19

### Changed

- Bumped the `affinidi-did-common` requirement from `"0.3"` to `"0.4"`.
  No functional change to this crate: `Document` gained a typed
  `also_known_as` field, which is additive.

## [0.8.1] - 2026-06-13

### Added

- Re-export the DID resolver cache SDK as `affinidi_tdk::did_resolver` so the
  resolver is reachable through the facade (it was the only core dep not
  re-exported).
- Facade-first examples (W13): `examples/did_auth.rs` rewritten to import only
  through `affinidi_tdk::*`; new `examples/resolve_did.rs`. A CI step
  (`cargo build -p affinidi-tdk --examples`) keeps them compiling.

## [0.8.0] - 2026-06-13

### Added

- **Facade feature completion (W12).** Every published capability crate is now
  reachable through a facade feature and re-exported under a module:
  - `credentials` group → `vc`, `sd-jwt`, `sd-jwt-vc`, `mdoc`, `status-list`
    (+ `data-integrity`).
  - `protocols` group → `oid4vc-core`, `siopv2`, `openid4vci`, `openid4vp`.
  - `did-methods` group → `did-web`, `did-ebsi`, `did-scid`.
  - `trust` (`affinidi-trust-lists`), `tsp` (`affinidi-tsp`).
  - All optional and `dep:`-gated; individual + group features both available.
- Facade feature-matrix CI job (`checks-features.yaml`) building default,
  no-default, each group, and all-features.

### Changed

- Foundation deps (`affinidi-crypto`, `affinidi-tdk-common`) kept at
  `major.minor` (caret), **not** exact-pinned: these crates ship frequent patch
  releases (see ADR 0003), so an exact pin would break the facade on every
  patch. Use the facade **or** direct sub-crate deps, not both.
- `did-peer` documented as a code-gate feature (no extra dependency; gates the
  did:peer helpers in `dids`).

## [0.7.4] - 2026-06-06

### Changed

- Bump `affinidi-crypto` to `0.2` (P-384/P-521 key agreement +
  `#[non_exhaustive]` key-agreement enums, #357). No API change in this
  crate.

## [0.7.3] - 2026-06-01

### Changed

- Release on `affinidi-messaging-didcomm` 0.15 (#327). This crate
  re-exports didcomm as `affinidi_tdk::didcomm`, so consumers now get the
  0.15 envelope crate (crypto centralized in `affinidi-crypto`; the
  `crypto` submodule was removed — its key-agreement types now live at
  `affinidi_crypto::jose::key_agreement`). Wire behaviour is unchanged.
  This release is what unblocks downstream crates (e.g. `vta-sdk`) from
  pulling two incompatible didcomm `Message` types.

## [0.7.2] - 2026-05-31

### Changed

- Bump `affinidi-messaging-didcomm` to 0.14 (DIDComm v2.1 interop fixes:
  ECDH-1PU authcrypt KDF #322, JWS unprotected `kid` #323,
  sign-then-encrypt unpack #324). No `affinidi-tdk` API change.

## [0.7.1] - 2026-05-02

### Deprecated

- `TDK::delete_did_secret`, `TDK::save_secrets_locally`, and
  `TDK::load_secrets` — one-shot wrappers that build a fresh
  `KeyringStore` per call. They were retained from the pre-0.6 API for
  source compatibility; the canonical replacement is to construct a
  `KeyringStore` once at the call site and reuse it (cheaper for
  repeated ops, explicit lifetime). Marked `#[deprecated]` in 0.7.1
  with a removal target of **0.8**.

## [0.7.0] - 2026-05-02

### Breaking

- Upgraded to `affinidi-tdk-common` 0.6 and `affinidi-meeting-place` 0.4.
  Both upstream bumps are SemVer-breaking, so consumers must adopt the
  accessor-method API on `TDKSharedState` / `TDKEnvironment` /
  `TDKProfile` (see the
  [`affinidi-tdk-common` 0.6.0 changelog](../affinidi-tdk-common/CHANGELOG.md#060--2026-05-02)
  for the full migration).
- `secrets::*` methods (`delete_did_secret`, `save_secrets_locally`,
  `load_secrets`) now take `&self` rather than consuming `self`. The
  `self`-by-value receiver was a holdover that prevented chained use.
- `secrets::*` is rewired onto the new
  [`KeyringStore`](https://docs.rs/affinidi-tdk-common/0.6.0/affinidi_tdk_common/secrets/struct.KeyringStore.html)
  rather than the removed free functions in tdk-common 0.5.

### Changed

- `TDK::new` now delegates to `TDKSharedState::new` (which loads the
  on-disk environment, builds the HTTPS client with extra TLS roots from
  `TDKEnvironment::ssl_certificate_paths`, and spawns the
  `AuthenticationCache`) instead of duplicating that logic. Profile
  secrets are loaded into the shared resolver via the public
  `add_profile` API.
- `verify_data` is rewritten with `?`-driven control flow; behaviour is
  identical.

### Added

- `TDK::shared(&self) -> &TDKSharedState` — borrow the shared state
  without bumping the `Arc` refcount. `get_shared_state()` is unchanged.
- `#![forbid(unsafe_code)]` at the crate root — security signal,
  zero-cost.
- This `CHANGELOG.md`.

### Documentation

- Crate-level rustdoc rewritten to describe the new
  `TDK::new` → `TDKSharedState::new` delegation flow.
- Example `did_auth.rs` updated for the new
  `create_http_client(&[])` signature, the
  `TDKEnvironment::profiles()` accessor, and `TDKProfile::take_secrets()`
  to drain plaintext into the resolver.

### Tests

- Three near-duplicate `verify_data` tests deduplicated via a
  `proof_with_vm` helper; behaviour unchanged.

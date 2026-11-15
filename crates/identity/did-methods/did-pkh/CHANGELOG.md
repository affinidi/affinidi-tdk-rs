# Changelog

## [0.1.5] - 2026-11-15

`resolve_did` reads `DIDMethod::Pkh`'s parsed fields; optional resolver-trait
impl

### Added

- `resolve_did(&DID)` (#1153): resolve a parsed `did:pkh` DID (or DID URL)
  from the CAIP-10 namespace, reference and address its `DIDMethod::Pkh`
  already holds, without splitting the identifier again. The result (and any
  error) is the same as `resolve` on the DID string. A deprecated
  single-token prefix (`did:pkh:eth:0x…`) has two labels, so it never parses
  as a `DID`; `resolve` and `resolve_identifier` still accept it.
- Feature `resolver-traits` (off by default): `PkhResolver`, an
  `affinidi_did_resolver_traits::Resolver` (and so `AsyncResolver`) that
  resolves did:pkh and declines every other method. A failure is
  `ResolverError::ResolutionFailed`.

## [0.1.4] - 2026-11-15

Workspace lint and dependency housekeeping. No API or behaviour change.

- Dependency versions now come from the root `[workspace.dependencies]`
  for the external crates shared by five or more workspace members
  (#1070). The published manifest still names concrete requirements; the
  resolved dependency graph and every feature selection are unchanged.
- Workspace lints now include `unsafe_code = "deny"` (#1064).
- Minimum dependency requirements raised to versions already in use across the
  workspace (no new major/minor, Cargo.lock unchanged): `affinidi-did-common`
  0.4 -> 0.4.8.

## [0.1.3] - 2026-11-13

account ids checked the same way on every path

- The address after a deprecated prefix (`btc`, `doge`, `eth`, `celo`,
  `poly`, `sol`, `tz`) is now held to the CAIP-10 address grammar, as a
  CAIP-10 account id already was. `did:pkh:btc:1…:more` and addresses with
  characters outside `[-.%a-zA-Z0-9]` are refused with `InvalidIdentifier`.
- Bitcoin and Dogecoin mainnet addresses are verified as base58check P2PKH
  addresses (25 bytes, version byte `0x00` / `0x1e`, valid checksum), as
  Tezos addresses already were. Other `bip122` chains are unchanged.
- The `eip155` chain reference must be a decimal chain id without leading
  zeros (`1`, `137`); `abc` or `01` are refused with `InvalidIdentifier`.
- A mixed-case `eip155` address (CAIP-10 or `eth`/`celo`/`poly`) must match
  its EIP-55 checksum. All-lowercase and all-uppercase addresses carry no
  checksum and are accepted as before.
- Adds `sha3` 0.12 (already in the workspace through `affinidi-did-ethr`)
  for the EIP-55 Keccak-256 hash.

Behaviour change (R3.6): malformed identifiers that used to resolve are now
refused. Every valid identifier resolves to the same document as before; the
upstream conformance fixtures are unchanged. No public API change.

## [0.1.2] - 2026-09-15

`sha2` 0.11, `bech32` 0.12

No behaviour change. `sha2` moves this crate onto the line
`affinidi-crypto`, `affinidi-secrets-resolver` and `affinidi-tsp` already use,
so the workspace has one fewer crate left on 0.10. `Sha256::digest` is
unchanged across the bump.

The 0.10 copy does not leave the graph yet: `bls12_381_plus` — including its
latest 0.9.0 — still requires `sha2 ^0.10` and `rand_core ^0.6.4`, so
`affinidi-bbs` cannot move until that clears upstream.

## [0.1.1] - 2026-08-23

dependency refresh

- Bumps `base64` 0.22 → 0.23.
- No source or API change; the bumps are declaration-only and the crate
  compiles unmodified against them. Bumped workspace-wide in the same
  change so no two versions of these crates are compiled side by side.

## [0.1.0] - 2026-08-22

initial release

In-tree replacement for the spruceid `did-pkh` crate, written to drop the
`ssi-*` dependency stack (`im`, `sized-chunks`, `bitmaps`, `smallstr`,
`proc-macro-error`, `derivative` — all unmaintained and archived with no fixed
release — plus `reqwest 0.11` and the vulnerable `h2 0.3.x`).

See `README.md` for scope, conformance and behavioural differences.

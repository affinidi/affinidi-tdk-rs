# Changelog

## Unreleased (0.1.2) — `sha3` 0.12

No behaviour change and no public API change: these are private dependencies
here, which is what lets each crate move on its own schedule. Verified by
`cargo tree`/grep that no RustCrypto type appears in a public signature anywhere
in the workspace.

Version bump only; no source change. 11 tests green.

## Unreleased (0.1.1) — dependency refresh

- Bumps `base64` 0.22 → 0.23.
- No source or API change; the bumps are declaration-only and the crate
  compiles unmodified against them. Bumped workspace-wide in the same
  change so no two versions of these crates are compiled side by side.

## 0.1.0 — initial release

In-tree replacement for the spruceid `did-ethr` crate, written to drop the
`ssi-*` dependency stack (`im`, `sized-chunks`, `bitmaps`, `smallstr`,
`proc-macro-error`, `derivative` — all unmaintained and archived with no fixed
release — plus `reqwest 0.11` and the vulnerable `h2 0.3.x`).

See `README.md` for scope, conformance and behavioural differences.

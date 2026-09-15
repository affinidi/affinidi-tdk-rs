# Changelog

## Unreleased (0.1.2) — `sha2` 0.11, `bech32` 0.12

No behaviour change. `sha2` moves this crate onto the line
`affinidi-crypto`, `affinidi-secrets-resolver` and `affinidi-tsp` already use,
so the workspace has one fewer crate left on 0.10. `Sha256::digest` is
unchanged across the bump.

The 0.10 copy does not leave the graph yet: `bls12_381_plus` — including its
latest 0.9.0 — still requires `sha2 ^0.10` and `rand_core ^0.6.4`, so
`affinidi-bbs` cannot move until that clears upstream.

## Unreleased (0.1.1) — dependency refresh

- Bumps `base64` 0.22 → 0.23.
- No source or API change; the bumps are declaration-only and the crate
  compiles unmodified against them. Bumped workspace-wide in the same
  change so no two versions of these crates are compiled side by side.

## 0.1.0 — initial release

In-tree replacement for the spruceid `did-pkh` crate, written to drop the
`ssi-*` dependency stack (`im`, `sized-chunks`, `bitmaps`, `smallstr`,
`proc-macro-error`, `derivative` — all unmaintained and archived with no fixed
release — plus `reqwest 0.11` and the vulnerable `h2 0.3.x`).

See `README.md` for scope, conformance and behavioural differences.

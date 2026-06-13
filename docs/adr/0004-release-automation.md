# ADR 0004 — Release automation: keep pipeline-rust, add local guards

- **Status:** Accepted (interim — see "Open: release-plz adoption")
- **Date:** 2026-06-13
- **Relates to:** Task W17; the 2026-06-13 publish-pipeline break (PR #456); the
  semver wave (W7–W11, [ADR 0003](0003-public-api-semver-policy.md)); the
  `didwebvh-rs` / `vta-sdk` `[patch.crates-io]` coupling.

## Context

Releases are driven by the org-owned shared workflow
`affinidi/pipeline-rust/.github/workflows/release.yaml@main`, triggered on push
to `main`. It compares each publishable crate's local version against crates.io
and publishes those that moved. The workspace currently sets
`workspace_publish: false` so the pipeline uses the legacy per-crate path that
**skips already-published crates** — `cargo publish --workspace` instead errors
on the first crate already at its current version, which blocks targeted patch
releases (the common case here: a security fix touches four of ~39 crates).

Two recurring pain points motivated W17:

1. **Manual version bumping across ~39 crates.** Every release hand-edits
   versions and CHANGELOGs across many manifests in dependency order. Tedious
   and error-prone.

2. **The 2026-06-13 break (PR #456).** W9 (#448) edited
   `affinidi-meeting-place`'s source to add a wildcard arm for the newly
   `#[non_exhaustive]` `Endpoint`, but left its version at 0.4.2. crates.io kept
   the *pre-seal* 0.4.2 source. When `affinidi-did-common 0.3.6` later published,
   the pipeline's `cargo publish` verify build — which resolves dependencies
   from the **registry**, ignoring our `[patch.crates-io]` redirects — compiled
   the stale 0.4.2 source against the new did-common and hit `error[E0004]:
   non-exhaustive patterns`, failing the whole release. The local workspace
   build (which *does* apply `[patch.crates-io]`) was green throughout, so
   nothing caught it before merge.

   **Root cause:** a published crate's source changed without a version bump, so
   the registry kept incompatible source at a version we still treated as
   current. The `[patch]` workspace build masks this class of bug entirely.

A third, smaller trap: the pinned Rust toolchain (`1.95.0`) is duplicated across
`rust-toolchain.toml`, `Cargo.toml`'s MSRV, and every `toolchain:` pin in the
workflow files (11 references, 6 files). Bumping it means editing all of them;
miss one and CI builds on a different compiler than local dev.

## Decision

### 1. Keep the pipeline-rust release workflow; do **not** swap to release-plz now.

Adopting `release-plz` (or `cargo-workspaces`) to automate version bumps and the
release PR is attractive, but the release workflow is **org-owned**
(`affinidi/pipeline-rust`). Swapping it is an org-level decision that must be
coordinated with whoever owns that pipeline — it cannot be made unilaterally in
this repo. We therefore keep `workspace_publish: false` + the skip-published
per-crate path for now, and treat release-plz adoption as a separate, sequenced
effort (below).

### 2. Add two build-free local PR guards (`.github/workflows/release-guards.yaml`).

These run on every PR, outside the shared pipeline, and protect the release path
without depending on the org pipeline:

- **`scripts/check-version-bumps.sh`** — for every *publishable* crate whose
  **source** changed in the PR (vs. the base), require its `Cargo.toml` version
  to differ from the base. This directly catches the 2026-06-13 trap: an
  edited-but-unbumped published crate now fails the PR. "Source" excludes
  `tests/`, `benches/`, `examples/`, `*.md`, and `CHANGELOG*` (test-/doc-only
  changes get no bump, per repo convention); `publish = false` crates are
  skipped (they never reach crates.io).

  Forcing a bump alongside any source edit means `main` never accumulates an
  unpublished source delta against a stale registry version — the pipeline then
  publishes the new source at a fresh version, and crates.io never goes
  incompatible.

- **`scripts/check-toolchain-sync.sh`** — assert every workflow `toolchain:` pin
  equals `rust-toolchain.toml`'s channel, and the workspace MSRV is `<=` it. A
  toolchain bump that misses a file now fails CI with the exact file:line.

Both scripts are pure bash + git + `jq` + `cargo metadata` (no Rust build),
portable to macOS bash 3.2, and runnable locally. The guards workflow carries no
`toolchain:` pin of its own (toolchain comes from `rust-toolchain.toml`), so it
adds nothing for the sync check to police.

## Consequences

- The PR that breaks the release the way #456 did is now caught **at PR time**,
  not after merge when the pipeline fails. The fix is mechanical: bump the
  crate's version (and CHANGELOG).
- Toolchain bumps become a one-line edit to `rust-toolchain.toml` plus whatever
  the sync check flags — no more silent per-file drift.
- These guards are complementary to, not a replacement for, the org pipeline.
  They reduce the pipeline's failure surface but do not change how it publishes.

## Open: release-plz adoption (deferred, org-level)

Parts (a) and (b) of W17 — automated version bumps / release PRs via release-plz,
and a single `unreleased.md` that tooling splits into per-crate CHANGELOGs — are
**deferred pending an org-level decision** on the pipeline-rust integration. When
revisited, the key constraints to honour:

- **Skip-already-published behaviour is mandatory** for targeted patch releases
  (the `workspace_publish: false` rationale). release-plz's per-crate publish
  satisfies this; `cargo publish --workspace` does not.
- **The `[patch.crates-io]` external coupling** ([ADR 0003](0003-public-api-semver-policy.md))
  constrains *which* bumps are legal: foundational crates pinned by external
  `didwebvh-rs` / `vta-sdk` must stay patch-level within their current minor
  until those external consumers are re-released. Any automation must respect
  that (e.g. release-plz `[[package]]` overrides), or it will propose
  minor/major bumps that break the redirect.
- **A dry run on a fork first** (per the W17 risk register) before touching the
  shared release path.

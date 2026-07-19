# Runbook — publishing `affinidi-did-common 0.4.0`

Covers affinidi-tdk-rs [#629](https://github.com/affinidi/affinidi-tdk-rs/pull/629)
and didwebvh-rs [#50](https://github.com/decentralized-identity/didwebvh-rs/pull/50).

TDK crates publish **only from CI** (push to `main`). `didwebvh-rs` is published
manually. This runbook is written around those two constraints.

## Why this one needs a runbook

`affinidi-did-common` takes a **minor** bump (0.3.9 → 0.4.0). Per
[ADR 0003 §3](../adr/0003-public-api-semver-policy.md) that invalidates the
`[patch.crates-io]` redirect held by any **external** crates.io consumer still
requiring `"0.3"` — but those consumers cannot build until 0.4.0 is on
crates.io:

```
affinidi-did-common 0.4.0     ──needs──▶  nothing new; publishable immediately
affinidi-data-integrity 0.7.7 ──needs──▶  did-common 0.4.0
didwebvh-rs 0.5.8             ──needs──▶  did-common 0.4.0 + data-integrity 0.7.7
did-scid, cache-sdk, …        ──needs──▶  didwebvh-rs 0.5.8
```

There are **two** external consumers in that chain, not one.
`affinidi-data-integrity` is easy to miss because `didwebvh-rs` reaches
`affinidi-did-common` through it transitively. Bumping `didwebvh-rs` alone still
leaves two copies of `affinidi-did-common` in the graph:

```
error[E0308]: expected `affinidi_did_common::Document`,
              found a different `affinidi_did_common::Document`
note: there are multiple different versions of crate `affinidi_did_common`
      in the dependency graph
```

## The release pipeline resolves ordering by itself

This is the key fact, and it is what makes the cycle escapable.
`affinidi/pipeline-rust/.github/workflows/release.yaml@main` with
`workspace_publish: false`:

- **Runs no workspace build before publishing.** Quoting the workflow: *"no
  unconditional `cargo build --release` here … a full-workspace build at release
  time … couples every crate's fate together (one unrelated broken crate fails
  the whole release before anything publishes)."*
- Publishes each crate via `cargo publish -p <crate>`, which **verifies only
  that crate's own dependency tree**. An unrelated broken crate cannot block it.
- Retries in passes (default `release_max_retries: 10`, 15s apart). A failed
  crate becomes a warning and is requeued; the loop stops early only when a full
  pass makes **no** progress. Publish ordering therefore sorts itself out.
- Skips any crate whose local version is not strictly greater than crates.io, so
  re-running is safe and resumes rather than restarting.

Consequence: **a red workspace build does not prevent publishing.** It only
means the PR's own checks are red, which is a merge-gate question, not a
release-pipeline one.

## Preconditions

- Admin/bypass rights to merge #629 with red checks.
- crates.io publish rights for `didwebvh-rs` (org: `decentralized-identity`,
  **not** `affinidi` — confirm before you start, not at step 3).
- #629 keeps the `didwebvh-rs` requirement at `"0.5"`, **not** `"0.5.8"`.
  Pinning a version that does not exist makes the workspace unresolvable, and
  cargo then refuses to package *any* crate:
  `error: failed to select a version for the requirement didwebvh-rs = "^0.5.8"`.
  `"0.5"` selects 0.5.8 automatically once published.

---

## Step 1 — merge #629 into `main` (force past red checks)

PR checks will be red: `did-scid`, `affinidi-did-resolver-cache-sdk` and their
dependents cannot compile until `didwebvh-rs 0.5.8` exists. That is expected and
is the reason for the bypass.

> **`main` is left non-compiling from here until step 2 completes.** Keep the
> window short and tell anyone working off `main`. This is the real cost of the
> minor-bump route; nothing else in this runbook is risky.

The release run then publishes, over several retry passes:

| Pass | Publishes |
|------|-----------|
| 1 | `affinidi-did-common 0.4.0` — needs only `affinidi-crypto`/`affinidi-encoding`, both live |
| 2 | `affinidi-data-integrity 0.7.7`, `affinidi-did-resolver-traits 0.1.3`, `affinidi-did-web 0.1.3`, `did-example 0.5.9`, `did-ebsi 0.1.4` |
| 3+ | no progress — remaining crates need `didwebvh-rs 0.5.8` |

The step then exits non-zero listing the unpublished crates. **That is the
expected outcome, not a failure to fix.** Tags for what did publish are pushed
regardless (`Push Tags` runs under `always()`).

Confirm before continuing:

```bash
cargo info affinidi-did-common      # 0.4.0
cargo info affinidi-data-integrity  # 0.7.7
```

## Step 2 — manually publish `didwebvh-rs 0.5.8`

In the didwebvh-rs repo on `did-common-0.4` (PR #50). `Cargo.lock` was
deliberately left unrefreshed there — it could not be regenerated honestly
before step 1. Refresh it now:

```bash
cargo update -p affinidi-did-common --precise 0.4.0
cargo update -p affinidi-data-integrity --precise 0.7.7
cargo tree | grep affinidi-did-common      # must show exactly one line: v0.4.0
cargo test --all-features                  # expect 438 passing
cargo publish
```

Commit the refreshed lockfile to PR #50 and merge it.

> `cargo update -p X` silently no-ops when two versions of `X` are in the graph.
> Use the `--precise` form above and verify with `cargo tree`.

## Step 3 — re-run the TDK release

Re-run the `release` workflow on `main` (or push any commit to `main`). With
`didwebvh-rs 0.5.8` live, the remaining 12 crates publish; the 6 from step 1 are
skipped automatically as already-published.

| Crate | Version |
|-------|---------|
| `did-scid` | 0.1.11 |
| `affinidi-did-resolver-cache-sdk` | 0.8.13 |
| `affinidi-did-authentication` | 0.3.10 |
| `affinidi-did-resolver-cache-server` | 0.9.3 |
| `affinidi-tdk-common` | 0.6.6 |
| `affinidi-meeting-place` | 0.4.4 |
| `affinidi-tsp` | 0.1.13 |
| `affinidi-messaging-sdk` | 0.18.60 |
| `affinidi-tdk` | 0.8.4 |
| `affinidi-messaging-didcomm-service` | 0.3.20 |
| `affinidi-messaging-mediator` | 0.17.3 |
| `affinidi-tdk-test-support` | 0.8.1 |

(The retry loop handles ordering within this set; the table is for verification,
not for driving anything manually. Regenerate it with `cargo metadata`.)

## Step 4 — verify

`main` should now compile again:

```bash
git checkout main && git pull
cargo update -w
cargo tree --workspace | grep -o 'affinidi-did-common v[0-9.]*' | sort -u
# must print exactly one line: affinidi-did-common v0.4.0
cargo test --workspace --no-fail-fast
```

Two failures are **pre-existing on main** and unrelated to this release:

- `vta-sdk` — `DidCommTransport: MessageTransport` not satisfied.
- `affinidi-did-common` under `--no-default-features` — `KeyType`/`JWK` E0599s.

Then check no `[patch.crates-io]` redirect is masking a stale registry crate:

```bash
cargo tree --workspace | grep -o 'affinidi-[a-z-]* v[0-9.]*' | sort -u
```

Any crate at two versions means a redirect has fallen through — the failure mode
this runbook exists to prevent.

## If something goes wrong

crates.io publishes are **irreversible** — yank only, and a yanked version
cannot be republished at the same number.

- **Step 1 publishes fewer crates than expected** — read the per-crate warnings
  in the job log. The loop only gives up after a pass with zero progress, so a
  crate left pending has a real dependency problem, not an ordering one.
- **Step 2 fails** — step 1's publishes are permanent, which is fine; those
  versions are correct regardless. Fix `didwebvh-rs` and retry. Do **not** bump
  `affinidi-did-common` again to work around it.
- **A crate needs a code change to publish** — it also needs a fresh patch bump.
  Publishing changed source at an already-published version is what broke the
  2026-06-13 release; see `scripts/check-version-bumps.sh` and ADR 0004.

## Known trap for next time

`did-example` is a workspace member referenced *by version* from
`affinidi-did-resolver-cache-sdk` but was **missing from `[patch.crates-io]`**,
so cargo silently built against the published copy instead of local source —
which is how a second `affinidi-did-common` kept entering the graph even after
`didwebvh-rs` was handled. #629 adds it.

If you add a workspace crate that another member depends on *by version*, add it
to `[patch.crates-io]` in the same PR. Otherwise local changes to it will not
take effect in workspace builds, and a stale registry copy will drag in old
transitive dependencies.

Note also that `[patch.crates-io]` replaces the registry crate **unconditionally**
for path-dependency members: a workspace crate requiring `"0.3"` while the local
crate is at `0.4.0` fails to resolve outright rather than falling back to the
registry. This is why there is no "bump the foundational crate on its own first"
PR — it cannot be made to resolve.

# Runbook — publishing `affinidi-did-common 0.4.0`

Covers affinidi-tdk-rs [#629](https://github.com/affinidi/affinidi-tdk-rs/pull/629)
and didwebvh-rs [#50](https://github.com/decentralized-identity/didwebvh-rs/pull/50).

Read the whole thing before running anything. Steps 1–3 are manual and
out-of-band; step 5 is the normal automated release.

## Why this one needs a runbook

`affinidi-did-common` takes a **minor** bump (0.3.9 → 0.4.0). Per
[ADR 0003 §3](../adr/0003-public-api-semver-policy.md) that invalidates the
`[patch.crates-io]` redirect held by any **external** crates.io consumer still
requiring `"0.3"`, so those consumers must be republished first — but they
cannot build until 0.4.0 is on crates.io. That circularity is the entire
problem:

```
affinidi-did-common 0.4.0  ──needs nothing new──▶  publishable immediately
affinidi-data-integrity 0.7.7 ──needs──▶ did-common 0.4.0
didwebvh-rs 0.5.8         ──needs──▶ did-common 0.4.0 + data-integrity 0.7.7
everything else           ──needs──▶ didwebvh-rs 0.5.8
```

There are **two** external consumers in that chain, not one.
`affinidi-data-integrity` is easy to miss because `didwebvh-rs` pulls
`affinidi-did-common` through it transitively; bumping `didwebvh-rs` alone still
leaves two copies of `affinidi-did-common` in the graph and fails with:

```
error[E0308]: expected `affinidi_did_common::Document`,
              found a different `affinidi_did_common::Document`
note: there are multiple different versions of crate `affinidi_did_common`
      in the dependency graph
```

## Preconditions

- crates.io publish rights for the `affinidi-*` crates and `didwebvh-rs`.
- `cargo login` done.
- affinidi-tdk-rs #629 checked out locally. **Do not merge it yet** — merging
  before step 3 triggers the release pipeline against an unpublishable graph.
- didwebvh-rs #50 checked out locally on `did-common-0.4`.

> `didwebvh-rs` lives under the `decentralized-identity` org, not `affinidi`.
> Confirm publish rights there before starting, not at step 3.

---

## Step 1 — publish `affinidi-did-common 0.4.0`

From the #629 branch:

```bash
cargo publish -p affinidi-did-common
```

This works because `affinidi-did-common` depends only on already-published
crates (`affinidi-crypto 0.2`, `affinidi-encoding 0.1`).

It also depends on the workspace **resolving**, which is why #629 keeps the
`didwebvh-rs` requirement at `"0.5"` rather than `"0.5.8"`. Pinning a version
that does not exist yet makes the whole workspace unresolvable and cargo refuses
to package *any* crate:

```
error: failed to select a version for the requirement `didwebvh-rs = "^0.5.8"`
```

If you see that, someone has re-pinned it — revert to `"0.5"`. Cargo selects
0.5.8 automatically once published, since it is a patch release.

Verify: `cargo info affinidi-did-common` shows 0.4.0.

## Step 2 — publish `affinidi-data-integrity 0.7.7`

Same branch, after step 1 has propagated (usually seconds; the verify build
resolves from the registry, so it will fail if 0.4.0 is not yet visible):

```bash
cargo publish -p affinidi-data-integrity
```

## Step 3 — publish `didwebvh-rs 0.5.8`

Switch to the didwebvh-rs repo, `did-common-0.4` branch (PR #50).

`Cargo.lock` is intentionally uncommitted there — it could not be regenerated
honestly before steps 1–2. Refresh it now:

```bash
cargo update -p affinidi-did-common --precise 0.4.0
cargo update -p affinidi-data-integrity --precise 0.7.7
cargo test --all-features        # expect 438 passing
cargo publish
```

Commit the refreshed `Cargo.lock` to PR #50 and merge it.

> `cargo update -p X` silently no-ops when two versions of `X` are in the graph.
> Use the `--precise` form above, and confirm with
> `cargo tree | grep affinidi-did-common` — you want **one** line, `v0.4.0`.

## Step 4 — confirm #629 goes green

With 0.5.8 live, affinidi-tdk-rs #629 resolves. Re-run CI. Expect green apart
from two failures that are **pre-existing on main** and unrelated:

- `vta-sdk` — `DidCommTransport: MessageTransport` not satisfied.
- `affinidi-did-common` under `--no-default-features` — `KeyType`/`JWK` E0599s.

Sanity check locally:

```bash
cargo tree --workspace | grep -o 'affinidi-did-common v[0-9.]*' | sort -u
# must print exactly one line: affinidi-did-common v0.4.0
```

## Step 5 — merge #629 and let the pipeline publish the rest

Merging to `main` triggers
`affinidi/pipeline-rust/.github/workflows/release.yaml@main`, which compares
each crate's local version against crates.io and publishes those that moved.
`workspace_publish: false` means it **skips already-published crates**, so
`affinidi-did-common 0.4.0` and `affinidi-data-integrity 0.7.7` from steps 1–2
are passed over rather than erroring.

The remaining 16 publish in this dependency order:

| # | Crate | Version |
|---|-------|---------|
| 3 | `affinidi-did-resolver-traits` | 0.1.3 |
| 4 | `affinidi-did-web` | 0.1.3 |
| 5 | `did-ebsi` | 0.1.4 |
| 6 | `did-example` | 0.5.9 |
| 7 | `did-scid` | 0.1.11 |
| 8 | `affinidi-did-resolver-cache-sdk` | 0.8.13 |
| 9 | `affinidi-did-authentication` | 0.3.10 |
| 10 | `affinidi-did-resolver-cache-server` | 0.9.3 |
| 11 | `affinidi-tdk-common` | 0.6.6 |
| 12 | `affinidi-meeting-place` | 0.4.4 |
| 13 | `affinidi-tsp` | 0.1.13 |
| 14 | `affinidi-messaging-sdk` | 0.18.60 |
| 15 | `affinidi-tdk` | 0.8.4 |
| 16 | `affinidi-messaging-didcomm-service` | 0.3.20 |
| 17 | `affinidi-messaging-mediator` | 0.17.3 |
| 18 | `affinidi-tdk-test-support` | 0.8.1 |

(Regenerate this ordering with `cargo metadata` rather than editing by hand.)

## Step 6 — post-release verification

```bash
cargo update -w && cargo test --workspace --no-fail-fast
```

Confirm no `[patch.crates-io]` entry is silently masking a stale registry crate:

```bash
cargo tree --workspace | grep -o 'affinidi-[a-z-]* v[0-9.]*' | sort -u
```

Any crate appearing at two versions means a `[patch]` redirect has fallen
through — the failure mode this whole runbook exists to prevent.

## If a step fails partway

crates.io publishes are **irreversible** — you can yank, never unpublish, and a
yanked version still can't be republished at the same number.

- **Failure at step 1 or 2** — nothing downstream has moved; fix and retry.
- **Failure at step 3** — steps 1–2 are already live and permanent. That is
  fine and not wasted: those versions are correct regardless. Fix `didwebvh-rs`
  and retry. Do **not** bump `affinidi-did-common` again to work around it.
- **Failure during step 5** — the pipeline skips already-published crates, so
  re-running after a fix resumes rather than restarting. Any crate that needs a
  code change to publish also needs a fresh patch bump (see
  `scripts/check-version-bumps.sh` and ADR 0004 for why publishing changed
  source at an existing version is what broke the 2026-06-13 release).

## Known trap for next time

`did-example` was a workspace member referenced *by version* from
`affinidi-did-resolver-cache-sdk` but **missing from `[patch.crates-io]`**, so
cargo silently built against the published copy rather than local source. #629
adds it. If you add a workspace crate that another member depends on by version,
add it to `[patch.crates-io]` in the same PR, or local changes to it will not
take effect in workspace builds and a stale registry copy will drag in old
transitive dependencies.

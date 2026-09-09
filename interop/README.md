# TSP interop harness

A fast, local round-trip harness between **`affinidi-tsp`** (this repo) and the
ToIP reference **`tsp_sdk` 0.10.0**, the reference's first Rev 3 release. It
feeds the *same* raw keys, VIDs and payload to both libraries, round-trips every
message type in both directions, and prints a pass/fail gate.

```
cd interop
cargo +stable run
```

`+stable` is not optional: the harness needs a newer toolchain than the
workspace pin in `rust-toolchain.toml`.

This is a **developer-only** harness. It is its own standalone Cargo workspace
(see the empty `[workspace]` in `Cargo.toml`), so the main workspace and CI never
build it, and `tsp_sdk`'s dependency graph never has to co-resolve with the
workspace.

## No prerequisites

The reference comes from crates.io. There is nothing to clone and nothing to
patch — a change from every earlier revision of this harness:

- 0.9.0-alpha2 (Rev 2) did not build without its `resolve` feature and needed
  three source patches, applied by hand to a sibling checkout.
- The Rev 3 work was done against the reference's `rev3` branch, which built
  clean but still had to be cloned to `../../tsp-sdk-rev3`.
- 0.10.0 builds with `default-features = false, features = ["serialize", "nacl",
  "pq"]` as published.

`nacl` is the libsodium sealed box and `pq` the post-quantum suite; both are off
in a `default-features = false` build and both are coverage this crate now has.

## What it covers

19 cases, all passing:

| | |
|---|---|
| Direct (HPKE-Base) | both directions |
| Direct, 2 MiB payload | both directions |
| Direct (sealed box, §8.3) | both directions |
| Routed | both directions |
| Nested | both directions |
| Control — invite / accept / cancel | both directions |
| Direct, post-quantum | both directions, plus a negative case |

The post-quantum case uses the specification's published `pq_alice`/`pq_bob`
rather than generated keys — see [`docs/tsp/interop.md`](../docs/tsp/interop.md)
for why, and for what it adds over the vector suite. Its negative case asserts
that a post-quantum ciphertext offered classical keys is refused rather than
misread.

## What the harness is for

It catches what the specification's own vectors cannot. A published vector fixes
one direction: it proves this crate can *read* bytes the reference produced.
Nothing in a vector can pin an encoder, because HPKE seals with fresh randomness
and no two runs produce the same message. Only a live pairing shows that the
reference can read what we write.

The converse is also true, which is why both exist. The harness packs with one
implementation and unpacks with the other, so a *shared* misreading of the spec
passes it — both sides agree, and nothing external says whether the agreement is
right. That is not hypothetical: the accept's two digests were in the wrong
order on this branch until the spec text settled it, and an interop run between
two implementations making the same choice would have been green.

# TSP interop status: `affinidi-tsp` vs the ToIP reference

**Status: FULLY INTEROPERABLE against the released reference.**

`affinidi-tsp` on this branch implements TSP spec **Rev 3** and wire-interoperates
with [`tsp_sdk` 0.10.0](https://crates.io/crates/tsp_sdk) — the reference's first
Rev 3 release, published 8 September 2026 — for every message type this crate
implements, in both directions: **19/19 PASS**.

| Case | `affinidi-tsp` ↔ `tsp_sdk` 0.10.0 |
|---|---|
| Direct (HPKE-Base) | ✅ both directions |
| Direct, 2 MiB payload | ✅ both directions |
| Direct (libsodium sealed box, §8.3) | ✅ both directions |
| Routed | ✅ both directions |
| Nested | ✅ both directions |
| Control — invite / accept / cancel | ✅ both directions |
| **Direct, post-quantum** (`MLKEM768-X25519` + ML-DSA-65) | ✅ both directions |

Verified empirically by the [`interop/`](../../interop/) harness: a single-graph
round-trip feeding both libraries the same raw keys, VIDs and payload. See
[`interop/README.md`](../../interop/README.md) to run it.

```
cd interop && cargo +stable run
```

## What changed when the reference released

The Rev 3 migration was done against the reference's `rev3` *branch*, from a
sibling checkout at `../../tsp-sdk-rev3`. 0.10.0 replaces that entirely:

- The harness now depends on the **published crate**, not a local checkout. No
  clone to prepare, and none of the three source patches 0.9.0-alpha2 needed —
  0.10.0 builds without its `resolve` feature as-is.
- It still needs a newer toolchain than the workspace pin of 1.95.0, so run it
  as `cargo +stable run`.
- The harness gained two cases the branch could not run before: the sealed box
  (both sides now implement §8.3) and post-quantum.

Rev 3 messages do not interoperate with Rev 2 peers in either direction — the
reference says so in its own release notes — so `main`, which is still Rev 2, no
longer meets the released reference at all.

## Post-quantum

The post-quantum case is the one that needs explaining, because it is the only
one that does not use freshly generated keys. It uses the specification's own
published `pq_alice`/`pq_bob` (Rev 3 Appendix A), for two reasons: generating an
ML-DSA-65 and a hybrid-KEM key pair would mean adding both algorithms to the
harness, and agreement over identities a third party fixed is better evidence
than agreement over keys one of the two libraries generated.

It complements rather than duplicates the vector suite. `direct-hpke-base-pq` in
`tests/spec_vectors.rs` proves we can *read* the reference's post-quantum bytes;
only the harness proves it can read ours, because HPKE seals with fresh
randomness and no published vector can pin an encoder's output. The harness also
asserts that a post-quantum ciphertext offered classical keys is **refused** —
reading it as X25519 splits `enc` at 32 bytes instead of 1120, and that has to
fail rather than produce something.

See [`post-quantum.md`](post-quantum.md) for what is and is not wired up above
the crate.

## The version field: three values, and why it does not matter

We emit `YTSP-AAC` (0.2). The reference emits `YTSP-ABA` (0, 1, 0). The published
spec text says `YTSP-ABA` with a three-component MAJOR.MINOR.PATCH reading.

Rev 3 originally kept Rev 2's constant, which would have left the two revisions
indistinguishable at the envelope; that was raised on
[spec PR #63](https://github.com/trustoverip/tswg-tsp-specification/pull/63) and
changed upstream in `c80b0e4` to `ABA`. Sam Smith then questioned the
three-component reading itself — under MAJOR.MINOR, `ABA` reads as version 64
rather than 2 — so we moved to `AAC`, which is where that argument lands. On
8 September the editor agreed ("I'm fine with MAJOR.MINOR only… note that this
will cause the test vectors to update one more time"), but the spec text has not
been edited yet and the reference has not moved.

Interop is unaffected, and that is the design rather than luck: **neither side
gates on MINOR.** The reference discards it outright (`let _minor_patch = …`),
and we carry it, consulting it only to attribute a parse that has *already*
failed. So the disagreement is invisible in both directions, and all 19 cases
pass across it.

Expect one more vector regeneration when the MAJOR.MINOR edit lands, at which
point `tests/vectors/rev3.json` and the reference both move to `AAC` and the
three values become one.

## Caveats

- **Re-run the harness on every reference bump.** 0.10.0 is the first Rev 3
  release; the wire format is stable in intent but the spec PR is still open.
- **The post-quantum code point `1AAQ` is provisional** — CESR issue #14 has not
  registered it. A reference built against a later table would disagree, and the
  harness is what would catch it.
- **Scope.** The three core relationship operations (invite / accept / cancel)
  interoperate. Routed relationship forming (`Reply_Path`) is implemented here
  and is not yet in the reference, so it is untested across the pair.

# TSP interop status: `affinidi-tsp`

`affinidi-tsp` implements the **merged** TSP Rev 3 specification
([trustoverip/tswg-tsp-specification@`f5b8668`](https://github.com/trustoverip/tswg-tsp-specification/commit/f5b8668952aabe8e541b535fcbdf589484ffc4f4)),
whose version marker is `YTSP-AAC` (MAJOR 0, MINOR 2). That is what this crate
emits.

## Where interop is tested

Cross-implementation conformance lives in
[OpenVTC/tsp-conformance](https://github.com/OpenVTC/tsp-conformance): one
runner, a driver per implementation, and CI. It covers five implementations —
this crate, the ToIP reference [`tsp_sdk`](https://crates.io/crates/tsp_sdk),
and the Go, Dart and JS implementations — across four suites: the specification's
Appendix A vectors (open, and byte-exact re-pack where the vector publishes its
ephemeral material), pairwise pack/open interop, negative cases, and the
relationship protocol.

On the current merged code the matrix is:

| Suite | Pass / fail |
|---|---|
| vectors | 137 / 0 |
| interop | 893 / 0 |
| negative | 377 / 8 |
| relationship | 250 / 0 |

All eight negative failures are `tsp_sdk` accepting a message it should refuse:
trailing bytes after the message, a non-zero CESR lead byte, and a signed-only
message whose ESSR sender does not match the envelope. None is in this crate.

The in-repo [`interop/`](../../interop/) harness predates the suite. It is a
single-graph round trip against `tsp_sdk` 0.10.0 and is kept as a quick local
check; the suite is the authoritative result.

## The reference

**`tsp_sdk` 0.11.0** is the latest reference release. It emits `YTSP-AAC`:
`TSP_VERSION` is `(0, 2)`, with MINOR written as the whole two-character count
(`src/cesr/packet.rs`). On read it gates on MAJOR and discards MINOR. Its
`test_vectors/rev3.json` is the file the specification's Appendix A is rendered
from, and it agrees value for value with `tests/vectors/rev3.json` here.

## The version field

Pre-merge drafts of Rev 3 printed `YTSP-ABA`, reading the three characters as
MAJOR.MINOR.PATCH. The merged specification reads them as MAJOR.MINOR — one
character of MAJOR, two of MINOR — so Rev 3 is `AAC`, where Rev 2 was `AAB`.

Only MAJOR gates processing, here and in the reference. A message packed by a
pre-merge peer under `ABA` still opens: its digest and signature cover the
version bytes it carries, and MINOR is carried rather than checked. It is
consulted only to explain a parse that has already failed.

Rev 3 messages do not interoperate with Rev 2 peers in either direction; MAJOR
is the same, but the wire changed throughout.

## Post-quantum

The `MLKEM768-X25519` + ML-DSA-65 path interoperates with the reference over the
specification's published `pq_alice`/`pq_bob`. The vector publishes no
ephemeral material — the hybrid KEM draws its encapsulation randomness — so it
is checked by opening, never by byte-exact re-pack. See
[`post-quantum.md`](post-quantum.md) for what is wired above the crate.

## Caveats

- **The post-quantum code point `1AAQ` is provisional**; CESR issue #14 has not
  registered it.
- **Re-run the suite on every reference release.** It is the check that catches
  a disagreement in either direction.

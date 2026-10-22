# TSP interop status: `affinidi-tsp`

`affinidi-tsp` 0.3 implements the **released TSP 1.0** specification
([trustoverip/tswg-tsp-specification@`ccda6b3`](https://github.com/trustoverip/tswg-tsp-specification/commit/ccda6b33159d860f05c328eb436dabe83548b705)),
whose version marker is `YTSP-BAA` (MAJOR 1, MINOR 0). That is what this crate
emits. 0.2.x implemented Rev 3 (`YTSP-AAC`, 0.2).

1.0 is Rev 3 with one payload rule changed: the ESSR sender field `VID_sndr`
MUST carry the sender's VID in every confidential payload, under HPKE-Base as
well as the sealed box. Rev 3 let HPKE-Base write the NULL VID `4BAA` there.
This crate always carried the sender, so its send side is unchanged; on receive
it now refuses a confidential payload whose sender field is NULL. A signed-only
payload may still carry NULL.

## Where interop is tested

Cross-implementation conformance lives in
[OpenVTC/tsp-conformance](https://github.com/OpenVTC/tsp-conformance): one
runner, a driver per implementation, and CI. It covers five implementations —
this crate, the ToIP reference [`tsp_sdk`](https://crates.io/crates/tsp_sdk),
and the Go, Dart and JS implementations — across four suites: the specification's
Appendix A vectors (open, and byte-exact re-pack where the vector publishes its
ephemeral material), pairwise pack/open interop, negative cases, and the
relationship protocol.

The last run, on 16 September 2026 against Rev 3 (`affinidi-tsp` 0.2.x), was:

| Suite | Pass / fail |
|---|---|
| vectors | 137 / 0 |
| interop | 893 / 0 |
| negative | 377 / 8 |
| relationship | 250 / 0 |

All eight negative failures are `tsp_sdk` accepting a message it should refuse:
trailing bytes after the message, a non-zero CESR lead byte, and a signed-only
message whose ESSR sender does not match the envelope. None is in this crate.

**These numbers predate 1.0.** The suite has not yet moved to the 1.0 vectors
or to `tsp_sdk` 0.16.0, and every driver still on Rev 3 is now refused on
MAJOR by a 1.0 one. Re-run once the drivers are updated. Until then, the
in-repo `tests/spec_vectors.rs` is the 1.0 check: all eleven Appendix A
vectors open, and every vector that publishes its ephemeral material (all but
the post-quantum one) re-packs byte for byte.

The in-repo [`interop/`](../../interop/) harness predates the suite. It is a
single-graph round trip against `tsp_sdk` 0.10.0 — a Rev 3 build, so it no
longer interoperates with 1.0 until it is moved to 0.16.0. The suite is the
authoritative result.

## The reference

**`tsp_sdk` 0.16.0** is the first reference release at 1.0. It emits
`YTSP-BAA`: `TSP_VERSION` is `(1, 0)`, with MINOR written as the whole
two-character count (`src/cesr/packet.rs`). On read it gates on MAJOR, so it
rejects 0.x drafts, and discards MINOR. Its `EssrSender` now defaults to
`Always`; `NullUnderHpkeBase` survives only to reproduce the draft wire format.
Its `test_vectors/rev3.json` (the name is kept) is the file the specification's
Appendix A is rendered from, and it agrees value for value with
`tests/vectors/rev3.json` here, including the new `control-rfi-referral`
vector.

## The version field

The three characters are MAJOR.MINOR — one character of MAJOR, two of MINOR.
Rev 2 was `AAB` (0.1), Rev 3 `AAC` (0.2), and 1.0 is `BAA`. Pre-merge drafts of
Rev 3 printed `YTSP-ABA`, reading the field as MAJOR.MINOR.PATCH; the
specification settled on two components.

Only MAJOR gates processing, here and in the reference. A different MINOR is
carried rather than checked, and is consulted only to explain a parse that has
already failed.

1.0 does not interoperate with Rev 3 or Rev 2 peers in either direction. Each
side refuses the other's MAJOR at the envelope, and this crate reports it as a
`RevisionMismatch` naming both versions rather than as a parse failure deeper
in. Upgrade both ends together.

The exception is keys-free addressing. `MetaEnvelope::parse` reads the frame
and both VIDs of any version, since that encoding is unchanged since Rev 2 and
a relay processes nothing it addresses. A mediator on 1.0 therefore still
routes between two endpoints that are both on Rev 3.

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
  a disagreement in either direction. It is due now: 1.0 and `tsp_sdk` 0.16.0
  are not yet in it.

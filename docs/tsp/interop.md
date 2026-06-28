# TSP interop status: `affinidi-tsp` vs the ToIP reference

**Question:** does `affinidi-tsp` (this repo) wire-interoperate with the official
ToIP reference implementation, [`tsp-sdk`](https://github.com/openwallet-foundation-labs/tsp)?

**Verdict (2026-06, `affinidi-tsp` 0.1.6 vs `tsp-sdk` 0.9.0-alpha2): NO — they do
not interoperate, in either direction.** This was verified empirically with a
two-binary round-trip (two standalone crates exchanging raw bytes through a file,
so the dependency graphs never linked), feeding **both** libraries the same raw
Ed25519 + X25519 keys, VIDs, and payload.

| Direction | Result |
|---|---|
| `affinidi-tsp` `pack` → `tsp-sdk` `open` | **FAIL** — `Decode(VersionMismatch)` |
| `tsp-sdk` `seal` → `affinidi-tsp` `unpack` | **FAIL** — `unknown code: -E` |
| each library opening its own output | OK |

Both failures happen at the **first parse step (outer framing)** — neither side
even reaches the other's crypto. And even if framing matched, the AEAD differs, so
decryption would still fail.

> **Status update (as of `affinidi-tsp` 0.1.7).** The **crypto** mismatches below —
> the AEAD and the HPKE `info` — are now **fixed** (the AEAD is ChaCha20Poly1305 and
> `info` is empty, per the spec; see the changelog / #540). The **CESR framing**
> mismatches remain, and a framing rewrite to the spec/reference format is in
> progress. The headline "no interop" verdict therefore still holds until the
> framing work lands; the field tables below describe the original 0.1.6 divergence,
> with the crypto rows now resolved.

## Where they agree, and where they don't

| Aspect | `affinidi-tsp` | `tsp-sdk` 0.9.0-alpha2 | Match |
|---|---|---|:---:|
| KEM | DHKEM(X25519, HKDF-SHA256) | X25519HkdfSha256 | ✅ |
| KDF | HKDF-SHA256 | HkdfSha256 | ✅ |
| HPKE mode | Auth | Auth (default) | ✅ |
| **AEAD** | **AES-128-GCM** | **ChaCha20Poly1305** | ❌ fundamental |
| **CESR framing** | one `Matter`/Tag1 header (`D4 00 05`) + a bespoke, mostly non-CESR body | nested CESR count-code groups (`-E`/`-Z`/`-C`/`-K`), `YTSP` version marker, var-data crypto codes | ❌ fundamental |
| **Payload encoding** | raw payload encrypted directly | payload **CESR-encoded** (`-Z … XSCS …`) *before* encryption | ❌ fundamental |
| HPKE `info` | `b"TSP-v1-direct"` | empty | ❌ |
| enc/tag placement, signature framing | `enc`-before-ct, raw 64-byte Ed25519 sig appended | tag+enc after ct, CESR-framed sig | ❌ (subsumed by framing) |
| signature algorithm | Ed25519 | Ed25519 | ✅ (framing differs) |

The two implementations share only the **KEM and KDF**. They disagree on the
AEAD, the entire CESR envelope framing, the payload encoding, the HPKE info/AAD
bytes, and the signature framing.

## Which side is spec-correct?

Adjudicated against the **TSP specification, v1.0 Experimental Implementor's Draft
Rev 2** ([trustoverip.github.io/tswg-tsp-specification](https://trustoverip.github.io/tswg-tsp-specification/))
— the same revision `affinidi-tsp` claims to target. On every clear point, the
reference (`tsp-sdk`) conforms and **`affinidi-tsp` diverges**:

| Mismatch | Spec says | `affinidi-tsp` | `tsp-sdk` | Conformant |
|---|---|---|---|---|
| AEAD | **ChaCha20Poly1305** only (code 0x0003); AES-GCM is not mentioned, no negotiation | AES-128-GCM | ChaCha20Poly1305 | **tsp-sdk** |
| HPKE `info` | **`NULL`** (empty) in `TSP_SEAL`/`TSP_OPEN` | `b"TSP-v1-direct"` | empty | **tsp-sdk** |
| Envelope framing | **CESR**: `TSP_Tag` count code `-E##` + `TSP_Version` `YTSP-###` + `VID_sndr`/`VID_rcvr` var-data codes | one `Matter`/Tag1 (`D4 00 05`) + bespoke non-CESR body, no `YTSP` version | CESR `-E`/`YTSP`/VID codes | **tsp-sdk** |
| Payload framing | CESR control codes incl. `XSCS` for the payload | raw payload, no CESR frame | `-Z … XSCS …` | **tsp-sdk** |
| Version marker | mandatory `TSP_Version` (`YTSP-###`) | none (a byte in the Matter raw) | `YTSP` marker | **tsp-sdk** |
| KEM / KDF | X25519 / HKDF-SHA256 | ✅ | ✅ | both |
| Signature algorithm | Ed25519 | ✅ | ✅ | both (framing differs; spec's sig **framing** is incomplete in this draft) |

**Conclusion: `affinidi-tsp` is the non-conformant side.** Its AEAD choice, HPKE
`info`, and CESR envelope/version framing are not what the TSP Rev 2 spec mandates
— they read as independent implementation choices, not spec-grounded ones. The
reference implements the spec. So the interop failure isn't a "two valid dialects"
situation: it's `affinidi-tsp` deviating from the standard it targets.

## Effort to close

There is **no small change** that yields a green round-trip. The smallest viable
path is for `affinidi-tsp` to **adopt `tsp-sdk`'s wire format end-to-end**:
ChaCha20Poly1305 AEAD + the nested-CESR envelope (`-E`/`-Z`/`-C`/`-K`) + CESR
payload pre-encoding + empty HPKE info + CESR signature framing. That is a
**large, wire-breaking change on the `affinidi-tsp` side** (rewrite
`envelope.rs` + `direct.rs`). The reference is authoritative for the spec rev it
targets, so the change belongs on our side.

## Caveat: the reference is alpha and does not build as published

Independent of interop, `tsp-sdk` 0.9.0-alpha2 **does not build from crates.io**:
its `definitions` module unconditionally imports from a `resolve`-gated path
(making `resolve` mandatory), `resolve` pulls `didwebvh-rs` into an
`affinidi-secrets-resolver` version diamond (two incompatible `Secret` types), and
it pins `serde = "=1.0.219"` exactly, which blocks bumping past the diamond. The
experiment only built `tsp-sdk` by vendoring it locally with the serde pin relaxed
and `didwebvh-rs` bumped. **Its wire format and dependency set are both unstable.**

## Recommendation

Because `affinidi-tsp` is the **non-conformant** side, the fix and the interop are
the same task: bring `affinidi-tsp` into line with the TSP Rev 2 spec, which the
reference already implements. This is a **correctness** issue (we don't match the
standard we claim to target), not merely a missing nice-to-have.

Sequence it by how stable each gap is:

1. **Now — the unambiguous, low-risk crypto fixes.** Switch the HPKE AEAD to
   **ChaCha20Poly1305** and set the HPKE `info` to **empty/NULL**. These are clear,
   stable spec requirements unlikely to change, and they're small, self-contained
   edits in `affinidi-tsp`'s `crypto`/`direct` layer. (Both are wire-breaking, but
   `affinidi-tsp` is `0.1.x` and pre-adoption, so the break is cheap now and only
   gets more expensive later.)
2. **Later — the CESR envelope/payload/signature rewrite.** Replacing the
   bespoke `Matter`/Tag1 framing with the spec's count-code groups (`-E`/`-Z`/
   `-C`/`-K`) + `YTSP` version + var-data VID/payload/signature codes is the large
   change. Do it once (a) the spec's **signature framing** is complete (it is
   *incomplete* in Rev 2's current draft) and (b) `tsp-sdk` is **buildable +
   stable** so the round-trip can be the conformance test. Rewriting the framing
   now, against an incomplete draft with no working reference to test against,
   risks doing it twice.

Two ways to land step 2 when the time comes:
- **Re-implement the spec's wire format in `affinidi-tsp`** — keeps our lean
  dependency tree; we own the conformance.
- **Depend on `tsp-sdk` directly** for the wire layer — guaranteed conformance and
  interop, but pulls its heavyweight deps (askar, sqlx, reqwest, quinn) versus our
  lean stack, and it must build cleanly first.

Until step 2 lands, `affinidi-tsp` remains a **self-consistent but non-standard**
TSP — fine for TDK-internal use, but it will not interoperate with spec-compliant
TSP peers. That limitation should be stated wherever TSP support is advertised.

## Reproducing this verdict

The check is a two-binary round-trip that keeps the dependency graphs isolated (so
the alpha's deps don't have to co-resolve with this workspace):

- crate A depends only on `affinidi-tsp` (via path) and `pack`/`unpack`s;
- crate B depends only on `tsp-sdk` and `seal`/`open`s;
- both are fed the **same** raw Ed25519 + X25519 key bytes and VIDs, and exchange
  the packed bytes through a file.

Round-tripping in both directions and asserting success is the interop test. Today
it would assert **failure**, so it documents incompatibility rather than passing —
it can become an `#[ignore]`d interop test once `tsp-sdk` stabilizes.

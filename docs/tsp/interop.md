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

**Defer interop.** It is not achievable without a wire-breaking rewrite of
`affinidi-tsp`, and it is premature to target an alpha whose wire format isn't
frozen and whose published crate doesn't build. Revisit once `tsp-sdk` ships a
**stable (non-alpha) release** with a frozen wire format and a clean dependency
graph.

If/when interop becomes a goal, two options:
1. **Re-implement `tsp-sdk`'s wire format in `affinidi-tsp`** (large; keeps our
   lean dependency tree).
2. **Depend on `tsp-sdk` directly** for the wire layer (smaller code, but pulls
   its heavyweight deps — askar, sqlx, reqwest, quinn — versus our lean stack).

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

# TSP interop status: `affinidi-tsp` vs the ToIP reference

> **On the `rev3` branch this document describes the past, not the present.**
>
> This branch implements TSP spec **Rev 3** and is verified against the
> reference's own `rev3` branch (`openwallet-foundation-labs/tsp` @ `85bbf47`):
> **14/14 PASS**, both directions, for Direct (including a 2 MiB case), Routed,
> Nested and the three relationship control messages.
>
> Two things changed about running the harness. It now points at
> `../../tsp-sdk-rev3` rather than `../../tsp-sdk`, and the reference's `rev3`
> branch builds without the `resolve` feature as-is — so the three patches
> described below are **obsolete**. It does need a newer toolchain than the
> workspace pin of 1.95.0, so run it as `cargo +stable run`.
>
> The released reference, 0.9.0-alpha2, is still Rev 2 and is wire-incompatible
> with this branch in both directions. Everything below describes that Rev 2
> state on `main`.

**Status (as of `affinidi-tsp` 0.1.10): FULLY INTEROPERABLE.**

`affinidi-tsp` wire-interoperates with the official ToIP reference,
[`tsp-sdk`](https://github.com/openwallet-foundation-labs/tsp) (0.9.0-alpha2), for
**every** TSP message type, in **both** directions:

| Message type | `affinidi-tsp` ↔ `tsp-sdk` |
|---|---|
| Direct | ✅ both directions |
| Routed | ✅ both directions |
| Nested | ✅ both directions |
| Control (relationship invite / accept / cancel) | ✅ both directions |

This is verified empirically by the [`interop/`](../../interop/) harness — a
single-graph round-trip against `tsp-sdk`, feeding both libraries the same raw
Ed25519 + X25519 keys/VIDs/payload. It currently passes **14/14** cases (all four
types both ways, plus a 2 MiB large-payload Direct case). See
[`interop/README.md`](../../interop/README.md) to run it.

## What was aligned to the spec

The wire format matches the TSP spec (v1.0 Implementor's Draft Rev 2) and the
reference byte-for-byte:

- **HPKE** — `DHKEM(X25519, HKDF-SHA256)` + `HKDF-SHA256` + **ChaCha20Poly1305**,
  Auth mode, HPKE `info` = the envelope, AAD empty; RFC 9180-correct KEM (context
  order, `LabeledExtract` PRK, `eae_prk`/`shared_secret` labels).
- **CESR framing** — `-E` envelope wrapper, `YTSP` version, var-data VID codes, `G`
  ciphertext code, `-Z`/`XSCS` payload frame, `-C`/`-K` Ed25519 signature.
- **Routed / Nested** — `XHOP` + hop list (`-J` count + a `B` field per VID);
  Nested is the empty-hop-list case.
- **Control** — `XRFI` (invite, with a 32-byte nonce) / `XRFA` (accept) / `XRFD`
  (cancel); accept and cancel carry a `SHA256(plaintext payload frame)` digest as
  the relationship correlation (the `thread_id`).
- **Size cap** — a single variable-data field may be up to `3 * (1 << 24)` (~48 MiB),
  matching the reference's `DATA_LIMIT`.

The work landed across four PRs: **#540** (crypto suite), **#542** (Direct CESR
framing + RFC 9180 HPKE fixes), **#543** (Routed/Nested + size cap), **#544**
(Control / relationship).

## Caveats

- **`tsp-sdk` is alpha** (0.9.0-alpha2). Its wire format isn't frozen, so a future
  release could re-introduce a mismatch; re-run the harness when bumping the
  reference.
- The harness needs a local checkout of `tsp-sdk` at `../../tsp-sdk`, patched to
  build without its `resolve` feature — see [`interop/README.md`](../../interop/README.md).
- Scope: the three core relationship operations (invite/accept/cancel) interoperate.
  The reference's additional relationship payloads (nested-relationship,
  new-identifier, referral) and its `Base`/`ESSR` HPKE modes are not implemented.

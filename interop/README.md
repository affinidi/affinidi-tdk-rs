# TSP interop harness

A fast, local round-trip harness between **`affinidi-tsp`** (this repo) and the
ToIP reference **`tsp_sdk` 0.9.0-alpha2**. It feeds the *same* raw Ed25519 +
X25519 keys to both libraries and attempts a Direct-message round-trip both
directions, printing the wire bytes and the pass/fail per direction.

```
cd interop
cargo run
```

This is a **developer-only** harness: it is its own standalone Cargo workspace
(see the empty `[workspace]` in `Cargo.toml`), so the main workspace and CI never
build it, and `tsp_sdk`'s dependency graph never has to co-resolve with the
workspace.

## Prerequisite: `~/devel/tsp-sdk` (a patched tsp_sdk checkout)

The harness expects `tsp_sdk` 0.9.0-alpha2 at `../../tsp-sdk` (i.e.
`~/devel/tsp-sdk`, a sibling of this repo). The published alpha does **not** build
as-is (see `docs/tsp/interop.md`); apply these three minimal, behaviour-preserving
patches so it builds **without** the `resolve` feature — which is what removes the
didwebvh/`affinidi-secrets-resolver` dependency diamond and lets it share one
dependency graph with `affinidi-tsp`:

1. **Relax the exact serde pin.** In `Cargo.toml`, change `serde = "=1.0.219"` to
   `serde = "1.0"`.

2. **Relocate the JWK key-type enums out of the `resolve`-gated module.** The core
   `definitions` module uses `Curve`/`KeyType`/`Algorithm`/`Usage`, but they live
   in `src/vid/did/web.rs`, which is `#[cfg(feature = "resolve")]`. Move those four
   enums (and their `From<VidEncryptionKeyType>` / `From<VidSignatureKeyType>`
   impls) into a new, non-gated `src/definitions/jwk.rs`; add `pub mod jwk;` to
   `src/definitions/mod.rs` and repoint its imports to `jwk::…`; in
   `src/vid/did/web.rs` import them back via `use crate::definitions::jwk::…`.

3. **Gate `store` behind `resolve`.** `src/store.rs` imports
   `vid::resolve::verify_vid_offline`, so in `src/lib.rs` gate both `mod store;`
   and `pub use store::{Aliases, SecureStore};` with `#[cfg(feature = "resolve")]`
   (`async` already implies `resolve`, so async builds are unaffected).

With those, `cargo check --no-default-features --features serialize` in
`~/devel/tsp-sdk` succeeds.

## What it currently shows

The **CESR framing is byte-perfect** vs the reference (identical envelope, same
204-byte length, same `0xf8` lead). The remaining gap is the **HPKE crypto**:
affinidi-tsp's hand-rolled HPKE derives a different key/nonce than the `hpke`
crate `tsp_sdk` uses, so cross-implementation AEAD open fails in both directions
(each library's own self-round-trip passes). Closing that is the last step to a
green interop round-trip.

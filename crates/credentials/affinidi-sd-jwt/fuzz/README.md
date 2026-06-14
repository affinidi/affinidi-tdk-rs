# affinidi-sd-jwt fuzz targets

Coverage-guided fuzzing (cargo-fuzz / libFuzzer) of the SD-JWT parse/verify
layer (issue #477). Standalone workspace, detached from the parent so the
nightly requirement never touches the stable `1.95.0` pin.

## Requirements

```sh
rustup toolchain install nightly
cargo install cargo-fuzz --locked
```

Run from this `fuzz/` directory; use `cargo +nightly fuzz …` (or
`RUSTUP_TOOLCHAIN=nightly`).

## Targets

| Target   | Exercises                                                              |
|----------|-----------------------------------------------------------------------|
| `parse`  | `SdJwt::parse` — JWS split, disclosure decode, digest wiring (no keys) |
| `verify` | `verifier::verify` — signature + disclosure digests + claim resolution, against a fixed HMAC verifier (sync, trait-injected — no resolver, no I/O) |

## Corpus / seeds

Committed read-only seeds live in `seeds/<target>/` (valid SD-JWTs issued under a
fixed HMAC key — see `src/lib.rs`); the live libFuzzer `corpus/` is gitignored.
Regenerate with:

```sh
cargo +nightly run --bin gen_corpus
```

## Running

```sh
mkdir -p corpus/verify
cargo +nightly fuzz run verify corpus/verify seeds/verify -- -max_total_time=60
```

CI runs a short pass per target on PRs touching this crate and a longer pass
nightly (`.github/workflows/fuzz.yaml`).

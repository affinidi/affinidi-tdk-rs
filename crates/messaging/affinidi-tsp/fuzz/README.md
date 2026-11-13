# affinidi-tsp fuzz targets

Coverage-guided fuzzing (cargo-fuzz / libFuzzer) of the parsers in `affinidi-tsp`
that read bytes from outside the process. Standalone workspace, detached from
the parent so the nightly requirement never touches the stable toolchain pin.

## Requirements

```sh
rustup toolchain install nightly
cargo install cargo-fuzz --locked
```

Run from this `fuzz/` directory with `cargo +nightly fuzz …` (or
`RUSTUP_TOOLCHAIN=nightly`).

## Targets

| Target | Exercises |
|--------|-----------|
| `envelope` | `is_tsp`, `MetaEnvelope::parse`, `Envelope::decode` / `decode_full`, `ControlMessage::decode` (keys-free, what a relay reads) |
| `unpack` | `unpack` with the specification's published Appendix A keys, both directions, plus `next_hop` |

## Corpus / seeds

Read-only seeds live in `seeds/<target>/`: The specification's Appendix A messages (`tests/vectors/rev3.json`) in qb2 form. The live libFuzzer
`corpus/` is gitignored.

## Running

```sh
mkdir -p corpus/envelope
cargo +nightly fuzz run envelope corpus/envelope seeds/envelope -- -max_total_time=60
```

CI runs a short pass per target on PRs touching this crate and a longer pass
nightly (`.github/workflows/fuzz.yaml`). The committed `Cargo.lock` pins the
crates.io graph; `scripts/check-fuzz-lock.sh` fails if it drifts.

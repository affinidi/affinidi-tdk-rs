# affinidi-cesr fuzz targets

Coverage-guided fuzzing (cargo-fuzz / libFuzzer) of the parsers in `affinidi-cesr`
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
| `matter` | `Matter::from_qb64` / `from_qb2`; fixed-size codes must survive a decode → encode → decode round trip in both domains |
| `stream` | `sniff`, version-string reader, `Counter::from_qb64`, `Indexer::from_qb64`, qb64 ↔ qb2 transcoders |

## Corpus / seeds

Read-only seeds live in `seeds/<target>/`: Hand-written qb64/qb2 primitives, counters and an indexed signature. The live libFuzzer
`corpus/` is gitignored.

## Running

```sh
mkdir -p corpus/matter
cargo +nightly fuzz run matter corpus/matter seeds/matter -- -max_total_time=60
```

CI runs a short pass per target on PRs touching this crate and a longer pass
nightly (`.github/workflows/fuzz.yaml`). The committed `Cargo.lock` pins the
crates.io graph; `scripts/check-fuzz-lock.sh` fails if it drifts.

# affinidi-rdf-encoding fuzz targets

Coverage-guided fuzzing (cargo-fuzz / libFuzzer) of the parsers in `affinidi-rdf-encoding`
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
| `nquads` | N-Quads `parse`, then `serialize_dataset` and RDFC-1.0 canonicalization (N-degree work bounded) |
| `jsonld` | JSON-LD expansion to RDF, lenient and safe mode, then canonicalization (bundled contexts only, no fetching) |

## Corpus / seeds

Read-only seeds live in `seeds/<target>/`: The W3C `rdfc10` suite inputs from `tests/fixtures` and Verifiable Credential documents. The live libFuzzer
`corpus/` is gitignored.

## Running

```sh
mkdir -p corpus/nquads
cargo +nightly fuzz run nquads corpus/nquads seeds/nquads -- -max_total_time=60
```

CI runs a short pass per target on PRs touching this crate and a longer pass
nightly (`.github/workflows/fuzz.yaml`). The committed `Cargo.lock` pins the
crates.io graph; `scripts/check-fuzz-lock.sh` fails if it drifts.

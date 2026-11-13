# affinidi-trust-lists fuzz targets

Coverage-guided fuzzing (cargo-fuzz / libFuzzer) of the parsers in `affinidi-trust-lists`
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
| `xml` | `parse_trust_list_xml`, then loading into a `TrustListRegistry` and certificate lookups |
| `certificate` | `x509::parse_certificate`, `is_self_signed`, `extract_public_key` |

## Corpus / seeds

Read-only seeds live in `seeds/<target>/`: The XML samples from the crate's unit tests, a list carrying the test certificate, and `tests/fixtures/test_cert.der`. The live libFuzzer
`corpus/` is gitignored.

## Running

```sh
mkdir -p corpus/xml
cargo +nightly fuzz run xml corpus/xml seeds/xml -- -max_total_time=60
```

CI runs a short pass per target on PRs touching this crate and a longer pass
nightly (`.github/workflows/fuzz.yaml`). The committed `Cargo.lock` pins the
crates.io graph; `scripts/check-fuzz-lock.sh` fails if it drifts.

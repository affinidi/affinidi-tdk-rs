# affinidi-mdoc fuzz targets

Coverage-guided fuzzing (cargo-fuzz / libFuzzer) of the parsers in `affinidi-mdoc`
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
| `issuer_signed` | `IssuerSigned::from_cbor_bytes`, then digests, `x5chain`, validity window, attribute lookup, re-encoding |
| `device_response` | `DeviceResponse::from_cbor_bytes` (including `deviceSigned`), then digests, `x5chain`, validity window, disclosed names, re-encoding |
| `engagement` | `DeviceEngagement::from_cbor_bytes` and `CoseKey::from_cbor_bytes`, re-encoding what decodes |

## Corpus / seeds

Read-only seeds live in `seeds/<target>/`: Hand-built ISO 18013-5 structures with correct item digests and placeholder signatures and certificate bytes. The live libFuzzer
`corpus/` is gitignored.

## Running

```sh
mkdir -p corpus/issuer_signed
cargo +nightly fuzz run issuer_signed corpus/issuer_signed seeds/issuer_signed -- -max_total_time=60
```

CI runs a short pass per target on PRs touching this crate and a longer pass
nightly (`.github/workflows/fuzz.yaml`). The committed `Cargo.lock` pins the
crates.io graph; `scripts/check-fuzz-lock.sh` fails if it drifts.

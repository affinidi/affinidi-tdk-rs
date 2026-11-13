# affinidi-status-list fuzz targets

Coverage-guided fuzzing (cargo-fuzz / libFuzzer) of the parsers in `affinidi-status-list`
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
| `bitstring` | `BitstringStatusList::decode` (base64url + capped GZIP inflation) at a declared size, then reads |
| `token` | `VerifiedStatusListToken::verify` past an accept-all signature callback (claims, capped ZLIB inflation), `status_of`, and `StatusListReference::from_claims` |

## Corpus / seeds

Read-only seeds live in `seeds/<target>/`: Encoded lists and status list JWTs produced with the standard library's gzip/zlib. The live libFuzzer
`corpus/` is gitignored.

## Running

```sh
mkdir -p corpus/bitstring
cargo +nightly fuzz run bitstring corpus/bitstring seeds/bitstring -- -max_total_time=60
```

CI runs a short pass per target on PRs touching this crate and a longer pass
nightly (`.github/workflows/fuzz.yaml`). The committed `Cargo.lock` pins the
crates.io graph; `scripts/check-fuzz-lock.sh` fails if it drifts.

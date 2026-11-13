# affinidi-messaging-didcomm-v1 fuzz targets

Coverage-guided fuzzing (cargo-fuzz / libFuzzer) of the parsers in `affinidi-messaging-didcomm-v1`
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
| `unpack` | `DIDCommV1Agent::unpack` (envelope detection, protected header, recipient match, CEK unwrap, decryption, message decode) with a fixed identity and peer; forward messages are read too |

## Corpus / seeds

Read-only seeds live in `seeds/<target>/`: Well-formed authcrypt / anoncrypt envelopes addressed to the fixed identity (their ciphertext is not valid), a plaintext and a forward message. The live libFuzzer
`corpus/` is gitignored.

## Running

```sh
mkdir -p corpus/unpack
cargo +nightly fuzz run unpack corpus/unpack seeds/unpack -- -max_total_time=60
```

CI runs a short pass per target on PRs touching this crate and a longer pass
nightly (`.github/workflows/fuzz.yaml`). The committed `Cargo.lock` pins the
crates.io graph; `scripts/check-fuzz-lock.sh` fails if it drifts.

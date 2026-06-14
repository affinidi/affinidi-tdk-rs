# affinidi-messaging-didcomm fuzz targets

Coverage-guided fuzzing (cargo-fuzz / libFuzzer) of the DIDComm envelope layer
(issue #477). This is a **standalone workspace** detached from the parent so the
nightly requirement never touches the stable `1.95.0` workspace pin.

## Requirements

cargo-fuzz needs **nightly** (the parent pins stable). Either:

```sh
rustup toolchain install nightly
cargo install cargo-fuzz --locked
```

Run everything from this `fuzz/` directory. Use `cargo +nightly fuzz …` (or set
`RUSTUP_TOOLCHAIN=nightly`) to override the repo's stable toolchain file.

## Targets

| Target               | Exercises                                                      |
|----------------------|---------------------------------------------------------------|
| `unpack`             | Full `message::unpack::unpack` — format detect → decrypt/verify → parse, with the fixed recipient/sender/signer keys |
| `decrypt`            | `jwe::decrypt::decrypt` directly (header → ECDH → key-unwrap → AEAD) |
| `message`            | Plaintext `Message::from_json` on raw bytes                    |
| `message_structured` | Structure-aware: an `Arbitrary`-built `Message` (didcomm `arbitrary` feature) serialized and re-parsed |

## Corpus / seeds

Committed read-only seeds live in `seeds/<target>/`; the live, mutable libFuzzer
corpus (`corpus/`) is gitignored. Regenerate the seeds with:

```sh
cargo +nightly run --bin gen_corpus
```

Seeds are valid envelopes addressed to fixed deterministic keys (see
`src/lib.rs`), so they decrypt/verify and the fuzzer starts past the AEAD /
signature gates. They are not byte-stable across regenerations (encryption draws
a fresh ephemeral key + IV), only always-valid.

## Running

Pass the live corpus dir first (writable, created on demand) then the read-only
seeds:

```sh
mkdir -p corpus/unpack
cargo +nightly fuzz run unpack corpus/unpack seeds/unpack -- -max_total_time=60
```

CI runs a short pass of every target on PRs that touch this crate and a longer
pass nightly (see `.github/workflows/fuzz.yaml`).

> External harnesses wanting richer, seed-parameterised fixtures can use
> `affinidi-tdk-test-support`'s `didcomm_fuzz` module instead; this crate keeps a
> minimal dependency graph so the sanitizer build stays fast.

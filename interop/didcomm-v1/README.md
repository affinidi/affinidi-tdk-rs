# DIDComm v1 interop harness (Credo)

A **developer-only** harness that round-trips DIDComm v1 envelopes between
`affinidi-messaging-didcomm-v1` and **Credo** — the reference implementation
every Aries-lineage wallet is built on.

It follows the precedent set by [`../`](..), the TSP interop harness: it is not
a Cargo target, CI never runs it, and its output is committed so CI needs no
Node.

```bash
cd interop/didcomm-v1
npm install
npm run generate
```

## What it does

**Direction 1 — Credo → Rust.** Drives a real Credo agent's
`DidCommEnvelopeService.packMessage` and writes the resulting envelopes to
`crates/messaging/affinidi-messaging-didcomm-v1/tests/fixtures/credo.json`.
Those committed bytes are what `tests/credo_interop.rs` opens **in CI** — the
security-critical direction, since it is where an attacker's input arrives.

**Direction 2 — Rust → Credo.** If `rust-envelopes.json` is present, opens each
of this crate's envelopes through Credo's own decryption path and reports
pass/fail per case. Produce that file first:

```bash
cargo test -p affinidi-messaging-didcomm-v1 --test credo_interop \
    -- --ignored emit_envelopes_for_credo
```

Expected output:

```
self-check: Credo reopened all of its own envelopes
wrote 5 Credo-generated cases
Credo opened 5/5 Rust envelopes
```

## Two things that will otherwise waste your afternoon

**The askar backend must be registered before Credo is imported.** Credo's ESM
build imports `askar` as a named export from the CJS `askar-shared` package, and
that binding is snapshotted when the module is first evaluated. `registerAskar`
assigns to `exports.askar` at runtime, so registering afterwards leaves Credo
holding `undefined` and failing deep inside the KMS with `Cannot read properties
of undefined (reading 'keyGetJwkSecret')`. That is why `run.mjs` exists and why
`generate.mjs` must not be run directly. The same failure appears as
`(reading 'storeOpen')` when `askar-nodejs` and `@credo-ts/askar` resolve
different `askar-shared` copies — keep them on the same major. That is why
`@openwallet-foundation/askar-nodejs` moves with `@credo-ts/askar`: 0.7.0
widened its peer to `^0.4.3 || ^0.5.0 || ^0.6.0`, so npm hoists the newest
while `askar-nodejs` 0.4.3 keeps bundling its own 0.4.3, and the two copies
are back.

**Credo cannot unpack an envelope without a matching DID record.** Its
`unpackMessage` starts by calling `extractOurRecipientKeyWithKeyId`, which
searches the agent's *created DID records* for one containing the recipient key.
A bare agent built from imported keys does not satisfy it — Credo cannot open
even its **own** envelopes that way, which is easy to misread as a bug in the
Rust packer. The harness therefore uses `unpackWithKnownKey`, a transcription of
Credo's private `decryptDidcommV1Message` with the recipient key supplied rather
than looked up. It skips exactly that wallet-state lookup and nothing else:
header parsing, the `alg`/`enc` checks, the authcrypt sender+iv requirement,
`ECDH-HSALSA20` + `XSALSA20-POLY1305`, and `C20P` with the base64url header as
AAD all still run through Credo and askar. A self-check asserts Credo reopens
its own envelopes through that path first, so a green result for the Rust
envelopes is not vacuous.

## Regenerating fixtures

`npm run generate` overwrites `credo.json` with fresh envelopes. The party keys
come from fixed seeds, so identities and verkeys are stable across runs, but the
ciphertext changes every time (fresh CEKs and nonces). Re-run
`cargo test -p affinidi-messaging-didcomm-v1` afterwards and commit both.

The `generator` block in each fixture records which Credo and askar produced
it, read from the installed packages rather than a literal — so it cannot
keep claiming a version that is no longer installed.

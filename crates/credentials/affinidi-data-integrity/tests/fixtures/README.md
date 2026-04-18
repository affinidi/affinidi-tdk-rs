# Data Integrity fixtures

Each `*.json` file in this directory contains a deterministic signed
document + proof produced by this crate at a known code revision.
The `fixtures.rs` integration test re-produces the proof from the
stored inputs and asserts byte-for-byte equality with the stored
output.

## What this catches

Any behavioural regression in the sign pipeline that *shouldn't* change
bytes: canonicalization quirks, multicodec mix-ups, hash ordering,
timestamp formatting, `proofValue` encoding, Ed25519-to-X25519 seed
derivation, ML-DSA parameter-set dispatch.

## What this does not catch

Any regression that changes outputs *intentionally* — those will trip
the test and force the author to regenerate fixtures and justify why.
That's the point.

## Regenerating fixtures

Set `AFFINIDI_DATA_INTEGRITY_REGEN_FIXTURES=1` and re-run the
`fixtures` integration test. The test will overwrite each fixture with
the new output. Commit the diff and document the behaviour change in
the PR.

## Fixture inputs are all deterministic

- `seed` — 32 bytes, hex-encoded.
- `document` — JSON.
- `created` — ISO-8601 UTC, seconds precision, `Z` suffix.
- `proof_purpose` — defaults to `assertionMethod`.

Nothing else influences the signature because all supported suites use
deterministic signing.

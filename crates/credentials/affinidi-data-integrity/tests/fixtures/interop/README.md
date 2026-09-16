# Interop fixtures

Proofs produced by **other** Data Integrity implementations, verified by this
crate in `tests/interop_verify.rs`.

These are not regenerated. Unlike the fixtures one directory up, which this
crate signs and re-signs, each file here is a byte-for-byte artifact from a
foreign signer, kept exactly as it was emitted, because the property under test
is that *this* verifier accepts what *that* signer produced. Regenerating one
from this crate would test the crate against itself.

They sit in a subdirectory so `tests/fixtures.rs`, which reads every top-level
`*.json` in `tests/fixtures/` as a sign fixture, does not pick them up.

## `affinidi-ssi-dart-eddsa-jcs-2022-nonce.json`

An `eddsa-jcs-2022` proof over a Trust Task document, signed by
[`affinidi-ssi-dart`](https://github.com/affinidi/affinidi-ssi-dart) using a
fresh `did:key` Ed25519 key via `DataIntegrityEddsaJcsGenerator`.

Why this producer: `affinidi-ssi-dart` sets `nonce` on **every** proof it emits,
so it is the case that exposed `DataIntegrityProof` dropping `nonce` before
re-hashing. `created` carries a `Z` because it was signed with the
`affinidi-ssi-dart` fix that emits a UTC dateTimeStamp (VC Data Integrity §2.1);
before that fix its `created` had no timezone and could not be read here at all.

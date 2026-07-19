# Affinidi TDK Test Support

## Changelog history

## 19th July 2026

### 0.8.1 — affinidi-did-common 0.4

- Bumped the `affinidi-did-common` requirement from `"0.3"` to `"0.4"`.
  No functional change to this crate: `Document` gained a typed
  `also_known_as` field, which is additive.

## 14th June 2026

### 0.7.0 — documented testing API + cookbook (TI6)

- **Published.** `publish` flipped to `true` — the fixture API stabilised with
  the TI-series and external consumers can now pull this in as a
  `dev-dependency` from crates.io. It remains a `0.x` testing crate (additive
  where possible; breaking changes get a minor bump + a `CHANGELOG` entry).
- **Stability.** The fixture config enums (`did_web::Fault`, `resolver::Outcome`)
  and the error enums (`ScenarioError`, `DeterminismError`, `VectorError`) are
  now `#[non_exhaustive]`, so new variants land additively. Match arms over them
  must carry a `_` wildcard.
- **Docs.** Each module now carries a runnable, CI-compiled (`cargo test --doc`)
  doc example of its happy path (`did_web` was the last one without). A
  copy-paste scenario cookbook spanning these fixtures, the embedded mediator
  (`affinidi-messaging-test-mediator`), and the language-agnostic
  `docker-compose.test.yml` path lives at `docs/testing/cookbook.md`.
- No behaviour change to any fixture.

### 0.6.0 — seeded did:peer generation (TI4a)

- `determinism`: deterministic `did:peer` identities. `did_peer_from_seed(seed,
  keys, service)` and the `didcomm_identity_from_seed(seed, service)` convenience
  (Ed25519 verification + X25519 encryption) derive their keys from a caller seed
  so **same seed → same DID, keys, and key ids** across runs — reproducible CI
  failures and golden-file assertions. The assembled DID and default `dm` service
  match `DID::generate_did_peer` byte-for-byte. `seeded_secret(key_type, &seed)`
  exposes the underlying primitive (Ed25519 / X25519 / P256 / Secp256k1).
  TEST-ONLY (seeded keys are predictable; never a production key path).
- TI4's injectable clock follows separately as TI4b (a `Clock` trait threaded
  through the mediator + SDK).

## 13th June 2026

### 0.5.0 — mdoc (COSE) + OID4VP present/verify flows (TI5b)

- `mdoc_scenario`: mdoc flows on `CredentialScenario` reusing the shared
  issuer/holder/verifier identities — `issue_mdoc` (MSO signed with the issuer's
  EdDSA COSE key, holder key bound into `deviceKeyInfo`), `present_mdoc` /
  `present_mdoc_with_binding` (selective disclosure, optional device-auth holder
  binding), and `verify_mdoc` / `verify_mdoc_with_alg` (`verify_issuer_auth` with
  an EdDSA algorithm allowlist + digest checks). `session_transcript()` yields a
  deterministic QR-engagement transcript for binding tests.
- `oid4vp`: OID4VP present/verify flows carrying both eIDAS mandatory formats
  through the authorization request/response envelope —
  `oid4vp_present_sd_jwt` / `oid4vp_verify_sd_jwt` (`vp_token` = SD-JWT compact
  serialization, KB-JWT bound to `client_id`/`nonce`) and `oid4vp_present_mdoc` /
  `oid4vp_verify_mdoc` (`vp_token` = base64url(CBOR) `DeviceResponse` transport).
  Envelope validation runs before the credential is cryptographically verified.
- `Party` gains the COSE accessors `cose_signer` / `cose_verifier` /
  `cose_signer_with_alg` / `device_cose_key`; `ScenarioError` gains `Mdoc` and
  `Oid4vp` variants. Closes the credentials/protocols e2e gap for both eIDAS
  formats (TI5 acceptance criteria).

### 0.4.0 — shared test-vector layout + loader (TI7)

- `vectors`: a documented `tests/vectors/<source>/…` convention plus a loader
  (`load_json`, `load_str`, `load_json_dir`, `vectors_root`) so interop vectors
  drop in without bespoke loader code. `affinidi-bbs` migrated onto it as the
  reference. Supports the BBS-signing KAT and JOSE-crypto vector work.

### 0.3.0 — CredentialScenario sd-jwt-vc fixture (TI5a)

- `credential_scenario`: `CredentialScenario` stands up deterministic
  issuer/holder/verifier `did:key` identities, an in-memory `BitstringStatusList`,
  and a `StaticResolver` pre-populated with their DID documents. Helpers cover the
  SD-JWT VC `issue → present → verify` round trip plus the W4/W5 negatives
  (status-list revocation, holder-binding failure, disallowed `alg`). Ships
  `Ed25519Signer` / `Ed25519Verifier` (the SD-JWT crate provides only an HMAC
  test signer); the verifier enforces an algorithm allowlist before the signature.

### 0.2.0 — did:web/webvh mock server + StaticResolver (TI2)

- `did_web::MockDidWebServer`: an in-process HTTP origin (ephemeral `127.0.0.1`
  port) serving `did.json` / `did.jsonl` (+ witness) with fault injection
  (`Delay`, `Hang`, `Status`, `Garbage`, `Oversize`) and per-path request
  counts. `webvh_authority()` yields `localhost%3A<port>` for minting
  `did:webvh` DIDs that resolve over HTTP.
- `resolver::StaticResolver`: a deterministic, fault-injecting `AsyncResolver`
  with per-DID outcomes (`Resolves`, `Fails`, `NotHandled`, `Delays`, `Hangs`)
  and a recorded call log for cache-stampede / dedup assertions.
- Unblocks the W1/W2/W3 cache-server/SDK hardening regression tests.

### 0.1.0 — scaffold (TI0)

- New `affinidi-tdk-test-support` crate: the shared home for cross-cutting,
  in-process integration-test fixtures across the TDK workspace, complementing
  the mediator-specific `affinidi-messaging-test-mediator`.
- Scaffold only — `publish = false`, no fixtures yet. Establishes the crate, its
  workspace membership, and CI coverage so each TI-series harness lands as a
  thin, self-contained PR. First fixture (the did:web mock server) arrives in
  TI2.

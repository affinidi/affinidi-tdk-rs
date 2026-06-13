# Affinidi TDK Test Support

## Changelog history

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

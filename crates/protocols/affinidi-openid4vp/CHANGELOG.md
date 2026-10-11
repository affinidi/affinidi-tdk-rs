# Affinidi OpenID4VP Changelog

## Unreleased (0.1.4) — OpenID4VP 1.0 verifier pieces

Additive: the verifier side of OpenID4VP 1.0, beside the existing pre-1.0 and
Presentation Exchange types, which are unchanged.

- `client_id` — `ClientId` / `ClientIdPrefix` (§5.9): build and parse prefixed
  client identifiers (`decentralized_identifier:`, `x509_hash:`,
  `x509_san_dns:`, …). `ClientId::x509_hash` computes the base64url SHA-256 of
  the leaf certificate's DER. `Display` is the full identifier, prefix
  included — the audience a key-binding proof names. An unprefixed identifier
  is refused.
- `request_object` — `RequestObject` with the 1.0 members (`response_uri`,
  `dcql_query`, `client_metadata` with `jwks` and
  `encrypted_response_enc_values_supported`, `verifier_info`), the
  `direct_post_jwt` constructor, `validate` (prefixed `client_id`, a nonce, an
  `https` `response_uri`, an encryption key and `enc` value), `sign` — a JAR,
  `typ: oauth-authz-req+jwt`, the key named by `kid` or `x5c`, with profile
  header members (`JarHeader::extra`, e.g. swiyu's `profile_version`) — and
  `wallet_invocation_uri` (`<scheme>://?client_id=…&request_uri=…`).
- `response` (feature `direct-post-jwt`) — `receive_direct_post_jwt`: reads the
  form a wallet posts to `response_uri`, decrypts `response=<JWE>` with the
  caller's `EcdhEsDecryptionKey` and allowed `enc` values, or returns the
  wallet's clear error (`error`, `error_description`, `state`). The decrypted
  `vp_token` is the 1.0 map from credential query id to presentations; the
  pre-1.0 bare `vp_token` is refused.
- `DcqlQuery::evaluate_presentation` — the verifier's mirror of
  `match_credentials`: whether verified presentations satisfy the query. Every
  presentation must meet its query (format, `meta`, holder binding, `claims`,
  `claim_sets`); an id the query did not ask for, or a repeat without
  `multiple`, is refused; required `credential_sets` need an answered option.

Requires `affinidi-oid4vc-core` 0.1.10.

## 14th June 2026 Release 0.1.3

- `Oid4vpError` is now `#[non_exhaustive]` (ADR-0003) so new variants land
  additively. Patch bump keeps the `0.1` pin valid; consumers that `match` it
  must add a `_` wildcard arm. No behaviour change. (W7 sweep)

# Changelog

All notable changes to `affinidi-did-common` are documented here. The
format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this crate follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.4] - 2026-05-31

### Added

- `VerificationMethod::decode_public_key() -> (multicodec, bytes)` —
  a single decoder for verification material that handles both
  `publicKeyMultibase` (Multikey) and `publicKeyJwk` (via
  `affinidi-crypto`), returning the multicodec + raw key bytes (32 octets
  for Ed25519/X25519, uncompressed SEC1 for the EC curves). This is the
  shared source of truth used by the messaging SDK and the
  DID-authentication layer, replacing their previously-duplicated
  JWK/multibase parsing (which had drifted — see the ECDH-1PU interop
  work in `affinidi-messaging-didcomm` 0.14).

# Affinidi VC Changelog

## 13th June 2026 (0.1.2)

Semver wave (W7/W10 — release W11). `VcError`, `VerifiableCredential`, and
`CredentialStatus` are now `#[non_exhaustive]`: match `VcError` with a wildcard
arm; obtain the structs via deserialization/issuance (fields stay public for
reads). Patch bump — see
[ADR 0003](../../../docs/adr/0003-public-api-semver-policy.md) and
[the migration guide](../../../docs/migration/2026-06-semver-wave.md).

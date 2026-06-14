# Affinidi VC Changelog

## 14th June 2026 (0.2.1)

`SdJwtVcError` is now `#[non_exhaustive]` (ADR-0003), completing the sealing the
W7 wave started on `VcError`. Patch bump keeps the `0.2` pin valid; match it with
a `_` wildcard arm. No behaviour change. (W7 sweep)

## 13th June 2026 (0.1.2)

Semver wave (W7/W10 — release W11). `VcError`, `VerifiableCredential`, and
`CredentialStatus` are now `#[non_exhaustive]`: match `VcError` with a wildcard
arm; obtain the structs via deserialization/issuance (fields stay public for
reads). Patch bump — see
[ADR 0003](../../../docs/adr/0003-public-api-semver-policy.md) and
[the migration guide](../../../docs/migration/2026-06-semver-wave.md).

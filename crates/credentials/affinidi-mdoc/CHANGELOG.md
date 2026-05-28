# Affinidi mdoc Changelog

## 28th May 2026 Release 0.2.0

### Security

- **HIGH — MSO `ValidityInfo` was parsed but never enforced.**
  `verify_issuer_auth()` and `verify_digests()` accepted an mdoc whose
  `validUntil` was years in the past. ISO/IEC 18013-5 §9.3.1 requires
  the reader to reject documents outside their validity window, and
  `MdocError::Expired` already existed (unused) for exactly this. New
  `ValidityInfo::check(now)` and `ValidityInfo::check_now()` methods
  parse the RFC 3339 timestamps and return `Expired` when `now` falls
  outside `[validFrom, validUntil]`. Verifiers MUST call this on the
  MSO returned from `IssuerSigned::verify_issuer_auth` — signature and
  digest checks alone do not establish current validity.

### Breaking

- **`MdocError::Expired` is now `Expired(String)`** (was a unit variant).
  The variant existed but was unused, so no in-workspace consumer is
  affected; out-of-workspace callers pattern-matching on the unit form
  must update to the tuple form, e.g.
  `Err(MdocError::Expired) => …` becomes
  `Err(MdocError::Expired(_)) => …`. The carried string describes which
  bound was crossed (not-yet-valid vs. expired) and the offending
  timestamp.

### Dependencies

- Adds `time = "0.3"` (with `parsing` feature) — already in the workspace
  via `affinidi-messaging-sdk`.

### Tests

- `validity_info_check_within_window` — in-window passes.
- `validity_info_check_expired` — `now > validUntil` returns `Expired`.
- `validity_info_check_not_yet_valid` — `now < validFrom` returns `Expired`.
- `validity_info_check_malformed` — non-RFC-3339 timestamps return
  `InvalidMso`.

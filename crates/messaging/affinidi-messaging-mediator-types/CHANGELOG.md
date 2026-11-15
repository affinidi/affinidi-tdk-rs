# Affinidi Messaging Mediator Types

## [0.1.2] - 2026-11-15

`MediatorACLSet::from_u64` clears unassigned bits

Bits 19-63 of an ACL value are unassigned and documented as "must stay zero",
but `from_u64` (and so `from_hex_string`) kept them, so two values enforcing
the same ACL compared unequal and the stray bits round-tripped. They are now
cleared (#1027). A value with only assigned bits is unaffected. `Deserialize`
still accepts whatever `acl` the JSON holds; that is tracked with the
`MediatorACLSet` wire-format follow-up (#1141).


## [0.1.1] - 2026-11-10

audit actions for DID multiplexing

Three new `AuditAction` values, so the mediator can audit what the
`messaging/mux/*` specs require it to:

- `mux_grant_revoke`: a grant was revoked (`messaging/mux/revoke`).
- `mux_revoke_all`: a member DID voided an epoch (`messaging/mux/revoke-all`).
- `mux_grant_suspend`: the unknown-key rule suspended a grant.

`AuditAction` is `#[non_exhaustive]`, so this is additive.

## [0.1.0] - 2026-10-13

the mediator protocol types, as a crate of their own

The `types` module of `affinidi-messaging-mediator-common` 0.17.6 (ACLs,
accounts, audit, message pickup, problem reports, `Clock`), as its own crate.
The mediator is moving to its own repository; this crate stays with the SDK as
the contract between the two, so neither repository depends on the other.

This release only publishes the crate. Nothing depends on it yet: the next
releases of `affinidi-messaging-mediator-common` (which re-exports it as
`types`) and `affinidi-messaging-sdk` switch to it, which a new crate has to be
on crates.io before they can.

`SystemClock` does not depend on mediator-common's `server`-gated `time`
helpers. It reads the system clock directly and falls back to 0 before the
UNIX epoch, as before; the error log for that fallback is behind the new
`tracing` feature.

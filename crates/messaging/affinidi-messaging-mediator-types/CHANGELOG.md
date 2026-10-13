# Affinidi Messaging Mediator Types

## 0.1.0 — the mediator protocol types, as a crate of their own

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

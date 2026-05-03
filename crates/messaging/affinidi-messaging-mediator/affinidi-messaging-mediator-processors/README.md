# affinidi-messaging-mediator-processors

[![Rust](https://img.shields.io/badge/rust-1.90.0%2B-blue.svg?maxAge=3600)](https://github.com/affinidi/affinidi-tdk-rs/tree/main/crates/affinidi-messaging/affinidi-messaging-mediator/affinidi-messaging-mediator-processors)
[![License](https://img.shields.io/badge/license-Apache--2.0-green.svg)](https://github.com/affinidi/affinidi-tdk-rs/blob/main/LICENSE)

Standalone background processors for the Affinidi Messaging Mediator.
These binaries run as separate processes from the mediator and are
intended for **horizontal scaling**: deploy additional instances onto
extra hosts and they coordinate through Redis to share work.

## Redis-only by design

Multi-process / multi-host coordination is built on Redis primitives:

- **Forwarding processor** — Redis Streams consumer groups
  (`XREADGROUP` / `XACK` / `XAUTOCLAIM`) for at-least-once delivery
  across competing consumers.
- **Message expiry cleanup** — atomic `SPOP` on expiry-timeslot sets
  so multiple processors drain the same timeslot without duplicating
  work.

Memory and Fjall storage backends are single-process by definition
and have no equivalent multi-host coordination, so these binaries
only make sense for Redis-backed deployments.

If you don't need horizontal scaling, you don't need this crate. The
mediator runs the same workloads in-process via the
[`MediatorStore`](../affinidi-messaging-mediator-common/src/store/mod.rs)
trait against any backend — Redis, Fjall, or Memory.

## Processors

### message_expiry_cleanup

Removes messages whose expiry timestamp has passed. Compatible with
the in-process expiry sweep — multiple instances of this binary can
run alongside the mediator's own sweep without duplicating deletes.

### forwarding_processor

Reads queued messages from `FORWARD_Q` and delivers them to remote
mediators (HTTP POST or WebSocket). Multiple instances coordinate via
the consumer group so each message is processed exactly once.

## Crate layout

```
src/lib/              Shared library code
  src/lib/<processor>  Processor-specific implementation
src/<processor>/       Binary entry point
conf/<processor>.toml  Configuration template
```

## Related crates

- [`affinidi-messaging-mediator`](../) — parent mediator service
  (runs the same workloads in-process via `MediatorStore`)
- [`affinidi-messaging-mediator-common`](../affinidi-messaging-mediator-common)
  — shared types including the `MediatorStore` trait

## License

[Apache-2.0](https://github.com/affinidi/affinidi-tdk-rs/blob/main/LICENSE)

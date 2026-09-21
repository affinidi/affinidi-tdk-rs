# Changelog

## Unreleased (0.1.0) — first release

The headless engine behind the mediator console:

- `MediatorConsole::connect` / `connect_with` connects as an `Identity` and
  discovers the mode (`Admin { root }` or `SelfService`) and `Capabilities`
  from the mediator's record of the account. The mediator is found from the
  DID's `DIDCommMessaging` service when not given.
- `IdentitySource`, with `ProfileFileSource` (TDK profile JSON, as
  `mediator-setup` writes it) and `StaticIdentities`. VTA-backed sources live
  with the VTA.
- Mediator-wide views for administrators: `stats`, `queues`, `accounts`,
  `audit`, `config`. Per-account operations for self or any account:
  `account_of`, `queue_status`, `messages`, `inspect` (raw envelope, opened
  locally when the session can decrypt it), `delete`, `update_account`.
- Two-step purges: `purge_preview` returns a `PurgePlan`; `purge` refuses with
  `PlanStale`, removing nothing, if the queue changed since the preview.
- `monitor` opens a `MonitorFeed` of live traffic metadata that renews its lease,
  reports sequence gaps and heartbeats, and unsubscribes on drop. One task owns
  the connection's live stream and routes monitor batches by subscription.

Requires `affinidi-messaging-sdk` 0.26.19 and a mediator serving the
`messaging/*` operations tasks (`affinidi-messaging-mediator` 0.28.20).

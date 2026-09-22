# Changelog

## Unreleased (0.1.2) — say plainly when the mediator is too old

- **New:** `MediatorConsole::mediator_version()` reports the version read from
  the mediator's public `readyz` endpoint at connect.
- **New:** `serves_operations()` says whether that version is at least
  `OPERATIONS_SINCE` (0.28.20). When the version can't be read, it's assumed
  to be recent enough, and the mediator answers for itself.
- **Changed:** on an older mediator, statistics, the queue ranking and queue
  status, message listing, reading and deleting, purges and the monitor
  return `Refused(protocol.trust_task.unsupported)` at once, naming both
  versions.
  - Before, those requests were sent anyway. An older mediator doesn't
    answer them, so every call waited out the SDK's 10-second reply timeout
    and failed with "No response from API". (Mediator 0.28.26 also fixes the
    general case: any refusal now answers its request.)
  - Account, access-list, audit and configuration calls are unaffected.

## Unreleased (0.1.1) — finding the mediator in a map-form service

`MediatorConsole::connect` now finds the mediator in a `DIDCommMessaging`
service written in the map or array form
(`[{ "uri": "did:…", "accept": [...] }]`), which is how VTA-managed DIDs
publish it. `affinidi-did-common` 0.4.2 (the version on crates.io) returns
that `uri` JSON-quoted, so the mediator DID was missed and `connect` failed
with `no mediator for …`. `affinidi-did-common` 0.4.3 fixes this at the source,
and the console now also accepts the quoted form, so it works whichever of
the two a build resolves.

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

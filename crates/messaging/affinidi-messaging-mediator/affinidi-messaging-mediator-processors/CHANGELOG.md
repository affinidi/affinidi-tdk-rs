# Affinidi Messaging Mediator Processors

## Unreleased (0.14.1) — `functions_file` resolves against the config file

Both processors resolve `functions_file` the way the mediator now does:
relative to the configuration file, with the working-directory fallback and a
deprecation warning. They load configuration independently of the mediator, so
without this the two would disagree about where the same config file's Lua
functions live. Requires `mediator-common` 0.16.12 for `config_path`.

## Unreleased (0.14.0) — TSP Rev 3: `mediator-common` 0.16

No source change in this crate. It takes a minor for the same reason
`mediator-config` does: it carries `mediator-common` types, and
`ForwardQueueEntry::to_did` may now be empty under Rev 3 §5.3.3, which forbids
an intermediary retaining a relayed endpoint-to-endpoint destination. A
processor that read that field for a log line will now read `""`; nothing routes
on it.

Invisible to cargo-semver-checks, because no signature moves in either crate.

## Changelog history

## 5th May 2026

### 0.13.1

- **CHORE:** Bumped internal pin on
  `affinidi-messaging-mediator-common` to `0.15` to track the
  feature-gating rework. The processors enable `redis-backend`
  (which now implies the `server` umbrella), so no source change
  is needed.

## 24th April 2026

### 0.13.0

- **CHORE:** Bumped internal pin on
  `affinidi-messaging-mediator-common` to `0.13` (new cloud
  backends + schema change on `AdminCredential`). Processor code
  itself is unchanged apart from the `lru` dep bump below — the
  version bump exists to move the workspace in lockstep.
- **CHORE:** `lru` dependency `0.12 → 0.17`. Five major bumps,
  but the `LruCache::new(NonZeroUsize)` / `get` / `get_mut` /
  `put` signatures used by the forwarding processor stayed stable
  across the span; no code change needed.

## 28th March 2026

### 0.12.3

- **FIX:** Replaced `deadpool-redis` with direct `redis` crate dependency
  - Forwarding processor now uses dedicated blocking connection for XREADGROUP
  - Fixes spurious timeout errors from redis 1.x's 500ms default response timeout
- **CHORE:** Cleaned up message expiry cleanup processor logging
  - No longer logs every second when idle

### 0.12.2

- **CHORE:** Normalized `affinidi-messaging-mediator-common` version specifier
  to `major.minor` format

## 5th March 2026

### 0.12.1

- **CHORE:** Bumped dependencies
  - `deadpool-redis` upgraded from `0.22` to `0.23`
  - `tokio` upgraded from `1.49` to `1.50`

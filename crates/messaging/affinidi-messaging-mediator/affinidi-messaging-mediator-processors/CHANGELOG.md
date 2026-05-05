# Affinidi Messaging Mediator Processors

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

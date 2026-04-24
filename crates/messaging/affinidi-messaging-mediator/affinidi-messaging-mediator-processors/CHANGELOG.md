# Affinidi Messaging Mediator Processors

## Changelog history

## 24th April 2026

### 0.14.0

- **CHORE:** Bumped internal pin on
  `affinidi-messaging-mediator-common` to `0.14` (new cloud
  backends + schema change on `AdminCredential`). Processors
  themselves are unchanged in this release — the version bump
  exists only to move the workspace in lockstep.

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

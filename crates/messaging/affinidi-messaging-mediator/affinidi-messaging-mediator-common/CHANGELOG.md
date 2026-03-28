# Affinidi Messaging Mediator Common

## Changelog history

## 28th March 2026

### 0.12.3

- **FIX:** Replaced `deadpool-redis` connection pool with direct `redis` crate
  `ConnectionManager` (auto-reconnecting multiplexed connection)
  - Fixes XREADGROUP BLOCK timeout errors caused by redis 1.x's 500ms default
    response timeout conflicting with blocking commands
  - `DatabaseHandler` now uses `ConnectionManager` for normal operations and a
    dedicated `MultiplexedConnection` (no response timeout) for blocking commands
  - `database_timeout` config now maps to `ConnectionManagerConfig` response/connection timeouts
  - `database_pool_size` config is deprecated and ignored
- **CHORE:** Upgraded `redis` from `1.0` to `1.1` with `connection-manager` feature

## 10th March 2026

### 0.12.2

- **CHORE:** Updated import paths (`affinidi_didcomm` → `affinidi_messaging_didcomm`)

## 5th March 2026

### 0.12.1

- **CHORE:** Updated Redis dependencies
  - `redis` upgraded from `0.32` to `1.0`
  - `deadpool-redis` upgraded from `0.22` to `0.23`

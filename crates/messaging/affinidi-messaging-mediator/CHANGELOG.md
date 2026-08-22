# Changelog

## [0.18.21] - 2026-08-22

### Fixed

- **A websocket close now states why**, so a refused duplicate connection stops
  reading as a network fault.

  `WebSocketCommands::Close` carried no reason, so the handler answered all three
  of its senders identically — the `duplicate-channel` problem report and the
  close reason `"replaced by a newer connection"`:

  - the incumbent, displaced by a newer connection — true;
  - a newcomer **refused** by the duel damper, whose own connection was never
    displaced and whose peer kept the slot — the inverse of true;
  - a session that reached registration with no authenticated DID — not a
    duplicate at all.

  A refused client was told it had been replaced, so the most it could honestly
  render was "the connection dropped". Two app instances presenting one DID
  therefore looked like a transport problem.

  `Close` now carries a `CloseReason`, and each maps to its own problem-report
  code and close reason:

  | Reason | Problem-report code | Close reason |
  |---|---|---|
  | `Replaced` | `w.websocket.duplicate-channel` | `replaced by a newer connection` |
  | `Refused` | `w.websocket.duplicate-channel-refused` | `this DID already has a live connection` |
  | `Unauthenticated` | `w.websocket.unauthenticated-session` | `session has no authenticated DID` |

  **`duplicate-channel` is preserved verbatim** for `Replaced`: it is the code
  existing clients already match on, and that socket is the one whose meaning
  never changed. Clients keying on it need no change.

  The eviction *policy* is deliberately untouched — newest-wins on an isolated
  duplicate still lets a client reclaim a half-open slot, the duel damper still
  holds the slot for a live incumbent, and displacement still triggers the
  stored-mail re-cover. The defect was never the policy; it was that the
  policy's outcome was unsayable.

## [0.18.20] - 2026-08-19

### Changed

- **Track `trust-tasks-rs` 0.11.0**, up from 0.9.0. Both releases in between are
  additive — new task families, no change to any type this crate uses — so
  nothing here had to move but the requirement:

  - **0.10.0** added the `vta/contexts/*` and `vta/webvh/*` families (the
    did:webvh lifecycle: DIDs, hosting servers, agent names) and the eight
    `vta/services/*` families that supersede a VTA's `/services/*` REST routes.
  - **0.11.0** corrected two of those `vta/services/*` schemas after writing the
    handlers found them unable to express the operation: rollback can
    legitimately publish no log entry, and disable takes a drain window the
    agent may refuse to honour.

  The reason to take it here is that a VTA cannot: `vta-sdk` must speak the same
  `trust-tasks-rs` these crates do, because `acl_setup` builds a `MediatorAcl`
  and hands it to `TrustTasks::account_update`. Two semver-incompatible copies
  make that a type error, so the VTA stays on 0.9 until this workspace moves.

  A second `trust-tasks-rs` 0.9 remains in the lockfile via this crate's
  `vta-sdk` dependency, and both coexist cleanly — no `trust-tasks-rs` type
  crosses that boundary. It clears when VTI ships a `vta-sdk` built on 0.11.



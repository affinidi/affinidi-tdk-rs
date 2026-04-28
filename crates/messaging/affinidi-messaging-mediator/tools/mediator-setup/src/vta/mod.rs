//! Wizard-side VTA integration: TUI state machine + thin adapters over
//! the SDK's [`vta_sdk::provision_client`] surface.
//!
//! The SDK owns the wire protocol (resolve → enumerate → dispatch →
//! sealed-bundle open) and ships its own diagnostics + event channel
//! shapes. This module re-exports the SDK types the wizard consumes,
//! plus the wizard-only state-machine types ([`VtaConnectState`],
//! [`ConnectPhase`], [`VtaSession`], the 3-variant [`VtaIntent`] /
//! [`VtaReply`] enums that span the online + offline sealed-handoff
//! sub-flows).
//!
//! Phase machine:
//!   `EnterDid` → `EnterContext` → (FullSetup) `EnterMediatorUrl` →
//!   `AwaitingAcl` → `Testing` → either `Connected`, the
//!   `TransportFallbackPrompt` (interactive [F]/[R]/[O]/[B] choice
//!   when the alternate transport is still viable), or the
//!   `RecoveryPrompt` (post-auth failure, exhausted attempts, or
//!   no advertised transport).
//!
//! `[O] Offline` from either prompt drops the operator into the
//! sealed-handoff sub-flow with `vta_did` / `context_id` /
//! `mediator_url` carried over.

pub mod cli;
pub mod intent;
pub mod runner;
pub mod session;
pub mod state;

// ── Local TUI-state types ────────────────────────────────────────────
pub use intent::{VtaIntent, VtaReply, VtaTransport};
pub use runner::run_connection_test;
pub use session::VtaSession;
pub use state::{ConnectPhase, FallbackOptions, OfflineReason, RecoveryOptions, VtaConnectState};

// ── SDK re-exports — use these via `crate::vta::*` so consumers
// stay decoupled from the upstream module path. Only the items the
// wizard actually consumes are surfaced here; the rest stay reachable
// via the canonical `vta_sdk::provision_client::*` path for the few
// call sites that need them. ──────────────────────────────────────────
pub use vta_sdk::provision_client::{
    AttemptResult, AttemptResultKind, DiagCheck, DiagEntry, DiagStatus, EphemeralSetupKey,
    Protocol, ProvisionResult, ResolvedVta, VtaEvent, pending_list,
};

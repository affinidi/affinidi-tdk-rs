# TODO — Transport Fallback for VTA-Connect

Spec: `crates/messaging/affinidi-messaging-mediator/tools/mediator-setup/SPEC.md`
Plan: `tasks/transport-fallback-plan.md`

## Slice 0 — Foundations

- [x] **0.1** Split `DiagCheck::Authenticate` → `AuthenticateDIDComm` + `AuthenticateREST`. Update runner emits + UI labels. _(commit 78333a8)_
- [x] **0.2** Extract `run_didcomm_attempt(...)` private fn out of `run_connection_test`. Define `AttemptOutcome` + `AttemptError` with explicit pre-auth / post-auth boundary. _(commit 9024332)_
- [x] **Checkpoint:** existing tests + manual DIDComm-only happy path green. Tag `slice-0-complete`.

## Slice 1 — REST-only VTA path

- [x] **1.1** `run_rest_attempt_admin_only` via `session::challenge_response`. Returns `VtaReply::AdminOnly`. _(commit 34d4f4f — used `session` instead of `auth_light` because the lightweight packer only handles did:key VTAs)_
- [x] **1.2** `run_rest_attempt_full_setup` via authenticated `VtaClient::provision_integration`. Reuse sealed-bundle opener. Returns `VtaReply::Full`. _(commit cb6034c — happy-path test deferred to Slice 5; failure-path tests landed)_
- [x] **1.3** `select_initial_transport()` orchestrator + fix `EnumerateServices` to be `Ok` whenever any transport is advertised. Remove the no-DIDComm hard-fail. _(commit 07cb2ea)_
- [x] **Checkpoint:** REST-only VTA fixture reaches `Connected` end-to-end (unit-tested via select_initial_transport + REST attempt fns; live mock-VTA integration test lands in Slice 5). AC-2 satisfied. Tag `slice-1-complete`.

## Slice 2 — Recovery prompt + sealed-handoff transition

- [x] **2.1** Add `AttemptLog` state + `ConnectPhase::RecoveryPrompt` + `recovery_options()` helper. Pure logic, unit-tested. _(commit 05c4bb8)_
- [x] **2.2** Render recovery panel — `[R]` / `[E]` / `[O]` / `[B]` with dim-out for unavailable options. Failure summary above. _(commit 131db05)_
- [x] **2.3** `[O] Offline` transitions into sealed-handoff with `vta_did`, `context_id`, `mediator_url` carried over. Reason banner on intro. _(commit 6d7b169)_
- [x] **Checkpoint:** no-transport scenario lands on recovery prompt and routes to sealed-handoff. Tag `slice-2-complete`.

## Slice 3 — DIDComm → REST fallback (interactive)

- [x] **3.1** Add `ConnectPhase::TransportFallbackPrompt` + `fallback_options()` helper. Unit-tested. _(commit c362d7e)_
- [x] **3.2** Render fallback panel — `[F]` / `[R]` / `[O]` / `[B]`. _(commit c362d7e — reuses recovery renderer)_
- [x] **3.3** Wire orchestrator: pre-auth failure → fallback prompt; post-auth failure → recovery prompt (skip fallback). `[F]` invokes `run_rest_attempt`. `[R]` re-spawns DIDComm. _(commit c362d7e)_
- [x] **Checkpoint:** dual-transport VTA with DIDComm killed → operator falls back to REST and reaches `Connected`. AC-5/AC-7 satisfied. Tag `slice-3-complete`.

## Slice 4 — Headless auto-fallback

- [x] **4.1** Auto-fallback in `vta_connect::cli::run_phase2_connect` (the actual headless online entry point). _(commit 604e817 — bootstrap_headless::dispatch is sealed-handoff-only and doesn't need fallback wiring)_
- [x] **4.2** Structured `HeadlessVtaError` with protocols attempted + sealed-handoff hint. _(commit 604e817)_
- [x] **4.3** Exit codes: `2` = no transport worked, `3` = VTA-side rejection, `0` = success. Documented in `--help`. _(commit 604e817)_
- [x] **Checkpoint:** AC-11 unit-tested via `auto_fallback_target` + `HeadlessVtaError` Display tests. End-to-end mock-VTA verification lands in Slice 5. Tag `slice-4-complete`.

## Slice 5 — Tests + cleanup

- [x] **5.1** Sweep unit-test coverage: `select_initial_transport_*`, `recovery_options_*`, `fallback_options_*`. _(commit 3183cb4 — already in place across slices)_
- [x] **5.2** Unit-test `AttemptLog` edge cases (retries, mixed pre/post-auth across transports). _(commit 3183cb4 — 3 new tests)_
- [ ] **5.3** Integration tests in mock-VTA harness — **deferred**. Needs a resolver-injection refactor to stub `resolve_vta` out of `run_connection_test`, which is broader than this feature's scope. Each component (REST attempt fns, orchestrator routing logic, recovery option helpers) is unit-tested independently.
- [ ] **5.4** Manual TUI walkthrough — **operator-driven**, document in PR description.
- [x] **5.5** Stale `vta_connect/mod.rs` module doc rewritten. `Protocol::Rest` and `AttemptOutcome::PostAuthFailure` `#[allow(dead_code)]` markers removed. `large_enum_variant` lints explicitly allowed with rationale. Two collapsible `if let` chains in `ui/recovery.rs` fixed. Pre-existing clippy warnings in the workspace remain — addressing them is broader than this feature. _(commit 3183cb4)_
- [x] **Checkpoint:** all spec ACs satisfied except integration tests (Slice 5.3, deferred) and manual TUI verification (Slice 5.4, PR-description). Tag `transport-fallback-complete`. Open PR.

## Pre-implementation confirmations

- [ ] Confirm `VtaClient` can be constructed from `(base_url, AuthResult)` without going through `integration::startup()`. If not, add a vta-sdk constructor first.
- [ ] Confirm the mock-VTA harness can serve `POST /bootstrap/provision-integration` with a real sealed bundle. If not, Slice 1 leans on manual verification.
- [ ] Operator review of fallback-prompt option ordering (`[F]` first vs `[R]` first).

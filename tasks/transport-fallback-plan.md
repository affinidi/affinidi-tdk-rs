# PLAN — Transport Fallback for VTA-Connect

**Spec:** `crates/messaging/affinidi-messaging-mediator/tools/mediator-setup/SPEC.md`
**Branch:** `fix/mediator-deployment`
**Status:** Draft, awaiting approval

## Dependency graph

```
Slice 0 — Foundations (no behaviour change)
  0.1 split DiagCheck::Authenticate → AuthenticateDIDComm / AuthenticateREST
  0.2 extract run_didcomm_attempt() out of run_connection_test
        │
        ▼
Slice 1 — REST-only VTA path (vertical: enumerate → auth → provision over REST)
  1.1 run_rest_attempt for AdminOnly  (challenge_response_light)
  1.2 run_rest_attempt for FullSetup  (VtaClient::provision_integration)
  1.3 orchestrator: REST-only branch + EnumerateServices Ok semantics
        │
        ▼
Slice 2 — Recovery prompt + sealed-handoff transition
  2.1 AttemptLog state + ConnectPhase::RecoveryPrompt
  2.2 render recovery prompt (dim unavailable options)
  2.3 wire [O] Offline → sealed_handoff with carry-over state
        │
        ▼
Slice 3 — DIDComm-first → REST fallback (interactive)
  3.1 ConnectPhase::TransportFallbackPrompt + state
  3.2 render fallback prompt
  3.3 orchestrator: pre-auth failure → fallback prompt; post-auth → recovery
        │
        ▼
Slice 4 — Headless auto-fallback
  4.1 bootstrap_headless auto-falls without prompting
  4.2 structured terminal-error format
  4.3 exit-code distinction: no-transport vs VTA-rejection
        │
        ▼
Slice 5 — Tests + cleanup
  5.1 unit: transport selector across all four endpoint combos
  5.2 unit: AttemptLog + recovery option-availability rules
  5.3 integration: mock-VTA REST-only and dual-with-DIDComm-killed fixtures
  5.4 manual TUI walkthrough
  5.5 remove DiagCheck::Authenticate alias, fix stale doc comment
```

Vertical slicing rationale: each slice is end-to-end (UI → state → runner → VTA) for one realistic operator scenario. After every slice the wizard runs and a real workflow completes.

## Slice 0 — Foundations

Refactor-only, no behaviour change. Existing happy path stays green.

### Task 0.1 — Split `DiagCheck::Authenticate`

**Files:** `vta_connect/diagnostics.rs`, `vta_connect/runner.rs`, `ui/diagnostics.rs`.

**Acceptance:**
- `DiagCheck` gains `AuthenticateDIDComm` and `AuthenticateREST` variants. `Authenticate` is removed (single-commit, internal-only).
- `DiagCheck::all()` returns: `[ResolveDid, EnumerateServices, AuthenticateDIDComm, AuthenticateREST, ListWebvhServers, ProvisionIntegration]`. The two `Authenticate*` rows are filtered out at `pending_list()` time based on which transports the VTA advertises (still seeded as `Pending` until we know — see Task 1.3 for the filter wiring; for this task, both rows are seeded and `AuthenticateREST` is set to `Skipped("DIDComm-only VTA")` by the runner during the transition window).
- Runner emits `AuthenticateDIDComm` events where it currently emits `Authenticate`. Existing detail strings unchanged.
- `ui/diagnostics.rs` row labels: "Authenticate via DIDComm" / "Authenticate via REST".

**Verification:**
- `cargo test -p affinidi-messaging-mediator-setup` — existing diagnostics test (`apply_update_sets_status_on_matching_check`) updated to use `AuthenticateDIDComm`.
- Manual: drive online VTA-connect against existing DIDComm-only fixture; checklist still shows green icons end-to-end.

### Task 0.2 — Extract `run_didcomm_attempt`

**Files:** `vta_connect/runner.rs`.

**Acceptance:**
- New private async fn `run_didcomm_attempt(intent, vta_did, mediator_did, setup_did, setup_privkey_mb, ctx, tx) -> AttemptOutcome` where `AttemptOutcome` enumerates `{ ConnectedAdmin(reply), PreflightOk{...}, PreAuthFailure(reason), PostAuthFailure(reason) }`.
- `run_connection_test` becomes thin: resolve → enumerate → call `run_didcomm_attempt` → forward outcome to existing event sender.
- Pre-auth vs post-auth boundary is explicit in `AttemptOutcome` — pre-auth is anything before the `DIDCommSession::connect` future resolves `Ok`; everything after is post-auth.
- No public-API change. `pub use runner::{VtaEvent, run_connection_test}` unchanged.

**Verification:**
- `cargo test -p affinidi-messaging-mediator-setup`.
- Manual: drive happy path; behaviour identical to before.

**Checkpoint:** Slice 0 ships as one PR or two atomic commits. Tag `slice-0-complete`. Confirm no regression before starting Slice 1.

## Slice 1 — REST-only VTA path

Activates the dormant `Protocol::Rest` path. Removes the AC-2 hard-fail. By the end of this slice, a REST-only VTA can complete provisioning.

### Task 1.1 — `run_rest_attempt` for AdminOnly

**Files:** new `vta_connect/runner_rest.rs` (split out so the runner module doesn't bloat past 1k lines), `vta_connect/runner.rs` (orchestrator hook).

**Acceptance:**
- Function signature: `async fn run_rest_attempt_admin_only(rest_url, vta_did, setup_did, setup_privkey_mb) -> Result<VtaReply, AttemptError>`.
- Implementation: build a `reqwest::Client`, call `vta_sdk::auth_light::challenge_response_light(...)`. If it returns an `AuthResult`, the setup DID is ACL-enrolled — wrap into `VtaReply::AdminOnly { admin_did: setup_did, admin_private_key_mb: setup_privkey_mb }`. The token is discarded (not persisted; the wizard's downstream code re-authenticates at runtime).
- All errors from `auth_light` map to `AttemptError::PreAuth(reason)` — there is no post-auth phase for AdminOnly.
- Emits `AuthenticateREST` `Running` → `Ok`/`Failed` events through the existing `VtaEvent` channel.

**Verification:**
- New unit test: stubbed `reqwest::Client` against a mock HTTP server that returns the canonical challenge/auth flow. Assert `VtaReply::AdminOnly` returned, setup DID echoed.
- New unit test: same harness, mock returns 401 → assert `AttemptError::PreAuth` with the body text.

### Task 1.2 — `run_rest_attempt` for FullSetup

**Files:** `vta_connect/runner_rest.rs`, `vta_connect/provision.rs` (extract opener).

**Acceptance:**
- Function signature: `async fn run_rest_attempt_full_setup(rest_url, vta_did, setup_did, setup_privkey_mb, ask: ProvisionAsk) -> Result<VtaReply, AttemptError>`.
- Implementation:
  1. `challenge_response_light` to get an `AuthResult`.
  2. Construct a `VtaClient` with `Transport::Rest` (base URL + token from step 1).
  3. Build `ProvisionIntegrationRequest` from `ProvisionAsk` (mirroring how `provision.rs::provision_mediator_integration` builds the DIDComm-side request — the VP body shape is the same; only the wire transport differs).
  4. Call `client.provision_integration(req)`.
  5. Decode the armored sealed bundle from the response, open it with the setup key's X25519 secret (re-use the existing opener in `provision.rs` — extract a private `open_template_bootstrap_bundle` helper if needed).
  6. Return `VtaReply::Full(ProvisionResult)` with the same shape the DIDComm path produces.
- Pre-auth boundary: failure during `challenge_response_light` or `VtaClient` construction → `PreAuth`. Post-auth boundary: failure inside `provision_integration` (HTTP non-2xx with auth-token-still-valid) or bundle-open failure → `PostAuth`.
- Emits `AuthenticateREST` and `ProvisionIntegration` rows through `VtaEvent`.

**Verification:**
- New unit test against a mock HTTP server returning a real sealed bundle (the `sealed_handoff.rs::tests` harness already produces these).
- Assert the resulting `VtaReply::Full` has the expected `admin_did`, `integration_did`, `summary.admin_rolled_over` fields.
- Assert `ProvisionResult` is shape-identical to what the DIDComm path produces (snapshot test or field-by-field).

### Task 1.3 — Orchestrator: REST-only branch + `EnumerateServices` semantics

**Files:** `vta_connect/runner.rs` (orchestrator).

**Acceptance:**
- New private fn `select_initial_transport(resolved: &ResolvedVta) -> InitialChoice` returns:
  - `BothAvailable` if `mediator_did.is_some() && rest_url.is_some()` → start with DIDComm.
  - `DIDCommOnly` if only DIDComm → start DIDComm; no REST fallback.
  - `RestOnly` if only REST → start REST; no DIDComm row in checklist (filter at `pending_list()` time).
  - `Neither` → emit `EnumerateServices` `Failed`, transition to `RecoveryPrompt` with only `[O] Offline` and `[B] Back` available (depends on Slice 2 — for now in Slice 1, route to a hard-fail with a sealed-handoff hint, same as today's behaviour for the no-DIDComm case).
- `EnumerateServices` row: `Ok` whenever at least one transport is advertised. Today it reports `Ok` only when DIDComm is present — fix that.
- Removes the AC-2 hard-fail. `cargo run --bin mediator-setup` against a REST-only fixture VTA reaches `Connected`.

**Verification:**
- New unit test: `select_initial_transport` for each of the four combinations.
- Integration test: mock-VTA REST-only fixture (built on existing harness) — drive AdminOnly and FullSetup intents, both reach `Connected`.
- Manual: spin up a REST-only test VTA, drive the wizard, confirm provision succeeds.

**Checkpoint:** Slice 1 ships. AC-2 from spec satisfied. Tag `slice-1-complete`.

## Slice 2 — Recovery prompt + sealed-handoff transition

Operator-facing path for "all online attempts exhausted, switch to offline". Built before fallback so the transition target exists before we wire fallback into it.

### Task 2.1 — `AttemptLog` state + `ConnectPhase::RecoveryPrompt`

**Files:** `vta_connect/mod.rs`.

**Acceptance:**
- New struct on `VtaConnectState`: `pub attempted: AttemptLog` with fields `didcomm: Option<AttemptResult>`, `rest: Option<AttemptResult>`. `AttemptResult` carries `{ outcome: Connected | PreAuthFailure(String) | PostAuthFailure(String), at: Instant }`.
- New variant `ConnectPhase::RecoveryPrompt`.
- Helper on `VtaConnectState`: `pub fn recovery_options(&self, resolved: &ResolvedVta) -> RecoveryOptions` returning `{ retry_didcomm: bool, retry_rest: bool, offline_available: bool }`. `retry_*` is true iff the transport is advertised AND its last attempt was pre-auth (post-auth failure means no retry — VTA accepted us).
- `apply_event` updated to write into `AttemptLog`.
- Pure logic — no UI changes.

**Verification:**
- Unit tests for `recovery_options` covering: pre-auth failure → retry available; post-auth failure → retry not available; transport not advertised → option disabled; never attempted → option disabled.

### Task 2.2 — Render recovery prompt

**Files:** `ui/diagnostics.rs` (or new `ui/recovery.rs` if it exceeds ~50 lines).

**Acceptance:**
- New panel rendered when `phase == RecoveryPrompt`. Layout reuses the existing `render_action_box` pattern.
- Options: `[R] Retry DIDComm`, `[E] Retry REST`, `[O] Offline sealed-handoff`, `[B] Back`. Unavailable options render with `theme::muted_style()` and don't accept keypresses.
- Above the options: a summary block listing each transport's last failure reason, dimmed-red. Operator can read why before choosing.

**Verification:**
- Manual: trigger the panel by stubbing `phase = RecoveryPrompt` in a test build. Visual check.
- Snapshot test optional (`insta` not currently in the workspace; skip unless cheap).

### Task 2.3 — `[O] Offline` transition with carry-over

**Files:** `app.rs`.

**Acceptance:**
- Selecting `[O]` invokes a new `transition_to_sealed_handoff(reason: OfflineReason)` on the wizard app. Reason values: `BothFailed`, `NoTransportAvailable`, `OperatorChoice`.
- Carry-over: `vta_did`, `context_id`, and (FullSetup only) `mediator_url` are pre-populated on the sealed-handoff state. Setup key is regenerated (the previous one was tied to a DIDComm session that may have leaked transcript metadata — fresh setup key is the safer default; documented inline).
- Sealed-handoff intro renders a one-line banner: "Online attempts failed: <reason>. Online steps reached: <last successful diag check>. Use this offline flow to complete setup via the VTA admin."
- Existing sealed-handoff flow's UI/state shape unchanged otherwise.

**Verification:**
- Manual: drive wizard, force a no-transport scenario, confirm `[O]` lands on sealed-handoff with `vta_did` pre-filled.
- Unit test for `transition_to_sealed_handoff` carry-over field-by-field.

**Checkpoint:** Slice 2 ships. Operator can recover from "neither transport advertised" by switching to offline. Tag `slice-2-complete`.

## Slice 3 — DIDComm-first → REST fallback (interactive)

### Task 3.1 — `ConnectPhase::TransportFallbackPrompt`

**Files:** `vta_connect/mod.rs`.

**Acceptance:**
- New variant `ConnectPhase::TransportFallbackPrompt`. Holds no payload — UI reads from `AttemptLog`.
- Helper `fallback_options(&self, resolved) -> FallbackOptions` returning `{ fall_back_to_rest: bool, retry_didcomm: bool, offline_available: bool }`. `fall_back_to_rest` is true iff REST is advertised AND no REST attempt has been made yet (don't offer a fallback that already failed).

**Verification:**
- Unit tests for `fallback_options` covering the same combinatorics as `recovery_options`.

### Task 3.2 — Render fallback prompt

**Files:** `ui/diagnostics.rs`.

**Acceptance:**
- New panel rendered when `phase == TransportFallbackPrompt`. Options: `[F] Fall back to REST`, `[R] Retry DIDComm`, `[O] Offline`, `[B] Back`.
- Failure detail shown above the options (DIDComm error reason).

**Verification:**
- Manual visual check.

### Task 3.3 — Orchestrator: route failures to the right prompt

**Files:** `vta_connect/runner.rs`, `app.rs`.

**Acceptance:**
- When `run_didcomm_attempt` returns `PreAuthFailure` AND REST is advertised → transition to `TransportFallbackPrompt`. AdminOnly and FullSetup behave identically here.
- When `run_didcomm_attempt` returns `PreAuthFailure` AND REST is not advertised → transition to `RecoveryPrompt` (skip fallback prompt; fallback isn't possible).
- When `run_didcomm_attempt` returns `PostAuthFailure` → transition to `RecoveryPrompt` directly. Confirm `recovery_options.retry_rest == false` because no fallback should be offered post-auth.
- When `run_rest_attempt` (whether reached via fallback or direct REST-only path) returns `PreAuthFailure` → transition to `RecoveryPrompt`. `retry_rest` is true (a fresh REST attempt may succeed if the failure was transient).
- When `run_rest_attempt` returns `PostAuthFailure` → transition to `RecoveryPrompt`. `retry_rest` is false.
- `[F] Fall back to REST` invokes `run_rest_attempt` with the carry-over state. Diagnostics row `AuthenticateREST` transitions from `Pending` to `Running` to terminal.
- `[R] Retry DIDComm` resets the DIDComm row to `Running`, clears the previous failure, re-spawns the runner.

**Verification:**
- Unit test: simulate `AttemptOutcome::PreAuthFailure`, assert the orchestrator picks the right next phase based on `resolved.rest_url.is_some()`.
- Unit test: same for `PostAuthFailure` — must always go to `RecoveryPrompt`, never `TransportFallbackPrompt`.
- Integration test: mock-VTA dual-transport fixture with DIDComm port killed mid-handshake → wizard ends up at `Connected` over REST.
- Manual: same scenario, drive interactively, walk through the fallback prompt.

**Checkpoint:** Slice 3 ships. Interactive fallback works end-to-end. Tag `slice-3-complete`.

## Slice 4 — Headless auto-fallback

### Task 4.1 — `bootstrap_headless` auto-falls

**Files:** `bootstrap_headless.rs`.

**Acceptance:**
- The headless driver doesn't enter `TransportFallbackPrompt` or `RecoveryPrompt` — it inspects `AttemptLog` and `recovery_options` directly.
- Decision tree:
  1. Both advertised → try DIDComm. PreAuth fail → auto-fall to REST. PreAuth fail again or PostAuth → terminal error.
  2. Only DIDComm advertised → try DIDComm. Any failure → terminal error.
  3. Only REST advertised → try REST. Any failure → terminal error.
  4. Neither advertised → terminal error immediately.
- Headless does **not** fall back from PostAuth failures (same boundary as interactive).
- No prompts written to stdout — it's structured logging only.

**Verification:**
- Integration test: drive `bootstrap_headless` against a dual-transport mock VTA with DIDComm killed; assert `Ok(VtaSession)` returned via REST.
- Integration test: same harness, both transports configured to fail PreAuth → assert `Err` with both reasons named.

### Task 4.2 — Structured terminal-error format

**Files:** `bootstrap_headless.rs`.

**Acceptance:**
- Error type: `HeadlessVtaError { didcomm: Option<String>, rest: Option<String>, recommendation: SealedHandoffHint }`.
- `Display` impl produces a stable multi-line message: protocol attempted, reason, sealed-handoff command suggestion (`mediator-setup --headless --offline-vta-handoff <args>` — wire the exact flag during implementation; spec doesn't pin this).
- Goes to `tracing::error!` and stderr.

**Verification:**
- Snapshot test on the `Display` output for each combination.

### Task 4.3 — Exit-code distinction

**Files:** `bootstrap_headless.rs`, `main.rs`.

**Acceptance:**
- Exit code `2`: no transport worked (all attempts PreAuth or `Neither` advertised).
- Exit code `3`: VTA accepted the request but rejected it post-auth (template render error, etc.).
- Exit code `0`: success.
- Documented in the binary's `--help` text.

**Verification:**
- Integration test asserts the right exit code for each scenario.

**Checkpoint:** Slice 4 ships. Headless mode complete. Tag `slice-4-complete`.

## Slice 5 — Tests + cleanup

### Task 5.1 — Unit: transport selector

Already implicit in earlier tasks. Sweep coverage at this point and fill gaps.

**Acceptance:**
- Test names follow `select_initial_transport_*` pattern, one per case (4 cases).
- Test names follow `recovery_options_*` and `fallback_options_*` for state helpers.

### Task 5.2 — Unit: AttemptLog edge cases

**Acceptance:**
- Tests cover: never attempted, single PreAuth, single PostAuth, retry after PreAuth, both transports tried, retry after both failed.

### Task 5.3 — Integration: mock-VTA fixtures

**Files:** `tests/` directory inside the wizard crate (extend existing `sealed_handoff.rs::tests` harness).

**Acceptance:**
- `rest_only_vta_completes_full_setup` — REST-only fixture, FullSetup intent, asserts `VtaReply::Full` and shape parity with DIDComm path.
- `rest_only_vta_completes_admin_only` — same but AdminOnly.
- `dual_transport_didcomm_killed_falls_back_to_rest` — dual fixture, DIDComm closes connection during handshake, REST reaches `Connected`.
- `dual_transport_didcomm_post_auth_failure_no_fallback` — dual fixture, DIDComm session opens then template render fails, asserts wizard ends in `RecoveryPrompt` with `retry_rest == false`.

### Task 5.4 — Manual TUI walkthrough

**Acceptance (operator-driven, recorded in PR description):**
1. Dual-transport VTA, kill DIDComm port between `EnterMediatorUrl` and `Testing`. Confirm fallback prompt renders, fall back to REST, reach `Connected`.
2. REST-only VTA. Confirm no `AuthenticateDIDComm` row appears in checklist.
3. Dual-transport VTA, force a template error on the VTA side. Confirm no fallback prompt; recovery prompt offers only Offline / Back.
4. No-transport VTA (DID doc with no `#DIDCommMessaging` and no `vta-rest`). Confirm wizard lands directly on `RecoveryPrompt` with only Offline / Back active.

### Task 5.5 — Cleanup

**Files:** `vta_connect/mod.rs` (line 7 doc comment), `vta_connect/diagnostics.rs` (rm `Authenticate` if not done in 0.1).

**Acceptance:**
- Stale "DIDComm (primary) or REST (fallback)" doc comment removed/rewritten now that it's true.
- All `#[allow(dead_code)]` markers re-evaluated (e.g. `Protocol::Rest` no longer dormant).
- `cargo clippy -p affinidi-messaging-mediator-setup -- -D warnings` clean.

**Checkpoint:** Slice 5 ships. All 12 spec ACs satisfied. Tag `transport-fallback-complete`. Open PR.

## Risks / open questions

1. **Mock-VTA harness coverage of REST.** The existing `sealed_handoff.rs::tests` harness builds sealed bundles directly. We need to confirm a fixture that serves `POST /bootstrap/provision-integration` with the same bundle is straightforward; if not, Slice 1 verification leans more on manual against a real VTA.
2. **`VtaClient` construction from a raw token.** Need to confirm the public API supports building `Transport::Rest` from `(base_url, AuthResult)` without going through `integration::startup()`. If not, add a constructor in vta-sdk before Task 1.2.
3. **Setup-key reuse vs regenerate on offline transition.** Spec says regenerate; confirm there's no downstream coupling that requires reusing the same key (e.g., the operator's `pnm acl create` is bound to the original setup DID — they'd have to re-run it for the offline flow's new DID). This is a UX wrinkle, not a blocker; document on the offline-intro screen.
4. **Order of `[F]` vs `[R]` in fallback prompt.** Spec implies `[F]` first (fall back is the happy path); confirm with operator before final UI. Trivial to change later.

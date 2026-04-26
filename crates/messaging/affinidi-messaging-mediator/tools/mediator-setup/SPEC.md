# SPEC — Transport Fallback for VTA-Connect

**Crate:** `affinidi-messaging-mediator-setup`
**Branch:** `fix/mediator-deployment`
**Status:** Draft, awaiting approval

## 1. Objective

Add transport-aware happy-path selection to the wizard's online VTA-connect
sub-flow. The wizard should prefer DIDComm when both transports are advertised,
fall back to REST on pre-auth failure, and — when both transports are exhausted
or unavailable — present a recovery prompt that offers retry, REST attempt, or
transition to the existing offline sealed-handoff sub-flow.

Today the runner hard-fails any VTA whose DID document doesn't advertise
`#DIDCommMessaging` (`vta_connect/runner.rs:140-146`), even when a `vta-rest`
service is present. This locks REST-only deployments out of the online flow
entirely. The fix activates the dormant `Protocol::Rest` branch and wires a
parallel REST execution path through the runner.

### Out of scope

- New REST endpoints on the VTA. The vta-sdk already exposes
  `VtaClient::provision_integration` (FullSetup) and `auth_light` (AdminOnly).
- Re-architecting `VtaIntent` or `VtaReply`. The reply shapes carry over
  unchanged — only the transport that produced them differs.
- Changing the offline sealed-handoff sub-flow. Spec only adds an entry path
  *into* it from the recovery prompt.
- TUI redesign of the diagnostics panel beyond two new row types.

## 2. Decisions (confirmed with operator)

| # | Decision |
|---|---|
| 1 | **Fallback boundary = pre-auth.** A failure that prevents `Connected` from being emitted (resolve, enumerate, session-open, authcrypt handshake, REST 401) triggers fallback. A failure *after* auth succeeds (template render, list_webvh_servers, provision_integration body) means the VTA accepted us — retrying over a different wire reproduces the same rejection. Show diagnostics + quit. |
| 2 | **Interactive prompts, headless auto-falls.** TUI run prompts the operator at each fallback boundary. The headless `bootstrap_headless.rs` path auto-falls without prompting. |
| 3 | **Both intents fall back.** `FullSetup` falls back via `VtaClient::provision_integration`. `AdminOnly` falls back via `auth_light::challenge_response_light` (REST challenge proving setup DID is ACL-enrolled). |
| 4 | **Recovery prompt after exhaustion.** When the operator-elected attempts are spent, render a recovery panel with `[R] Retry DIDComm`, `[E] Retry REST`, `[O] Offline sealed-handoff`, `[B] Back`. Options unavailable for the current VTA dim out. |
| 5 | **Two diagnostic rows for auth.** `AuthenticateDIDComm` and `AuthenticateREST`. The second is only inserted when fallback fires (or when REST is the only advertised transport). |
| 6 | **Post-auth diagnostic rows stay single-row.** `ListWebvhServers` and `ProvisionIntegration` are scoped to the active protocol — once we've committed, we don't switch mid-stream. |

## 3. Acceptance Criteria

### Endpoint enumeration

- **AC-1.** VTA advertises both `#DIDCommMessaging` and `vta-rest`: wizard
  attempts DIDComm first. `AuthenticateDIDComm` row appears.
- **AC-2.** VTA advertises only `vta-rest`: wizard skips DIDComm entirely.
  Only `AuthenticateREST` row appears (no `AuthenticateDIDComm` row at all,
  not even `Skipped`). `EnumerateServices` row reports `REST: yes,
  DIDCommMessaging: no` as `Ok` (today it reports `Failed`).
- **AC-3.** VTA advertises only `#DIDCommMessaging`: behaviour unchanged from
  today — DIDComm-only path. No `AuthenticateREST` row.
- **AC-4.** VTA advertises neither: hard-fail with the recovery prompt offering
  only `[O] Offline` and `[B] Back`.

### Pre-auth failure → fallback

- **AC-5.** DIDComm session-open fails (network, authcrypt rejection, ACL not
  found): in interactive mode, prompt the operator with the failure detail and
  options `[F] Fall back to REST` / `[R] Retry DIDComm` / `[O] Offline` /
  `[B] Back`. Headless mode auto-falls to REST if advertised, else surfaces a
  terminal error referencing sealed-handoff.
- **AC-6.** REST authentication fails (HTTP 401/403/connect refused): in
  interactive mode, prompt with `[R] Retry REST` / `[O] Offline` / `[B] Back`
  (no `[F] DIDComm` option if DIDComm has already failed or wasn't advertised).
  Headless terminates with a non-zero exit code referencing sealed-handoff.

### Post-auth failure → no fallback

- **AC-7.** DIDComm session opens, then `provision_integration` returns a
  template error: emit `ProvisionIntegration` row as `Failed`, surface error
  detail, **do not** offer REST fallback. Recovery prompt offers only
  `[O] Offline` and `[B] Back`. The same applies symmetrically when REST is the
  active protocol — a `2xx` followed by an error body is a VTA-side rejection,
  not a transport problem.
- **AC-8.** `ListWebvhServers` failure on FullSetup remains non-fatal as today
  (logged on the diagnostic row, serverless path continues). No fallback
  semantics change.

### Recovery prompt

- **AC-9.** Recovery prompt renders only the actions valid for the VTA's
  advertised endpoints and the failures observed. Unavailable actions render
  dimmed and ignore keypresses.
- **AC-10.** `[O] Offline` transitions into the existing sealed-handoff sub-flow
  with `vta_did`, `context_id`, and `mediator_url` (FullSetup only) carried
  over so the operator doesn't re-type them. The reason-of-transition is
  shown on the sealed-handoff intro screen.

### Headless mode

- **AC-11.** `bootstrap_headless.rs` (and any non-TTY invocation) auto-falls
  pre-auth without prompting and never enters the recovery panel. On terminal
  failure it exits non-zero with a structured error message naming the
  protocols attempted, the failure reasons, and the recommended sealed-handoff
  command. The exit code distinguishes "no transport worked" from "VTA
  accepted us but rejected the request" so CI scripts can branch.

### Reply shape

- **AC-12.** `VtaReply::Full` and `VtaReply::AdminOnly` are produced
  identically regardless of which transport delivered them — downstream
  `VtaSession`, `config_writer`, summary rendering, and `ContextExport` paths
  see no change.

## 4. Files to Touch

| File | Change |
|---|---|
| `vta_connect/runner.rs` | Replace the hard-fail-when-no-DIDComm branch with a transport-selection function. Split `run_connection_test` into `run_didcomm_attempt` and `run_rest_attempt`, both returning a uniform `Result<VtaReply, AttemptError>`. Orchestrator decides which to run based on advertised endpoints and operator selection. |
| `vta_connect/diagnostics.rs` | Add `DiagCheck::AuthenticateDIDComm` and `DiagCheck::AuthenticateREST`. Remove `DiagCheck::Authenticate` (or leave deprecated alias for one release if any external consumer reads it — unlikely, internal-only). Update `DiagCheck::all()` ordering. |
| `vta_connect/mod.rs` | Add `ConnectPhase::TransportFallbackPrompt` and `ConnectPhase::RecoveryPrompt`. Remove the stale "DIDComm (primary) or REST (fallback)" doc comment now that it's accurate. Extend `VtaConnectState` with `attempted: AttemptLog` (small struct: which protocols tried, last error per protocol). |
| `vta_connect/runner.rs` (REST path) | New: REST FullSetup uses `vta_sdk::VtaClient::provision_integration` against the resolved `rest_url`. REST AdminOnly uses `vta_sdk::auth_light::challenge_response_light` (or whichever `auth_light` variant fits — confirm during implementation). |
| `ui/diagnostics.rs` | Render the two `Authenticate*` rows. Render the `RecoveryPrompt` panel with dim-out for unavailable options. |
| `ui/prompt.rs` | Render the interactive fallback prompt (`[F]` / `[R]` / `[O]` / `[B]`). |
| `bootstrap_headless.rs` | Wire auto-fall behaviour. Tag terminal errors with the protocols attempted. |
| `app.rs` | Add the `RecoveryPrompt → SealedHandoff` transition with state carry-over. |
| `vta_connect/intent.rs` | No change to types. May add a private helper documenting the transport precedence rule. |

## 5. Code Style

- Follow existing wizard conventions: `tracing` for logs, `anyhow::Result` at
  flow boundaries, typed errors inside modules.
- New types are non-exhaustive only if the variant set is genuinely open
  (it isn't — keep enums plain).
- No new dependencies. `arboard`, `ratatui`, `crossterm`, `tokio`, `tokio-util`,
  `vta-sdk` already cover everything needed.
- `cargo fmt` before commit; DCO sign-off (`-s`) per repo policy.

## 6. Testing Strategy

### Unit tests (in-crate)

- `runner` — tests for the transport-selection function with mocked
  `ResolvedVta` inputs covering all four endpoint combinations (both / DIDComm
  only / REST only / neither).
- `runner` — tests for the post-auth-failure path: assert no fallback fires
  when `Connected` boundary has been crossed.
- `vta_connect::state` — tests for `AttemptLog` accumulating across retries,
  recovery prompt option-availability rules.
- `diagnostics` — tests asserting row ordering and that `AuthenticateREST` is
  absent on a DIDComm-only VTA.

### Integration tests

- Mock-VTA harness already exists for sealed-handoff round-trip in
  `sealed_handoff.rs::tests`. Extend with two new fixtures:
  - REST-only VTA (no DIDComm service in DID doc) — assert FullSetup completes
    via REST and produces a `VtaReply::Full` identical in shape to the DIDComm
    path.
  - Dual-transport VTA where DIDComm session-open is configured to fail —
    assert the runner falls back to REST and reaches `Connected`.

### Manual / TUI verification

- Drive the wizard against a local dual-transport VTA, force-kill its DIDComm
  port mid-handshake, confirm the interactive prompt renders and operator can
  fall back.
- Drive headless mode with a REST-only VTA via
  `cargo run --bin mediator-setup -- --headless --recipe <path>` and confirm
  it auto-uses REST.
- Drive headless mode against a VTA whose DIDComm endpoint is advertised but
  unreachable; assert non-zero exit code and the structured error message
  names both attempted protocols.

### Regression

- Existing online-VTA happy-path tests (DIDComm-only against test fixture)
  must continue to pass without modification — backward compatibility on the
  DIDComm-advertising path.

## 7. Boundaries

### Always do

- Carry `vta_did`, `context_id`, `mediator_url`, `setup_key` across any
  recovery transition so the operator never re-enters them mid-flow.
- Surface every transport attempt in the diagnostics panel — operators must
  be able to read what the wizard tried and why each step succeeded or
  failed.
- Preserve the `VtaReply` shape so config writing and summary rendering are
  protocol-agnostic.
- Treat any failure once `Connected` has been emitted as a VTA-side rejection
  and stop attempting transports.

### Ask first

- Adding a new dependency (none expected; vta-sdk surface should suffice).
- Changing the `VtaIntent` or `VtaReply` enums.
- Modifying the offline sealed-handoff sub-flow's UI or state shape.
- Removing the stale `DiagCheck::Authenticate` variant (vs. deprecating with
  alias) — confirm no out-of-tree consumer reads the diagnostic stream.

### Never do

- Auto-fall back after a post-auth failure. The VTA accepted us; a different
  wire will reproduce the rejection and waste an operator's time.
- Drop into sealed-handoff silently without the operator's selection in
  interactive mode.
- Persist the active transport into `mediator-build.toml` or any other
  serialized config — the choice is an artefact of *one* wizard run, not
  steady-state mediator config. The runtime mediator code uses its own
  transport-selection logic against the VTA's advertised endpoints at startup.
- Skip writing the secret bundle when fallback succeeds — the wizard's
  downstream steps are unchanged once `Connected` is emitted by either path.

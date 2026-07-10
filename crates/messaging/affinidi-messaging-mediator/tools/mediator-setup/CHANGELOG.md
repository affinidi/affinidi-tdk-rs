# Affinidi Messaging Mediator Setup

## Changelog history

## 10th July 2026

### 0.1.21 — publish the minted public DID to an optional target

- After provisioning, the wizard can publish the mediator's public DID string
  to a target from the recipe's `[output].did_target` — either `file://<path>`
  or `aws_parameter_store://<name>[?region=<region>]` (SSM, gated by the new
  `publish-aws` build feature). Defaults to `None`, so interactive and local
  setups are unaffected.
- The parameter-store target uses `mediator-common`'s shared `parameter_store`
  grammar — the same one the mediator runtime parses when it reads `mediator_did`
  — so the published target can be pasted into `mediator.toml` verbatim. A
  hierarchical name keeps its leading slash (`aws_parameter_store:///mediator/did`),
  which AWS requires; the region is an optional `?region=` query parameter rather
  than a leading path segment, which would be ambiguous against that slash.
- Without `?region=` the ambient AWS chain is used (`AWS_REGION`, profile, IMDS),
  so the publish destination never silently inherits the secret-storage backend's
  region.
- The target is validated at recipe load — before anything is minted, provisioned,
  or written — including rejecting an `aws_parameter_store://` target in a build
  without the `publish-aws` feature, which previously failed only after
  provisioning had already run.

## 2nd July 2026

### 0.1.20 — advertise `TSPTransport` on VTA-minted mediators only when TSP is enabled

- Completes the TSP-advertisement consistency work for the VTA-managed DID
  path. When the operator enables the `tsp` protocol, the wizard now injects a
  `SERVICE_TSP` service object into the VTA provisioning request's
  `integration_template_vars`, so the VTA renders a `#tsp` `TSPTransport`
  service on the minted mediator DID (endpoint mirrors the DIDComm `URL`). When
  TSP is off, nothing is injected and the mediator advertises no TSP transport.
- Requires vta-sdk >= 0.18.15, whose `didcomm-mediator` template renders `#tsp`
  only when `SERVICE_TSP` is supplied (previously it was unconditional). The
  self-hosted `did:webvh` / `did:peer` paths were already handled in 0.1.18 /
  0.1.19; this closes the last (VTA) gap.

### 0.1.19 — strip `TSPTransport` from generated `did:webvh` when TSP is disabled

- The shipped `didcomm-mediator` template (vta-sdk) advertises a `#tsp`
  `TSPTransport` service **unconditionally**. On the self-hosted `did:webvh`
  path the wizard now strips that service when the operator did **not** enable
  the `tsp` protocol, so a DIDComm-only mediator no longer advertises a
  transport it cannot serve (which would make remote peers route TSP that the
  mediator then rejects). When TSP *is* enabled the service is kept/ensured as
  before. `did:peer` already only added the service when TSP was enabled.
- Note: VTA-managed DIDs are rendered server-side and still carry the template's
  unconditional `#tsp`; the mediator now warns about that mismatch at startup
  (see the `affinidi-messaging-mediator` changelog). Gating it at the source
  needs a vta-sdk template change (tracked separately).

### 0.1.18 — bake a `TSPTransport` service into generated `did:peer` / `did:webvh`

- When the operator selects the `tsp` protocol, the generated mediator DID now
  advertises a `TSPTransport` service so remote mediators can discover its TSP
  endpoint for routed/nested forwarding. Previously the mediator only logged a
  startup warning for `did:peer` / `did:webvh` (whose documents are bound to the
  DID and cannot be mutated at runtime the way `did:web` is).
  - `did:webvh`: the service is injected into the rendered document before the
    SCID is computed, so it is covered by the log entry. Endpoint mirrors the
    `DIDCommMessaging` HTTP endpoint (TSP and DIDComm share `/inbound`).
  - `did:peer`: a `tsp` service segment (resolver-expanded to `TSPTransport`) is
    added alongside the `dm` service.
  - No-op when TSP is not enabled — the default document is byte-identical to
    before. `did:key` cannot carry a service, so it is unaffected.
- See `docs/tsp/enablement.md` for the operator walkthrough.

## 14th June 2026

### 0.1.13 — bump vta-sdk to 0.13

- Updated the `vta-sdk` dependency requirement from `0.11` to `0.13` (the
  `provision-client` and `test-support` features). No behaviour change.

## 12th June 2026

### 0.1.12 — Unify the non-interactive setup paths (simplification T22)

- The interactive, `--non-interactive`, and `--from <recipe>` flows each inlined
  the same re-run safety guard (`inspect_existing` + `refuse_overwrite`); the two
  non-interactive flows also duplicated the config-summary banner. Extracted
  `guard_existing_setup` (now shared by all three) and `print_config_summary`
  (shared by both non-interactive flows). The `--non-interactive` config build is
  now a testable `build_config_from_args` helper.
- New **config-equivalence test**: the CLI-args path and the recipe path render a
  byte-identical `mediator.toml` for the same logical setup, so the two
  non-interactive entry points can't drift apart. Behaviour-identical refactor.

### 0.1.11 — Centralise secret-backend opening (simplification T21)

- The online (`provision_secret_backend`) and sealed/headless
  (`bootstrap_headless`: seed sweep, phase-1, phase-2) flows each inlined the
  same `MediatorSecrets::from_url` + `probe()` + error-mapping. Extracted into a
  small `secret_backend` module — `open_secret_backend` (open) and
  `open_and_probe_secret_backend` (open + fail-fast probe) — so the four call
  sites share one implementation. Behaviour-identical refactor; the rest of the
  VTA session lifecycle was already centralised (`VtaSession` +
  `provision_secret_backend`), so no further extraction was warranted.

## 9th June 2026

### 0.1.10 — optional did:web export for self-hosted webvh DIDs

- New option to also export a `did:web` copy of the mediator's DID
  document when generating a `did:webvh`. `did:webvh` and `did:web` are
  wire-compatible — the same document resolves under either method once
  the SCID is dropped — so the wizard rewrites the resolved DID document's
  identifier from `did:webvh:<scid>:<domain>` to `did:web:<domain>` (and
  every self-reference: `id`, `controller`, verification-method and
  service ids) and writes it to `did-web.json` next to `did.jsonl`. The
  operator can host that file at a plain web server's
  `/.well-known/did.json`.
  - Interactive: a Yes/No prompt after the mediator public-URL step. It
    defaults to "No (recommended)" and is framed as advanced — most
    deployments only need the did:webvh log; pick "Yes" only if you know
    you need a did:web identifier (e.g. a counterparty that resolves
    did:web but not did:webvh).
  - Non-interactive / recipe: `--save-did-web` CLI flag and
    `[identity] save_did_web = true` recipe key.
  - Covers both the local generator and VTA-managed webvh logs (the
    export triggers whenever the minted DID is a `did:webvh:` and the
    option is set); non-webvh DIDs are skipped with a note.
  - The file is a standalone operator artefact — the mediator runtime
    still serves its own document from the webvh log
    (`did_web_self_hosted` → `did.jsonl`) and never reads `did-web.json`,
    so the distinct filename avoids colliding with the runtime-served
    `/.well-known/did.json`.

### 0.1.9 — vta-sdk 0.11 (fix online provisioning against current VTAs)

- Bump `vta-sdk` `0.9.11` → `0.11`. Online VTA setup failed at the
  `provision-integration` step against current VTAs with
  `validation error: unsupported message type:
  https://firstperson.network/protocols/provision-integration/1.0/provision-integration`
  — that legacy FirstPerson-Network URI was retired upstream. `0.11`'s
  provision-client emits the canonical Trust Task URI
  (`https://trusttasks.org/spec/provision/integration/0.1`) the VTA accepts.
  No source changes in the tool; it builds and tests clean against `0.11`.
- Bump `toml_edit` `0.22` → `0.25` (the only other direct dependency behind a
  newer release the caret couldn't reach; `config_writer` uses the stable
  `DocumentMut` / `value` / `Table` API, unchanged across the bump). All other
  direct dependencies were already at their latest compatible release.

## 6th June 2026

### 0.1.8 — affinidi-crypto 0.2

- Bump `affinidi-crypto` to `0.2` (P-384/P-521 key agreement +
  `#[non_exhaustive]` key-agreement enums, #357). Updated `vta-sdk` to
  `0.9.11` and `didwebvh-rs` to `0.5.4` (both now on `affinidi-crypto 0.2` /
  `affinidi-data-integrity 0.7`), so the tool resolves to a single
  `affinidi-crypto 0.2.0`.

### 0.1.7 — stop clobbering the unified secret backend

- **FIX (#354):** After provisioning the unified secret backend, the wizard
  ran a legacy block that wrote an `affinidi_secrets_resolver`-format array
  to a hard-coded `<config_dir>/secrets.json`. Whenever `[secrets].storage`
  pointed at that same path — which the default `conf/secrets.json` always
  does — this clobbered the unified `{"entries": …}` envelope the backend
  had just written. The mediator then couldn't find its operating secrets
  or admin credential and refused to start with
  `Configuration Error: No operating secrets found`, crash-looping while
  the file backend re-initialised the file to `{"entries": {}}` on each
  restart — making it look like the wizard never wrote anything.

  The legacy writer is removed entirely. The unified secret backend
  (opened in `provision_secret_backend`) is now the sole owner of secret
  persistence; nothing reads the legacy array format anymore. Runtime
  secret persistence is unaffected — it was always handled by the
  `file://` backend's own write path, not by this wizard block.

- **FIX:** The completion and final-summary banners reported the secrets
  file as a hard-coded `conf/secrets.json` regardless of the operator's
  `[secrets].storage` path. They now print the actual configured path, so
  a `file://` backend at a custom location is reported correctly.

## 5th June 2026

### 0.1.6 — well-formed `file://` secret-backend URLs

- **FIX (#350):** The wizard built the `file://` secret-backend URL by
  formatting the operator's storage path directly
  (`format!("file://{path}")`). For a *relative* path such as the default
  `conf/secrets.json` this produced `file://conf/secrets.json`, which is
  RFC 3986-malformed: `conf` parses as the URL *authority* and the path
  becomes `/secrets.json`. The mediator then opened `/secrets.json` at the
  filesystem root — silently writing outside the working directory as
  root, or failing the backend probe with `permission denied` for any
  other user.

  `build_backend_url` now resolves the path to absolute against the
  current working directory before formatting, emitting a correct
  three-slash `file:///<abs>` URL (empty authority). It also tolerates an
  operator pasting a full `file://` URL into the path prompt (no more
  double-prefixed `file://file:///…`). Absolute paths are unchanged.

# Affinidi Messaging Mediator Setup

## Changelog history

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

# Affinidi Messaging Mediator Setup

## Changelog history

## 6th June 2026

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

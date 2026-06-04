# Affinidi Messaging Mediator Setup

## Changelog history

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

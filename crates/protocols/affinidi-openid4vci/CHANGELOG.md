# Affinidi OpenID4VCI Changelog

## 28th May 2026 Release 0.1.2

### Security

- **HIGH — bearer credential in `Debug`.**
  `PreAuthorizedCodeGrant::pre_authorized_code` is a bearer credential:
  presenting it at the token endpoint is sufficient to obtain an access
  token (and so the credential) on behalf of the holder
  (OpenID4VCI §3.5). Deriving `Debug` meant any
  `tracing::debug!("{:?}", offer)` or panic-on-unwrap would leak it
  into logs. Manual `Debug` impl now redacts `pre_authorized_code`;
  `tx_code` only carries config metadata (input mode, length,
  description) and remains visible.
- Picks up the `affinidi-oid4vc-core` 0.1.2 `alg=none` rejection
  through the workspace path dep (no Cargo.toml edit required — pinned
  on `0.1`).

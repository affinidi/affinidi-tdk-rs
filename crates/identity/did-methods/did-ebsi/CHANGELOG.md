# did:ebsi

## [0.1.8] - 2026-11-15

a reusable resolver, HTTP status as data, relative ids

- **Added (#1043):** `EbsiResolver { client, api_base }`, built with
  `EbsiResolver::new(api_base)` or `with_client_builder(builder, api_base)`,
  resolves with one HTTP client and connection pool across lookups.
  `resolve_ebsi_did` keeps its signature and builds one per call. New
  `DEFAULT_TIMEOUT` constant (20 s, as before).
- **Changed (#1043):** an unsuccessful HTTP status from the registry fails
  with the new `EbsiError::Network(NetworkError)`, carrying the URL, the
  status and the registry's `Retry-After`, instead of
  `EbsiError::ResolutionFailed("HTTP …")`, so a caller can tell a rate limit
  from an unregistered DID. `ResolutionFailed` is no longer returned.
- **Fixed (#1042):** a registry document whose verification method or
  service ids, or relationship references, are relative DID URLs resolves,
  with them made absolute against the document's `id`.
- Docs (#1045): `resolve_ebsi_did` returns a `Document`, not a JSON value.
- Compatibility (R3.6): no signature change. A caller matching
  `EbsiError::ResolutionFailed` for an HTTP error status now gets
  `EbsiError::Network` (the enum is `#[non_exhaustive]`).

## [0.1.7] - 2026-11-12

a size limit on the fetched document

- `resolve_ebsi_did` reads the registry's response under a 1 MiB limit (new
  `MAX_DOCUMENT_BYTES` constant). A response that declares a larger
  `Content-Length` is refused before its body is read, and the body is
  counted as it arrives, so one sent without a `Content-Length` stops being
  read at the limit. Before, the whole body was read into memory, however
  large, until the 20 s request timeout. A larger response now fails with
  `EbsiError::Http` (behaviour change, R3.6; no signature change).

## [0.1.6] - 2026-10-01

the fetched document must name the requested DID

- Resolution now refuses a fetched DID document whose `id` is not the DID
  that was requested (new `DocumentIdMismatch` error). Previously a server
  answering for one DID could return a document for another and have its
  verification methods trusted.

## [0.1.5] - 2026-09-15

`rand` 0.10

No behaviour change: the identifier is still 16 bytes from the thread RNG.

rand 0.10 renamed the old `RngCore` to `Rng` and moved the sampling methods
onto a new `RngExt`, so `use rand::Rng` no longer brings `random()` into
scope — the import changes, the call does not.

## Changelog history

## [0.1.4] - 2026-07-19

affinidi-did-common 0.4

- Bumped the `affinidi-did-common` requirement from `"0.3"` to `"0.4"`.
  No functional change to this crate: `Document` gained a typed
  `also_known_as` field, which is additive.

## [0.1.3] - 2026-06-14

non_exhaustive EbsiError (W7 sweep)

- `EbsiError` is now `#[non_exhaustive]` (ADR-0003) so new variants land
  additively. Patch bump keeps the `0.1` pin valid; consumers that `match` it
  must add a `_` wildcard arm. No behaviour change.

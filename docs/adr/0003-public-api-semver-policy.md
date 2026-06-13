# ADR 0003 — Public-API semver policy: `#[non_exhaustive]` by default

- **Status:** Accepted
- **Date:** 2026-06-13
- **Relates to:** the workspace semver wave (W7–W11); `DataIntegrityError` as the original exemplar; the `didwebvh-rs` / `vta-sdk` `[patch.crates-io]` coupling.

## Context

Most published crates in the workspace shipped exhaustive public enums and
struct-literal-constructible public structs. Adding a variant to an enum, or a
field to a struct, is then a **breaking** change for downstream consumers (their
`match` arms / struct literals stop compiling). `affinidi-data-integrity` was
the lone exemplar that had already applied `#[non_exhaustive]` to its error and
proof types.

Pre-1.0, the cost of repeated breaking majors as the DID/VC/DIDComm data models
evolve is high. We want new variants/fields to be **non-breaking by
construction**, so the API can grow without a major bump each time.

A second, hard constraint shapes *how* we version these changes. Several of our
foundational crates are consumed by **external crates.io crates** that we also
depend on and redirect to local paths via `[patch.crates-io]` — most notably
`didwebvh-rs` (pins `affinidi-did-common "0.3"`, `affinidi-secrets-resolver
"0.5"`, `affinidi-data-integrity "0.7"`) and `vta-sdk` (pins
`affinidi-messaging-didcomm`). A `[patch]` redirect only applies while our local
version **satisfies the external crate's requirement**. Minor-bumping a patched
crate past the externally-pinned minor breaks the redirect, so cargo pulls a
second copy from crates.io and the build fails with duplicate-type errors.

## Decision

1. **`#[non_exhaustive]` by default on public, consumer-facing types.** Public
   error enums, data-model enums (e.g. `Endpoint`, `OneOrMany`,
   `VerificationRelationship`, `Params`), and public structs that consumers
   should not literal-construct (e.g. `JWK`, `Document`, `VerifiableCredential`,
   `DataIntegrityProof`) carry `#[non_exhaustive]`.
   - **Option B (keep public fields):** struct fields stay `pub` for *reads*;
     `#[non_exhaustive]` only blocks external struct-literal construction and
     exhaustive destructuring. Each sealed struct provides a `new(..)`
     constructor and/or builder as the construction path.
   - Consumers `match` these enums with a wildcard arm and build these structs
     via constructors/builders/deserialization.

2. **New trait methods get default implementations** where the trait is a public
   extension point (e.g. `Resolver`, `AsyncResolver`, `Signer`,
   `SecretsResolver`), so adding a method is non-breaking.

3. **Versioning is constrained by the external `[patch.crates-io]` coupling.**
   Because adding `#[non_exhaustive]` is *technically* breaking but, in this
   workspace, would break externally-pinned `[patch]` redirects if shipped as a
   minor bump, such changes are released as **patch bumps** within the current
   minor when the crate has external crates.io consumers. This keeps every `0.X`
   pin (internal and external) valid. The change is safe in practice: adding
   `#[non_exhaustive]` does not break any consumer that already uses wildcard
   arms (and the workspace — including the patched external crates built from
   source — compiles green against the sealed types). A *true* minor/major bump
   of these crates requires first coordinating new releases of the external
   consumers (`didwebvh-rs`, `vta-sdk`) that depend on the new version.

## Consequences

- New variants and fields can be added to sealed types without a breaking
  release. This is the precondition for a stable 1.0 surface.
- Downstream `match` on these enums must include a `_` arm; struct literals must
  become constructor/builder calls. Migration is mechanical (see the migration
  guide).
- The semver wave (W7–W10) sealed the types; W11 released them as patch bumps
  per point 3. A future 1.0 push that wants true minor/major versioning must
  sequence the external-consumer releases first.
- New capability crates should adopt this policy from the start (`#[non_exhaustive]`
  on public enums/errors/consumer structs, constructors over literals).

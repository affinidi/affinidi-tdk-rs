# affinidi-did-webs

Rust implementation of the `did:webs` DID method: `did:web` discovery with
KERI-verified key state.

```toml
[dependencies]
affinidi-did-webs = "0.1"
```

## What it does

A `did:webs` identifier ends in a KERI **AID**, and publishes two artifacts:

| URL | contents |
|---|---|
| `https://<host>/<path>/<AID>/did.json` | the DID document, as a cache |
| `https://<host>/<path>/<AID>/keri.cesr` | the key event log it must be derived from |

The document this crate returns is **derived from the verified key event log**,
never copied from the published `did.json`. `did.json` carries no authority on
its own: it is cross-checked against the derivation, and a disagreement fails
the resolution rather than being resolved in either direction. As the
specification requires, a resolution fails if either artifact cannot be
fetched, and fails if no designated-aliases attestation in the stream names the
DID being resolved — a log that verifies does not make every host serving it a
publisher of the DID.

`resolve_with_metadata` also returns the DID document metadata — `versionId`,
`nextVersionId`, `equivalentId` and `deactivated` — and a DID URL carrying
`?versionId=<sn>` resolves the document as of that key event.

A deactivated identifier (its last rotation committed to no next keys) does
not resolve to its keys. Deactivation belongs to the DID, so it is read from
the whole stream: `resolve` and `resolve_from_artifacts` fail with
`DidWebsError::Deactivated` at every version, and `resolve_with_metadata`
reports `deactivated: true` at every version. The deactivating version's
document keeps only `id` and `alsoKnownAs`, and `update` publishes it so; an
earlier `?versionId=` returns that version's keys for checking signatures
made while they were current.

A `keri.cesr` stream is refused past `kel::MAX_STREAM_MESSAGES` messages,
`kel::MAX_STREAM_SIGNATURES` signatures, `kel::MAX_STREAM_BACKERS` witness
entries or `kel::MAX_STREAM_SEALS` seals, and `WebsResolver` verifies it on
tokio's blocking thread pool, no more at once than there are CPUs.

```rust,no_run
# async fn run() -> Result<(), affinidi_did_webs::DidWebsError> {
let doc = affinidi_did_webs::resolve(
    "did:webs:example.com:ENro7uf0ePmiK3jdTo2YCdXLqW7z7xoP6qhhBou6gBLe",
).await?;
# Ok(())
# }
```

Artifacts already in hand can be verified without any network access, which is
also how this crate is tested:

```rust,no_run
use affinidi_did_webs::{DidWebs, resolve_from_artifacts};

# fn run(keri_cesr: &[u8], did_json: &[u8]) -> Result<(), affinidi_did_webs::DidWebsError> {
let did = DidWebs::parse("did:webs:example.com:ENro7uf0ePmiK3jdTo2YCdXLqW7z7xoP6qhhBou6gBLe")?;
let doc = resolve_from_artifacts(&did, keri_cesr, Some(did_json))?;
# Ok(())
# }
```

## What is verified

- Every key event's SAID, before any of its fields are trusted.
- The prior-event digest chain, and sequence ordering.
- Controller signatures, against the keys each event type is signed by.
- **Signing thresholds**, everywhere a signature counts: on key events, and on
  the replies and attestations signed outside the log, which must meet the
  threshold of the key state at the establishment event they name — one key of
  a 2-of-3 identifier speaks for nobody. A threshold above one key is published
  as a `ConditionalProof2022` method, which alone is in `authentication` and
  `assertionMethod`.
- Pre-rotation commitments on every rotation.
- **Delegation**: a delegated event is accepted only if the delegator's own
  verified KEL, present in the same stream, anchors a seal naming that exact
  event. Delegation chains are followed, bounded, and cycle-checked.
- **Designated aliases**, which is where `alsoKnownAs` comes from. A DID
  document does not get to assert its own aliases: an alias counts only if the
  AID issued a credential saying so, and that credential is anchored in the
  AID's own key event log. The whole chain is checked — for an ACDC 1.x
  credential, registry inception anchored, issuance anchored, attestation
  signed by the AID's key state, and no revocation anchored; for 2.x, the
  registry's latest anchored, non-vacuous update discloses it as issued. A
  break anywhere yields no aliases from that attestation rather than a
  partially-trusted list. **Every registry event the KEL anchors must be in
  the stream**, so a host cannot withhold a revocation; a stream that leaves
  one out fails resolution. The aliases are those of
  every attestation that verifies, and the `did:web` twin and `did:keri` form
  appear only when designated.
- **Witness receipts**, when the key event log declares witnesses. An event
  whose own key state names backers and a threshold is only accepted once that
  many designated witnesses have receipted it — from the event's attachments or
  from separate `rct` messages. A KEL with `bt: 0` is unaffected.
- **Service endpoints**, from signed KERI endpoint authorisations. An endpoint
  appears only when two signed replies agree: `/end/role/add` from this AID
  authorising an identifier in a role, and `/loc/scheme` from *that* identifier
  saying where it is. `/end/role/cut` withdraws it. Replies supersede one
  another by KERI's BADA rule — the later establishment event first, then the
  later `dt` — so a key the controller has rotated away from cannot outrank
  the current one with a future-dated reply. Witness services come from the key
  state's witness list plus each witness's own location, and a delegated
  identifier publishes a `DelegatorOOBI` service.
- The published `did.json`, transformed back from its `did:web` form, against
  the derived document: the same verification methods, services and aliases,
  and the same `controller` and relationships where it publishes them. The
  reference implementation publishes no `controller`, `authentication` or
  `assertionMethod`, so a document may omit those — but never add to or change
  anything the stream establishes.

- **Critical designations.** A standing designation marked `"critical": true`
  whose schema this resolver does not implement fails resolution
  (`unsupportedDesignation`): it restricts the document, and serving the
  document without the restriction would be wrong.

## KERI 2.0 (alpha)

Both KERI versions are read, and an identifier is written in the version of
its own log: its designations and replies follow it. `create_controlled`
writes 2.0 unless its `Inception` says otherwise. **This integration is alpha:
expect breaking changes as the did:webs and KERI 2.0 specifications settle.**

| | KERI 1.x | KERI 2.0 |
|---|---|---|
| a designation | ACDC 1.x in a `vcp`/`iss`/`rev` registry, signed by the AID | ACDC 2.x (`acm`) in its own `rip`/`bup` registry, issued by an anchored update that discloses it |
| replacing one | a `rev` | a further `bup` disclosing `revoked` |
| a reply | `rpy` with a `-F` endorsement | `rpy` naming its sender in `i`, with a `-X` endorsement |

Each designation schema has a 2.x form (designated aliases `EF9Iy-vw…`, key
agreement `EIW1ONwn…`, service `EJVZ789s…`, key role `EBMCaUhH…`, which is
critical). `tests/fixtures/ours-v2` holds an identifier's lifecycle on 2.0
that keripy accepts in full. The positions taken on open questions are in
`docs/05-design-notes/did-webs-keri-v2.md` in
OpenVTC/verifiable-trust-infrastructure.

## Key agreement and services of any type

A document derived from key state alone has signing keys and KERI role
endpoints, and nothing to encrypt to or to reach a `DIDCommMessaging` or
`TSPTransport` service at. KERI's endpoint replies cannot carry those (keripy
accepts only its own roles, and `tcp`/`http`/`https` URLs), and converting the
identifier's Ed25519 signing key to X25519 would make its change authority an
encryption key.

So both are **designations**: ACDCs the AID issues to itself and anchors in
its KEL, verified exactly as designated aliases are — the mechanism the
specification's Implementors Guide calls "the best" for key agreement.

| Designation | Schema | Becomes |
|---|---|---|
| Key agreement (`a.keys`: CESR keys — X25519 `C`, P-256 `1AAJ`, secp256k1 `1AAB`) | [`schemas/key-agreement-designation.json`](schemas/key-agreement-designation.json) `EJZrf6N4vbhA1hQIujWiIiQmNi455EGS3iXdhxLSwvAi` | `JsonWebKey` methods in `keyAgreement` |
| Services (`a.services`: DID document service entries) | [`schemas/service-designation.json`](schemas/service-designation.json) `ELj0Sdf2Boi7BMiIFAEJ9_MSFJU8t-LavLN-gMb8oXM8` | entries in `service` |

```rust,no_run
use affinidi_did_webs::create::{CreateConfig, create};
use affinidi_did_webs::{DesignatedService, KeyAgreementKey};
use serde_json::json;

# fn run(x25519_public: [u8; 32]) -> Result<(), affinidi_did_webs::DidWebsError> {
let result = create(
    CreateConfig::builder("example.com")
        .key_agreement(KeyAgreementKey::X25519(x25519_public))
        .designated_service(DesignatedService::new(
            "#didcomm",
            "DIDCommMessaging",
            json!({ "uri": "did:webvh:QmMediator:mediator.example", "accept": ["didcomm/v2"] }),
        ))
        .build(),
)?;
# Ok(())
# }
```

`Change::KeyAgreement` and `Change::DesignatedServices` replace either set —
revoking the designation in force — without rotating the identifier. A key of
the current key state is never a key agreement key, and a designated service
cannot reuse the id of an endpoint KERI's own data establishes.

### Identifiers that designate no key agreement keys

Most KERI identifiers designate none, and KERI practice — including the
reference implementation's DIDComm support — encrypts to the X25519 key
converted from each Ed25519 key of the current key state. Resolution does the
same: an identifier that has never issued a key agreement or key role
designation, and is not deactivated, resolves with those converted keys in
`keyAgreement` (`key_agreement::converted_key_agreement`). Rotation replaces
them with the key state.

They are rendered after the published `did.json` is checked, because the
specification's derivation does not include them: a `did.json` without them —
keripy's — agrees, and one listing exactly them agrees too. This crate never
publishes them, and an identifier that has designated keys, even one whose
designation is since revoked, never gets them.

These schemas are this crate's, proposed to the `did:webs` specification; until
another implementation reads them, a resolver that derives the document from
KERI data alone will not reproduce `keyAgreement` or the designated services,
and will reject a `did.json` carrying them.

## Keys the caller holds

`create` and `update` derive every key from a salt. When keys live elsewhere —
an HSM, an enclave, a key service — or a recovery key is held by someone else,
use the controlled path, which never sees a secret:

```rust,no_run
use affinidi_did_webs::create::{CreateConfig, create_controlled};
use affinidi_keri::controller::{Inception, KeySigner, NextKey};
use affinidi_keri_core::threshold::Threshold;

# fn run(routine: &dyn KeySigner, successor: String, custodian_digest: String)
#     -> Result<(), Box<dyn std::error::Error>> {
let created = create_controlled(
    CreateConfig::builder("example.com")
        .controlled(Inception::new(
            vec![routine.public_key()?],
            Threshold::Simple(1),
            // The custodian hands over only its key's digest.
            vec![NextKey::PublicKey(successor), NextKey::Digest(custodian_digest)],
            Threshold::from_json_value(&serde_json::json!([["1/2", "1"]]))?,
        ))
        .build(),
    &[routine],
)?;
# Ok(())
# }
```

`update_controlled` applies every change but a rotation. A rotation is
`prepare_rotation`, then signatures — `PendingEvent::sign_with` here, or
`add_signature` with one made elsewhere (a `PendingEvent` serializes) — then
`complete_rotation`. Under the weighted `nt` above the custodian's key must
sign; the routine successor alone cannot rotate.

## Key roles (proposed extension)

A document derived from key state places every key of the key state — the
identifier's change authority — in both `authentication` and
`assertionMethod`. A verifier that selects keys by role, such as the
Verifiable Trust Infrastructure's `keyRoles` (VTI-KEY-090 to VTI-KEY-096), has
nothing to select by, and the change authority signs everything.

A **key role designation** ([`schemas/key-role-designation.json`](schemas/key-role-designation.json)
`EPulJFl5SEb8qb3ca5teXHRGiWmTsTkylGTrS2vB4ZQx`) binds other keys to roles —
`attestation` (rendered in `assertionMethod`), `operational`
(`authentication`), `messaging` (`keyAgreement`) — and once an identifier has
issued one, its document lists those role keys, each in its role's
relationship only, plus a top-level `keyRoles`, and **no key of the key state
at all**. Keys revoked for compromise stay listed with `revoked`, in no
relationship, for the life of the identifier.

```rust,no_run
use affinidi_did_webs::create::{CreateConfig, create};
use affinidi_did_webs::{KeyAgreementKey, KeyRoles, VerificationKey};

# fn run(sign: [u8; 32], op: [u8; 32], x25519: [u8; 32]) -> Result<(), affinidi_did_webs::DidWebsError> {
let result = create(
    CreateConfig::builder("example.com")
        .key_roles(
            KeyRoles::new()
                .with_attestation(VerificationKey::Ed25519(sign))
                .with_operational(VerificationKey::Ed25519(op))
                .with_messaging(KeyAgreementKey::X25519(x25519)),
        )
        .build(),
)?;
# Ok(())
# }
```

`Change::KeyRoles` replaces the binding (a key left out is retired), and
`Change::RevokeRoleKey` revokes one for compromise. This is a proof of concept
of an extension proposed to the `did:webs` specification
([docs/key-role-designation.md](docs/key-role-designation.md)): a resolver
that does not implement it derives the key-state document instead, and refuses
the `did.json` of an identifier that uses it.

## HTTPS, and the loopback exception

Artifacts are fetched over **HTTPS**. Two exceptions use plain HTTP:

- a **loopback** host (`localhost`, `127.0.0.1`, `::1`), which cannot be
  intercepted from elsewhere and rarely has a certificate;
- any host, if you opt in with `WebsResolver::allow_http(true)`.

The opt-in exists because the reference implementation
(`hyperledger-labs/did-webs-resolver`) fetches over plain HTTP, so
interoperating with it — or with KERI tooling on a private network without TLS
— is otherwise impossible. Leave it off in production: a `did:webs` document is
derived from a self-verifying key event log, so an attacker cannot *forge* one,
but they can serve a **stale** log and hide a key rotation that has already
happened, which is the attack pre-rotation exists to defeat.

## Creating identifiers

Behind the optional `create` feature. Resolution never needs it, and it pulls
`affinidi-keri`.

```rust,no_run
use affinidi_did_webs::create::{CreateConfig, create};
use affinidi_keri::config::InceptionConfig;

# fn run() -> Result<(), affinidi_did_webs::DidWebsError> {
let salt = [42u8; 16];
let result = create(
    CreateConfig::builder("example.com")
        .inception(InceptionConfig::builder().salt(salt.to_vec()).build())
        .build(),
)?;

// Publish these two files; this crate does not.
for (name, bytes) in result.artifacts().files() {
    println!("{name}: {} bytes", bytes.len());
}
# Ok(())
# }
```

`create` and `update` return **bytes plus a custody record**, and publish
nothing. Rotation, interaction and service designation go through `update`,
which takes the prior artifacts as the state — the key event log *is*
`keri.cesr`, so there is nothing else to keep.

### What must survive between events

Rotating later needs the keys the previous event committed to **by digest**, and
a digest cannot be reversed — so they are not recoverable from the published
artifacts. Two things have to be kept, and they belong in different places:

| | where |
|---|---|
| the **salt**, from which every key is derived | wherever the application keeps secrets — `affinidi-secrets-resolver` here. This crate never stores it. |
| the **custody record** (generations, sequence number, last SAID) | not secret; keep it with the artifacts |

A custody record is superseded by every update. Keeping a stale one is
indistinguishable from losing the keys, so `update` refuses one whose sequence
number does not match the published log.

### `did.json` is generated by the resolver's own code path

So the two cannot disagree. That is a constraint rather than a convenience: a
resolver derives the document from the key event log and ignores whatever the
published file adds, so anything not backed by KERI artifacts would be silently
dropped on the way back. Service endpoints are supported because they *can* be
backed — each is emitted as signed `rpy` messages the resolver verifies.

### Designating `alsoKnownAs`

An alias is not something a document may assert about itself. Designating one
issues a credential — a registry, an issuance, and the attestation, each anchored
in the identifier's own key event log — which the resolver verifies before
carrying any alias back. `create` takes `also_known_as`, and `update` takes
`Change::AlsoKnownAs`.

`also_known_as_scid` designates this identifier's own `did:scid:ke:1` form. ⚠️
That format code is *proposed* in the did:scid registry rather than registered,
so its spelling may change.

Every identifier designates itself, its `did:web` twin and `did:keri:<AID>` in
the attestation creation issues: a resolver refuses a DID its AID has not
designated, `did.json` is published in the `did:web` form (valid only when the
twin is designated), and the specification requires the `did:keri` alias. There
is no switch for any of them.

## What is not verified yet

- **Credential schema validation.** A designated-aliases attestation is matched
  by its schema SAID and its issuance chain is verified, but the credential body
  is not validated against the schema itself.

## Related crates

- [`affinidi-keri-core`](https://crates.io/crates/affinidi-keri-core) — KEL verification
- [`affinidi-did-web`](../did-web/) — the `did:web` half of the family
- [`affinidi-did-common`](../../affinidi-did-common/) — DID document types

## Contributing

See [CONTRIBUTING](https://github.com/affinidi/affinidi-tdk-rs/blob/main/CONTRIBUTING.md).

## License

[Apache-2.0](https://github.com/affinidi/affinidi-tdk-rs/blob/main/LICENSE)

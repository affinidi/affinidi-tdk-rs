# did:webs key role designation — a proposed extension

Status: proof of concept, implemented in `affinidi-did-webs`. Written to be
taken to the KERI Suite Working Group (KSWG) as a proposal for the `did:webs`
specification.

## Problem

A `did:webs` document is derived from the key state of its AID: every key of
the current key state becomes a verification method, and each is placed in
both `authentication` and `assertionMethod` (or, above a threshold of one, the
`ConditionalProof2022` over them is).

Those keys are the identifier's **change authority** — they sign key events.
Placing them in every verification relationship means:

- the key that can rotate the identifier is also the key that signs every
  credential and every authentication, so its exposure grows with every use;
- a verifier cannot tell which key may sign what. A relying-party framework
  that binds keys to purposes — the Verifiable Trust Infrastructure's key roles
  (VTI-KEY-070 to VTI-KEY-096: `attestation`, `operational`, `messaging`, and an
  `update` authority that must never be a verification method) — cannot use
  `did:webs` at all (VTI-KEY-173);
- an encryption key can only be had by converting a signing key, which makes
  the change authority an encryption key.

KERI itself already separates these: the KEL is the update authority, and
anything else an AID says about its keys can be said in an ACDC it issues and
anchors. The document derivation is what conflates them.

## Mechanism

A **key role designation** is an ACDC the AID issues to itself and anchors in
its KEL, exactly as the specification's designated-aliases attestation is:

```text
KEL ixn ──anchors──▶ vcp   a registry incepted by the AID
KEL ixn ──anchors──▶ iss   an issuance in that registry
                      └──▶ ACDC of schema EPulJFl5SEb8qb3ca5teXHRGiWmTsTkylGTrS2vB4ZQx
```

Its attribute block:

```json
{
  "d": "<attributes SAID>",
  "dt": "2026-11-09T00:00:00.000000+00:00",
  "roles": {
    "attestation": ["DKZs…"],
    "operational": ["DB3n…"],
    "messaging":   ["CPx1…"]
  },
  "revoked": [
    { "key": "DA9q…", "compromisedAt": "2026-11-01T00:00:00Z" }
  ]
}
```

`roles` maps a role name to the CESR public keys bound to it. Registered roles:

| Role | Use | Key types | Rendered in |
|---|---|---|---|
| `attestation` | signs attestations (credentials) | Ed25519 `D`, P-256 `1AAJ`, secp256k1 `1AAB` | `assertionMethod` |
| `operational` | signs operational material, authenticates | Ed25519 `D`, P-256 `1AAJ`, secp256k1 `1AAB` | `authentication` |
| `messaging` | key agreement; signs nothing | X25519 `C`, P-256 `1AAJ`, secp256k1 `1AAB` | `keyAgreement` |

A resolver ignores a role name it does not recognise, so the registry can grow.

## Rendering

Once an AID has issued a key role designation that verifies, its document is
derived from the designation rather than the key state, for the life of the
identifier:

- `verificationMethod` lists the role keys of the designation that stands, as
  `JsonWebKey` methods with id `#<key qb64>` (as the key state's keys are
  today), then every revoked key;
- each role key appears in its role's relationship and in no other;
- a top-level `keyRoles` maps each role to its keys' ids;
- **no key of the key state, and no `ConditionalProof2022`, appears anywhere**:
  the KEL alone states the update authority;
- a revoked key keeps its verification method, with the CID `revoked` property
  set to its compromise time, in no relationship and not in `keyRoles`;
- `service` and `alsoKnownAs` are derived as today; key agreement designations
  give way to the `messaging` role.

```json
{
  "id": "did:webs:example.com:EAid…",
  "controller": "did:webs:example.com:EAid…",
  "verificationMethod": [
    { "id": "#DKZs…", "type": "JsonWebKey", "controller": "did:webs:…", "publicKeyJwk": { "kty": "OKP", "crv": "Ed25519", "x": "…", "kid": "DKZs…" } },
    { "id": "#DB3n…", "type": "JsonWebKey", "controller": "did:webs:…", "publicKeyJwk": { "kty": "OKP", "crv": "Ed25519", "x": "…", "kid": "DB3n…" } },
    { "id": "#CPx1…", "type": "JsonWebKey", "controller": "did:webs:…", "publicKeyJwk": { "kty": "OKP", "crv": "X25519", "x": "…", "kid": "CPx1…" } },
    { "id": "#DA9q…", "type": "JsonWebKey", "controller": "did:webs:…", "publicKeyJwk": { "kty": "OKP", "crv": "Ed25519", "x": "…", "kid": "DA9q…" }, "revoked": "2026-11-01T00:00:00Z" }
  ],
  "authentication": ["#DB3n…"],
  "assertionMethod": ["#DKZs…"],
  "keyAgreement": ["#CPx1…"],
  "keyRoles": {
    "attestation": ["#DKZs…"],
    "operational": ["#DB3n…"],
    "messaging": ["#CPx1…"]
  },
  "service": [],
  "alsoKnownAs": ["did:web:example.com:EAid…", "did:keri:EAid…"]
}
```

The published `did.json` is cross-checked against this derivation as it is
today; `keyRoles` must be published and must match.

## Rotation and revocation

- **One designation stands.** Issuing a key role designation revokes the
  previous one (a `rev` anchored in the KEL). Two standing at once bind
  nothing.
- **Planned rotation** of a role key is a new designation without it; the key
  leaves the document. The key state is not rotated: role keys change without
  touching the change authority.
- **Revocation for compromise** is a new designation listing the key in
  `revoked` with its compromise time. A resolver collects the `revoked` entries
  of *every* key role designation the AID has issued, standing or since
  replaced, keeping the earliest time for a key: a compromise statement stays
  true after the designation that made it is replaced, so leaving an entry out
  of a later designation does not un-revoke the key. Issuers carry every entry
  forward regardless.
- **Rotating the key state** leaves the role keys in place: the designation
  stays verified against the key state it was signed under.
- `versionId` resolution reflects the designations anchored up to that event.

## Validation (fail closed)

The standing designation binds nothing — the document then lists no role key,
keeps its revoked keys, and never falls back to the key state's keys — when:

- a role key is a key of the current key state, or one the key state has
  committed to rotate to (its digest is in `n`);
- a key is bound to two roles, or both bound and revoked;
- a key is not of a type its role binds, or a role lists no keys;
- a `revoked` entry has no key or no RFC 3339 compromise time.

An issuer refuses the same, and refuses a role name it does not know.

## Security considerations

- The change authority signs only key events and designations; a compromise of
  a role key is recoverable by a new designation, without rotating the AID.
- Because the designation is signed under the key state's threshold and
  anchored in the KEL, a role binding has exactly the authority of the AID; a
  forged or unanchored designation is ignored like any other.
- A KERI next-key threshold can require a recovery key for every rotation of
  the change authority, which a VTA-held routine key alone cannot satisfy
  (VTI-KEY-129) — the property that makes KERI attractive for key-role
  identities in the first place.
- Never falling back to the key-state rendering is deliberate: a verifier that
  sees a key-role identity's document with its change authority in
  `assertionMethod` would accept a signature the controller meant no key to
  make.

## Interoperability caveat

This changes the derived document. A resolver that does not implement the
extension derives the key-state document for such an identifier, finds that
`did.json` does not match it, and refuses the identifier. Until the extension
is part of the specification, only resolvers built on `affinidi-did-webs`
resolve key-role identifiers. Identifiers that never issue a key role
designation are unaffected.

## Open questions for KSWG

1. Is "rendering replaced once opted in" acceptable, or should the key-state
   keys remain as verification methods in no relationship (visible for
   tooling, inert to verifiers)?
2. Should the schema, and the role registry, live in the `did:webs`
   specification or in a separate KERI designations registry shared with the
   key agreement and service designations?
3. Should `revoked` be a separate credential type (one per compromise) rather
   than an accumulated list?
4. Is the CID `revoked` property the right rendering, given
   `did:webs` today has no notion of a revoked verification method?
5. Should a threshold over role keys (a `ConditionalProof2022` per role) be
   expressible, for roles that are multi-signature?

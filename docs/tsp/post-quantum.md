# Post-quantum TSP in `affinidi-tsp`

**Status: the cryptography is built and verified against the specification's
own vectors. The VID model is not, so nothing above this crate can use it yet.**

Behind the `pq` feature, `affinidi-tsp` implements the two post-quantum
algorithms Rev 3 §8 defines, and opens the specification's `direct-hpke-base-pq`
vector end to end.

```
cargo test -p affinidi-tsp --features pq --test spec_vectors
```

## Why it was not built until now

The Rev 3 migration deliberately stopped short of post-quantum, and the reason
was evidence rather than effort. Four things were missing when Appendix A was
first published, and all four were reported against
[PR #63](https://github.com/trustoverip/tswg-tsp-specification/pull/63):

| Reported | Resolved |
|---|---|
| Five appendix values three characters short — the PQ vector, `pq_alice`'s ML-DSA signing key, `control-rfd`, and two long forms whose `did:peer:4` hash no longer matched their document | Fixed; all ten vectors now decode and all eight long forms hash correctly |
| `pq_bob`'s 32-byte encryption key cannot be an ML-KEM-768 decapsulation key — is a seed expansion specified anywhere? | §8.2.1 gained a sentence: it *is* the whole key, a seed `DeriveKeyPair` expands |
| `X25519MLKEM768` is the TLS spelling; IANA has `0x647a` as X-Wing and `draft-ietf-hpke-pq` asks to replace that entry | Spec now says `MLKEM768-X25519` at both tables |
| `[[FIPS204]]` and `[[def-FIPS180-4]]` do not render, and both are MTI references | Both corrected, `FIPS203` added |

Without those, a hybrid KEM and a post-quantum signature scheme would have
shipped validated by nothing but agreement with themselves — which the sealed
box had just demonstrated is not enough, since three details of that
construction are invisible to a round-trip test and only its vectors caught
them. The same is true here, and the vector suite says so explicitly.

## What is verified

`tests/spec_vectors.rs::post_quantum` checks, against bytes this crate had no
hand in producing:

- **The vector opens.** `direct-hpke-base-pq` decrypts to `hello world` and its
  ML-DSA-65 signature verifies — which pins the hybrid KEM, the signature
  scheme, and the `4F` ciphertext split at 1120 bytes rather than 32.
- **The seed expands.** `DeriveKeyPair` over each published 32-byte encryption
  key reproduces that identity's published 1216-byte public key. This is the
  September 8 clarification, checked rather than taken on trust.
- **The published key sizes are the algorithms' own** — 1952/4032 for ML-DSA-65,
  1216/32 for the hybrid. Cheap, and the check that catches truncation without
  any base64 reasoning.
- **Scheme confusion is a rejection.** An ML-DSA-signed message offered an
  Ed25519 verifying key fails as a scheme mismatch, not as a bad signature.

Three choices here are invisible to a round trip, and each is a plausible way to
be wrong on the wire:

1. **Which hybrid.** X-Wing and `MLKEM768-X25519` share `Nsecret`, `Nenc`, `Npk`
   and `Nsk`, so building the wrong one fails decapsulation with no length
   mismatch to point at it. We use `hpke 0.14`'s `XWing`, which is the crate the
   reference uses at v0.10.0 — its type name is the construction, its `KEM_ID`
   is `0x647a` and its `DeriveKeyPair` is hpke-pq's. See the module docs on
   `crypto::hpke_pq`.
2. **Which ML-DSA.** Pure with an empty context, prehash and `sign_internal` all
   produce a 3309-byte signature over the same message, and each verifies
   perfectly against itself. The vector picks pure-with-empty-context.
3. **Which key expansion.** An implementation that read the published 32-byte
   value as a raw ML-KEM key would agree with itself and with nobody.

## What is *not* built

**The VID model does not carry these keys.** `ResolvedVid::signing_key` and
`encryption_key` are `[u8; 32]`, and an ML-DSA-65 verifying key is 1952 bytes
and a hybrid encryption key 1216. So:

- No resolver produces a post-quantum VID, and no store holds one.
- The SDK and the mediator cannot send or receive one.
- `pack_pq` is direct messages only — no hops, no padding, no referral. Those
  live in the payload frame, which is identical across key types, so widening it
  is plumbing rather than protocol.

Nothing is silently wrong meanwhile: a peer publishing only an ML-KEM key fails
cleanly at resolution rather than being misread, and `unpack` without an
explicit key type still means Ed25519 and X25519.

**The code point `1AAQ` is provisional.** It is the next free code in the master
table for genus `-_AAACAA` and collides with nothing, but
[CESR issue #14](https://github.com/trustoverip/tswg-cesr-specification/issues/14)
has not registered it. A peer built against a later table may disagree, which is
the main reason `pq` is off by default.

## The API

```rust
use affinidi_tsp::message::direct::{DecryptionKey, VerifyingKey, pack_pq, unpack_with};

let packed = pack_pq(b"hello", MessageType::Direct, &alice, &bob, &sign_sk, &enc_pk)?;

let unpacked = unpack_with(
    &packed.bytes,
    DecryptionKey::MlKem768X25519(&enc_seed),
    VerifyingKey::MlDsa65(&verify_pk),
)?;
```

Both key enums are tagged rather than inferred from length, because the two KEMs
take a 32-byte private key each — the hybrid's is a seed — so nothing about the
value says which it is, and choosing wrong is a decapsulation failure that reads
as a bad key. §8.2.1 settles it from the recipient VID's declared key type.

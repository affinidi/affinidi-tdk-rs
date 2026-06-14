# Testing cookbook

Copy-paste scenarios for writing Affinidi TDK integration tests with **no
external infrastructure** — no Redis, no network, no standing services.

There are two paths:

- **Rust fixtures** (this page, most of it) — pull a fixture crate in as a
  `dev-dependency` and stand up mediators, DID resolution, and credential flows
  in-process. Three lines for a working mediator; a handful for an
  issue/present/verify round trip.
- **Language-agnostic** — `docker compose up` a known-good mediator + Redis +
  did:web host and point any client (any language) at it. See
  [Composed test stack](#composed-test-stack-any-language) below and
  [`docker-compose.md`](docker-compose.md).

The two fixture crates:

| Crate | Owns | Pull in as |
|-------|------|------------|
| [`affinidi-messaging-test-mediator`] | embedded mediator(s): `TestMediator`, `TestEnvironment`, `TestTopology` | `affinidi-messaging-test-mediator = "0.2"` |
| [`affinidi-tdk-test-support`] | did:web mock, deterministic resolver, seeded DIDs, credential scenarios, vector loader | `affinidi-tdk-test-support = "0.7"` |

> Every `affinidi-tdk-test-support` snippet below mirrors a **runnable,
> CI-compiled doc example** on the corresponding module (`cargo test --doc`), so
> the API shown here is the API that compiles. The mediator/SDK snippets are
> marked `ignore` because they need an async runtime and the full SDK; they
> follow the patterns covered by that crate's own integration tests.

---

## 1. A mediator in three lines

```rust,ignore
use affinidi_messaging_test_mediator::TestMediator;

let mediator = TestMediator::spawn().await.unwrap();
let endpoint = mediator.endpoint();   // http://127.0.0.1:<ephemeral>
let did = mediator.did();             // freshly-generated did:peer
// ... drive the SDK against `endpoint` / `did` ...
mediator.shutdown();
mediator.join().await.unwrap();
```

A fully-functional mediator on an ephemeral `127.0.0.1` port, `MemoryStore`
backend, random JWT signing key — all `did:peer`, so no network. For on-disk
persistence semantics, the builder takes a `FjallStore` backend.

## 2. Named users, end to end

`TestEnvironment` bundles a mediator, an SDK client (`env.atm`), and named users
whose DIDs already point at the mediator as their DIDComm service.

```rust,ignore
use affinidi_messaging_test_mediator::TestEnvironment;

let env = TestEnvironment::spawn().await.unwrap();
let alice = env.add_user("Alice").await.unwrap();
let bob = env.add_user("Bob").await.unwrap();

// Exercise the SDK against `env.atm`, `alice.profile`, `bob.profile` ...

env.shutdown().await.unwrap();
```

Each user is registered `LOCAL, ALLOW_ALL` and their secrets inserted into the
mediator's resolver, so you can pack/unpack without further wiring. See the
crate's README for ACL modes, WebSocket auth, and the local-vs-remote routing
footgun (use the mediator's **DID**, not its URL, as a user's service URI).

## 3. Two-hop forward across two mediators

`TestTopology` spawns N relay mediators in one process and routes a message
through them — the routing-2.0 double-forward, no Redis. This is the home for
the relay e2e (#385/#388).

```rust,ignore
use std::time::Duration;
use affinidi_messaging_test_mediator::TestTopology;

let topology = TestTopology::builder()
    .mediators(2)
    .spawn()
    .await
    .unwrap();

let alice = topology.add_user(0, "Alice").await.unwrap();  // on mediator 0
let bob = topology.add_user(1, "Bob").await.unwrap();      // on mediator 1

// Alice -> Bob, traversing both mediators; returns Bob's received text.
let received = topology
    .forward(0, &alice, 1, &bob, "hello across two hops", Duration::from_secs(15))
    .await
    .unwrap();
assert_eq!(received.as_deref(), Some("hello across two hops"));

topology.shutdown().await.unwrap();
```

`.rewrap()` switches the relay to rewrap mode (preserving the inner
recipient-addressed envelope); `.configure_each(|b| ...)` sets per-node backend
knobs (e.g. Fjall or Redis).

## 4. did:web / did:webvh mock + fault injection

`MockDidWebServer` serves DID documents and `did:webvh` logs from an ephemeral
loopback port so a test exercises the real HTTP fetch path — including the
failure modes that matter for resolver hardening.

```rust,ignore
use affinidi_tdk_test_support::did_web::{Fault, MockDidWebServer};

let server = MockDidWebServer::start().await;
server.register_did_document(&[], &did_document);   // serves /.well-known/did.json

// "Rotation": re-register the same location with the next document version.
server.register_did_document(&[], &rotated_document);

// Resolver hardening — every later response carries the fault until cleared:
server.set_fault(Fault::Delay(std::time::Duration::from_secs(5))); // slow origin
server.set_fault(Fault::Status(503));                               // error status
server.set_fault(Fault::Hang);                                      // never responds
server.set_fault(Fault::Oversize(10_000_000));                     // size-limit guard
server.clear_fault();

assert_eq!(server.hits("/.well-known/did.json"), 0); // count actual fetches
```

`Fault` is `#[non_exhaustive]` — match arms need a `_`. For `did:webvh`, mint the
DID with `server.webvh_authority()` (`localhost%3A<port>`).

## 5. A deterministic resolver (no network, no faults)

When you don't need an HTTP server, `StaticResolver` returns canned outcomes for
known DIDs and records every call — ideal for cache-stampede / fall-through
tests.

```rust,ignore
use affinidi_tdk_test_support::resolver::{Outcome, StaticResolver};

let resolver = StaticResolver::new()
    .resolves("did:web:good.example", good_doc)          // happy path
    .outcome("did:web:flaky.example", Outcome::Fails("boom".into()))
    .default_outcome(Outcome::NotHandled);               // unknown -> falls through

// ... drive resolution-dependent code against `resolver` ...
assert_eq!(resolver.call_count("did:web:good.example"), 1);
```

`Outcome` is `#[non_exhaustive]` and also models `Delays { after, then }` and
`Hangs` for timeout tests; `Outcome::resolves_after(dur, doc)` is the shorthand.

## 6. Reproducible identities (seeded `did:peer`)

Random test DIDs can't reproduce a CI failure or back a golden-file assertion.
Seed them instead: **same seed → same DID, keys, and key ids**, every run.

```rust,ignore
use affinidi_tdk_test_support::determinism::didcomm_identity_from_seed;

// Ed25519 verification + X25519 encryption did:peer, with a DIDComm service.
let (did, secrets) =
    didcomm_identity_from_seed(7, Some("https://mediator.example/".into())).unwrap();

// Same seed, same identity — anywhere, any run.
let (did_again, _) = didcomm_identity_from_seed(7, None).unwrap(); // (no service: a different DID)
```

`did_peer_from_seed(seed, &[(purpose, key_type), ...], service)` gives explicit
control over the key list; `seeded_secret(key_type, &seed)` is the low-level
primitive. **TEST-ONLY** — seeded keys are predictable; never a production key.

## 7. Credentials: issue → present → verify

`CredentialScenario` stands up a deterministic issuer, holder, and verifier plus
an in-memory revocation status list — the home for the W4/W5 negatives. All
synchronous, no network.

```rust
use affinidi_tdk_test_support::credential_scenario::CredentialScenario;
use serde_json::json;

let scenario = CredentialScenario::new();
let aud = scenario.verifier.did().to_string();

let vc = scenario
    .issue_sd_jwt_vc(
        "https://example.com/IdentityCredential",
        &json!({ "given_name": "Alice", "email": "alice@example.com" }),
        &json!({ "_sd": ["given_name", "email"] }),   // selectively disclosable
    )
    .unwrap();

// Holder presents only `given_name`, bound to the verifier (aud) + nonce.
let presentation = scenario.present(&vc, &["given_name"], &aud, "nonce-1").unwrap();

let result = scenario.verify(&presentation, &aud, "nonce-1").unwrap();
assert!(result.is_verified());
assert_eq!(result.claims["given_name"], "Alice");
assert!(result.claims.get("email").is_none(), "email was not disclosed");
```

### Revocation

```rust
let mut scenario = CredentialScenario::new();
let index = scenario.allocate_status();   // bind the VC to a status-list index
// ... issue a VC carrying `index`, present it ...

assert!(!scenario.is_revoked(index).unwrap());
scenario.revoke(index).unwrap();
assert!(scenario.is_revoked(index).unwrap());
// A status-aware verifier accepts only when crypto verifies AND not revoked.
```

The signature still verifies after revocation (revocation is orthogonal to
signing) — the accept decision must additionally consult `is_revoked`. The
disallowed-`alg` and wrong-holder-key negatives use `verify_with` /
`issue_sd_jwt_vc_with_signer`; see `tests/credential_scenario.rs`.

## 8. mdoc (ISO 18013-5) and OID4VP

The same three identities back the mdoc path and the OID4VP envelope, so one
scenario covers both eIDAS mandatory formats (`vc+sd-jwt` and `mso_mdoc`).

```rust
use affinidi_tdk_test_support::credential_scenario::CredentialScenario;
use std::collections::BTreeMap;
use serde_json::json;

let scenario = CredentialScenario::new();
const DOC_TYPE: &str = "eu.europa.ec.eudi.pid.1";

let mdoc = scenario
    .issue_mdoc(DOC_TYPE, DOC_TYPE, &json!({ "given_name": "Erika", "age_over_18": true }))
    .unwrap();

let mut requested = BTreeMap::new();
requested.insert(DOC_TYPE.to_string(), vec!["age_over_18".to_string()]);
let response = scenario.present_mdoc(&mdoc, &requested).unwrap();

let mso = scenario.verify_mdoc(&response).unwrap();   // issuerAuth + digests
assert_eq!(mso.doc_type, DOC_TYPE);
assert_eq!(response.disclosed_names(DOC_TYPE), vec!["age_over_18"]); // selective
```

For the OID4VP envelope (`oid4vp_request` / `oid4vp_present_sd_jwt` /
`oid4vp_present_mdoc` / `oid4vp_verify_*`), holder binding via device auth, and
the nonce-replay / tampered-token negatives, see `tests/oid4vp_flow.rs` and
`tests/mdoc_scenario.rs`.

## 9. Shared test vectors (KATs)

Keep known-answer-test vectors under `<crate>/tests/vectors/<source>/…` and load
them through one helper:

```rust,no_run
use affinidi_tdk_test_support::vectors;

// Resolves relative to `<crate>/tests/vectors/`.
let kat: serde_json::Value = vectors::load_json("dif-bbs/signature.json").unwrap();
let all = vectors::load_json_dir("dif-bbs").unwrap();   // every *.json in a dir
```

---

## Composed test stack (any language)

For non-Rust clients — or a realistic Redis-backed target this repo's
`MemoryStore` can't model — bring up a known-good mediator + Redis + static
did:web host with fixed, committed **TEST-ONLY** identities:

```bash
docker compose -f docker-compose.test.yml up --build
# mediator → http://localhost:7037/mediator/v1/   did:web → http://localhost:8080
```

Fixed identities, the regeneration recipe, and the smoke test are documented in
[`docker-compose.md`](docker-compose.md).

---

## Stability

`affinidi-tdk-test-support` is a `0.x` testing crate: minor releases may evolve
the API, but breaking changes get a minor bump and a `CHANGELOG` entry. Fixture
config enums (`Fault`, `Outcome`) and error enums are `#[non_exhaustive]`, so new
variants land additively — match arms need a `_` wildcard.
`affinidi-messaging-test-mediator` follows the same convention; see each crate's
README and `CHANGELOG`.

[`affinidi-messaging-test-mediator`]: ../../crates/messaging/affinidi-messaging-test-mediator
[`affinidi-tdk-test-support`]: ../../crates/tdk/affinidi-tdk-test-support

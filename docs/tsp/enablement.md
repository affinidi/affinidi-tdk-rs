# Enabling TSP on a mediator (operator guide)

How to turn on the **Trust Spanning Protocol (TSP)** for an Affinidi Messaging
mediator you operate. This is the deployment-side companion to the
developer-focused [TSP cookbook](./cookbook.md); for wire-level interop status
see [interop.md](./interop.md).

TSP is **additive alongside DIDComm** — a single mediator carries both on the
same HTTPS/WSS endpoints, sniffing each inbound message at ingress. Turning TSP
on never changes the DIDComm path.

---

## TL;DR

There are only two things to get right:

1. **Build the mediator with the `tsp` cargo feature** (alongside `didcomm`).
   TSP is entirely compile-time gated — there is **no runtime switch, no
   `[tsp]` config section, and no environment variable**.
2. **Make sure the mediator's DID document advertises a `TSPTransport`
   service** so other mediators can discover its TSP endpoint. Whether you have
   to do anything for step 2 depends on the DID method (see the matrix below).

Nothing else "turns TSP on." The mediator derives its TSP identity from the
Ed25519 (`authentication`) and X25519 (`keyAgreement`) keys already in its DID
document — no new keys, no extra secrets.

---

## Step 1 — build with the `tsp` feature

The mediator's default features are `["didcomm", "redis-backend"]` and do **not**
include TSP. `didcomm` and `tsp` are additive (not mutually exclusive); the
supported production shape is a **dual `didcomm,tsp` build**:

```bash
# from crates/messaging/affinidi-messaging-mediator
cargo build --release --no-default-features \
  --features didcomm,tsp,redis-backend
```

```toml
# or, as a dependency
affinidi-messaging-mediator = { version = "0.16", features = ["didcomm", "tsp"] }
```

> The crate `compile_error!`s if neither `didcomm` nor `tsp` is enabled. A
> `tsp`-only build compiles but is not a first-class supported deployment — run
> it with `didcomm` too.

If you provision with the **setup wizard** (`mediator-setup`), select the `tsp`
protocol (in the TUI, or `protocols = ["didcomm", "tsp"]` in a recipe). The
wizard translates that into the cargo features for the build and — as of setup
`0.1.15` — also bakes the `TSPTransport` service into the DID it generates (see
step 2).

---

## Step 2 — advertise a `TSPTransport` service

For routed / nested forwarding, a remote mediator resolves your mediator's DID
document and looks for a `TSPTransport` service (constant
`affinidi_tsp::TSP_SERVICE_TYPE`). TSP and DIDComm **share the mediator's
`/inbound`**, so the TSP endpoint is the same URI as the `DIDCommMessaging`
endpoint.

Whether you need to do anything depends on how the DID document is bound to the
DID:

| DID method | Who adds `TSPTransport` | What you do |
|------------|-------------------------|-------------|
| **did:web** | The mediator, **at startup** — it mirrors the `DIDCommMessaging` endpoint into a `#tsp` service on the served document. | Nothing. |
| **did:webvh** | Baked in **at DID generation** (the document is hash-bound; the running mediator cannot mutate it). The setup wizard does this for you. | Nothing if you use the wizard; otherwise add it before publishing (below). |
| **did:peer** | Baked in **at DID generation** (the document is derived from the DID string). The setup wizard does this for you. | Nothing if you use the wizard; otherwise add it (below). |
| **did:key** | — | Not usable: `did:key` cannot carry a service endpoint, so a `did:key` mediator cannot advertise TSP to remote peers. Direct local pickup still works, but routed/nested forwarding to it will not. |
| **VTA-managed** | The VTA renders the DID document server-side. | The VTA's mediator template must advertise `TSPTransport`; the local wizard cannot inject it into a VTA-minted DID. |

If TSP is enabled but the resolved document has no `TSPTransport` service, the
mediator logs a **startup warning** — remote peers won't be able to route TSP to
you (direct local delivery is unaffected).

### Hand-rolling the service (non-wizard DIDs)

Use the full `TSPTransport` type for `did:web` / `did:webvh`, pointing at the
same URI as your `DIDCommMessaging` endpoint:

```jsonc
{
  "id": "did:web:mediator.example.com#tsp",
  "type": "TSPTransport",
  "serviceEndpoint": "https://mediator.example.com/mediator/v1"
}
```

For `did:webvh` add this to the document **before** the log entry is created, so
the `TSPTransport` service is covered by the SCID.

For **`did:peer`** use the `tsp` service abbreviation (the resolver expands it to
`TSPTransport`) — e.g. a service segment `{"t":"tsp","s":"https://mediator.example.com/mediator/v1"}`.

---

## What you do *not* need to configure

- **No `[tsp]` config section and no TSP environment variable.** `mediator.toml`
  needs no TSP keys.
- **No new key material.** The mediator's TSP identity (its VID + signing +
  key-agreement keys) is derived from the Ed25519 and X25519 keys already in its
  DID document, resolved through the same secrets backend DIDComm uses.
- **No separate ingress endpoint.** Inbound bytes are classified automatically —
  a TSP CESR envelope vs a DIDComm JWE/JWS — on both the REST `/inbound` route
  and WebSocket binary frames.

Client authentication also comes for free: dual-protocol clients reuse the
DIDComm-authenticated JWT session, and pure-TSP clients can authenticate over
`/tsp/authenticate` (which mints the same session). See the cookbook's
[Authentication](./cookbook.md#authentication) section.

---

## Verifying it's on

1. **Startup logs** — with `tsp` built in, a missing `TSPTransport` service
   produces the warning described above. No warning (and a `#tsp` service in the
   resolved document) means discovery is wired.
2. **Resolve your DID** and confirm a `TSPTransport` (or, for `did:peer`, `tsp`)
   service is present with your `/inbound` base as its endpoint.
3. **Send a TSP message** — the end-to-end flows (Direct, routed relay,
   TSP↔DIDComm bridge, remote forwarding) are exercised by the
   `affinidi-messaging-test-mediator` integration tests
   (`tests/tsp_delivery.rs`, `tests/tsp_federation.rs`), which are the runnable
   source of truth.

---

## See also

- [TSP cookbook](./cookbook.md) — sending/receiving, relationships, WebSocket,
  Trust Tasks over TSP.
- [TSP interop status](./interop.md) — wire compatibility with the ToIP
  reference implementation.

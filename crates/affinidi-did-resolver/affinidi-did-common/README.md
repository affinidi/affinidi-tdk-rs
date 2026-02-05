# Affinidi DID Common Library

Contains common structs, traits and methods relating to Decentralized Identifiers
([DID](https://www.w3.org/TR/did-1.1/))

## Prerequisites

Rust version 1.90

## Building DID Documents

The crate provides builder types (`DocumentBuilder`, `VerificationMethodBuilder`,
`ServiceBuilder`) for ergonomic, programmatic construction of DID Documents.

### Creating a DID Document with a Service

```rust
use affinidi_did_common::{DocumentBuilder, ServiceBuilder, VerificationMethodBuilder};
use serde_json::json;

// 1. Build a verification method
let vm = VerificationMethodBuilder::new(
    "did:example:123#key-1",
    "Multikey",
    "did:example:123",
)
.unwrap()
.public_key_multibase("z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK")
.build();

// 2. Build a service with a simple URL endpoint
let linked_domain = ServiceBuilder::new_with_url(
    "LinkedDomains",
    "https://example.com",
)
.unwrap()
.id("did:example:123#linked-domain")
.unwrap()
.build();

// 3. Build a DIDComm service with a map endpoint and extra properties
let didcomm = ServiceBuilder::new_with_map(
    "DIDCommMessaging",
    json!({
        "uri": "https://example.com/didcomm",
        "accept": ["didcomm/v2"],
        "routingKeys": ["did:example:123#key-1"]
    }),
)
.id("did:example:123#didcomm")
.unwrap()
.build();

// 4. Assemble the full document
let doc = DocumentBuilder::new("did:example:123")
    .unwrap()
    .context_did_v1()
    .context_multikey_v1()
    .verification_method(vm)
    .authentication_reference("did:example:123#key-1")
    .unwrap()
    .assertion_method_reference("did:example:123#key-1")
    .unwrap()
    .service(linked_domain)
    .service(didcomm)
    .build();

assert_eq!(doc.service.len(), 2);
```

### Service endpoint variants

The `ServiceBuilder` supports both endpoint forms defined by the
[CID specification](https://www.w3.org/TR/cid-1.0/#services):

| Endpoint form | Constructor |
|---|---|
| Single URL string | `ServiceBuilder::new_with_url("type", "https://...")` |
| Map or ordered set | `ServiceBuilder::new_with_map("type", json!({...}))` |
| Pre-built `Endpoint` | `ServiceBuilder::new("type", endpoint)` |

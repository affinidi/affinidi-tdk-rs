# did-peer Rust implementation

Only supports did:peer numalgo 0,2 (did:peer:0, did:peer:2)

NOTE:
  The DID Peer Spec incorrectly specifies `VerificationMethod` and `Service`
  id's as relative URI fragments instead of absolute URI's.

  To address this, we prepend the full DID before the #fragment

## Build a WebAssembly package

**Prerequisite:** [wasm-pack](https://rustwasm.github.io/wasm-pack/installer/)

`wasm-pack build --target web --out-dir www/pkg`

this places compiled wasm files into the ./www/pkg/ directory.

Serve the website locally, run from the ./www/ directory of the project
`python3 -m http.server`

Website available [here](http://127.0.0.1:8000)

## Examples

To run examples `cargo run --example <command>`

Generate a random did:peer and corresponding DID document
`cargo run --example generate`

Resolve a did:peer to a DID Document
`cargo run --example resolve <did:peer:2.*>`

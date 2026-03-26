# affinidi-messaging-didcomm

A lean DIDComm v2.1 implementation for the Affinidi TDK.

## Features

- **Authcrypt** (ECDH-1PU+A256KW, A256CBC-HS512) — authenticated encryption
- **Anoncrypt** (ECDH-ES+A256KW, A256CBC-HS512) — anonymous encryption
- **Signed messages** (EdDSA / Ed25519)
- **Plaintext messages**
- **Forward/routing** (DIDComm Routing Protocol 2.0)
- **Curves**: X25519, P-256, K-256 (secp256k1)

## Optional features

- `messaging-core` — implements the `MessagingProtocol` trait from `affinidi-messaging-core`, enabling protocol-agnostic usage alongside `affinidi-tsp`.

## License

See [LICENSE](../../../LICENSE) for details.

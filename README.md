# Affinidi Messaging Framework

Affinidi Messaging Framework utilises existing open standards and cryptographic
techniques to provide secure, private, and verifiable digital communication.

The Affinidi Messaging Framework offers libraries and tools for implementing the
[DIDComm Messaging](https://identity.foundation/didcomm-messaging/spec/) protocol,
which builds upon the decentralized architecture of the
[Decentralised Identifier (DID)](https://www.w3.org/TR/did-1.0/) standard.
This framework includes packages designed to enable secure and private messaging,
as well as capabilities for discovering and establishing connections with individuals,
businesses, or AI agents.

## What is DIDComm

The DIDComm Messaging protocol is an open standard for implementing decentralised
communication. It is built on top of the Decentralised Identifier (DID) design,
which enables verifiable digital identity and establishes a secure channel for
communication between parties. It provides end-to-end encryption and message
verifiability in a decentralised manner without relying on a central system.

DIDComm Messaging works seamlessly with the Self-Sovereign Identity (SSI) model
and provides the communication layer in the SSI ecosystem, allowing users complete
control over their privacy and identity at every stage of digital interactions.

## Why DIDComm Matters

**Privacy by Design**: Messages are sent with end-to-end encryption by default
and minimise exposure of metadata, ensuring that only the intended recipient can
see the content of the message, and the messaging server doesn’t have access to
it.

**Trusted Digital Interaction**: DIDComm uses Decentralised Identifier (DID),
which enables signing and verifying the authenticity of the content sent by
another party. DIDComm provides the option to authenticate both parties to verify
their identity mutually, reducing the risk of fraud, especially when communicating
with businesses and AI agents.

**End-to-end Encryption**: It utilises Public Key Cryptography to encrypt the
message using the recipient’s public key published through DID, ensuring
only the recipient or the owner of the DID can decrypt and access the content.

**Flexible Implementation**: DIDComm is a highly extensible protocol allowing you
to implement other use cases beyond the usual chat or messaging app. DIDComm
provides the flexibility to work as a transport layer for an API platform instead
of the usual HTTP/S for request and response. DIDComm can also work with other
open standards like OID4VCI and OID4VP for credential issuance and sharing across
different platforms.

**Interoperability**: DIDComm is transport-agnostic, meaning it can work across
different devices and establish communication over HTTP, WebSockets, Bluetooth,
and other communication channels. DIDComm does not rely on the transport channel
to provide the security required for trusted communication.

> **IMPORTANT:**
> affinidi-tdk crate is provided "as is" without any warranties or guarantees,
> and by using this framework, users agree to assume all risks associated with its
> deployment and use including implementing security, and privacy measures in their
> applications. Affinidi assumes no liability for any issues arising from the use
> or modification of the project.

## Table of Contents

- [Core Concepts](#core-concepts)
- [Requirements](#requirements)
- [Overall Crate Structure](#overall-crate-structure)
- [Support & feedback](#support--feedback)
- [Contributing](#contributing)

## Core Concepts

- **Decentralised Identifier (DID)** - A globally unique identifier that enables
  secure interactions. The DID is the cornerstone of Self-Sovereign Identity (SSI),
  a concept that aims to put individuals or entities in control of their digital
  identities.

- **DID Document** - A DID is a URI (Uniform Resource Identifier) that resolves
  into a DID Document that contains information such as cryptographic public keys,
  authentication methods, and service endpoints. It allows others to verify
  signatures, authenticate interactions, and validate data cryptographically.

- **Envelope Encryption** - A cryptographic technique that uses multiple layers of
  encryption to protect the data. A Data Encryption Key (DEK) encrypts the data,
  and then the Key Encryption Key (KEK) encrypts the DEK. This layered approach
  enhances security by protecting the data and the key to access it.

- **Mediator** - A service that handles and routes messages sent between
  participants (e.g., users, organisations, another mediator, or even AI agents).

- **DIDComm Message** - usually called DIDComm Encrypted Message is a JSON Web
  Message (JWM), a lightweight, secure, and standardised format for structured
  communication using JSON. It represents headers, message types, routing metadata,
  and payloads designed to enable secure and interoperable communication across
  different systems.

## Requirements

- Rust (1.85.0) 2024 Edition

- Redis 8.0

## Overall Crate Structure

Affinidi Messaging consists of different crates, each providing various libraries
and tools that form the framework. Each crate has embedded sub-crates that provide
different capabilities to support and run the main crate.

### Affinidi Messaging

A messaging framework built on DIDComm protocol that facilitates confidential and
secure exchanges between senders and recipients.

[Set up Affinidi Messaging](./crates/affinidi-messaging/) and host your mediator
to enable secure and private communication within your network.

### Affinidi DID Resolver

A high-performance service that resolves and caches the DID document for a certain
period, for faster resolution of DID documents and processing of messages.

### Affinidi Meeting Place

Affinidi Meeting Place provides a safe and secure method for discovering and
connecting with others using decentralised identifiers (DIDs) and the DIDComm
Messaging protocol.

### Affinidi TDK

The Affinidi Trust Development Kit (TDK) provides common elements for developing
privacy-preserving services using decentralised identity technologies.

## Support & feedback

If you face any issues or have suggestions, please don't hesitate to contact us
'using [this link](https://share.hsforms.com/1i-4HKZRXSsmENzXtPdIG4g8oa2v).

### Reporting technical issues

If you have a technical issue with Affinidi Messaging's codebase, you can also
create an issue directly in GitHub.

1. Ensure the bug was not already reported by searching on GitHub under
   [Issues](https://github.com/affinidi/affinidi-tdk-rs/issues).

2. If you're unable to find an open issue addressing the problem,
   [open a new one](https://github.com/affinidi/affinidi-tdk-rs/issues/new).
   Be sure to include a **title and clear description**, as much relevant
   information as possible,
   and a **code sample** or an **executable test case** demonstrating the expected
   behaviour that is not occurring.

## Contributing

Want to contribute?

Head over to our [CONTRIBUTING](https://github.com/affinidi/affinidi-tdk-rs/blob/main/CONTRIBUTING.md)
guidelines.

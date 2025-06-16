# Affinidi Messaging Framework

Affinidi Messaging Framework is a secure, private, and verifiable digital
communication framework.

Affinidi Messaging Framework provides the libraries and tools for implementing the
[DIDComm Messaging](https://identity.foundation/didcomm-messaging/spec/) protocol,
which is built on top of the decentralised design of the
[Decentralised Identifier (DID)](https://www.w3.org/TR/did-1.0/) standard. This
framework provides packages for secure and private messages and for discovering
and connecting with others, whether a person, a business, or an AI agent.

> **IMPORTANT:**
> affinidi-tdk crate is provided "as is" without any warranties or guarantees,
and by using this framework, users agree to assume all risks associated with its
deployment and use including implementing security, and privacy measures in their
applications. Affinidi assumes no liability for any issues arising from the use
or modification of the project.

## Table of Contents

- [Core Concepts](#core-concepts)
- [Requirements](#requirements)
- [Overall Crate Structure](#overall-crate-structure)
- [Support & feedback](#support--feedback)
- [Contributing](#contributing)

## Core Concepts

The Affinidi Messaging Framework utilises existing open standards and cryptographic
techniques to provide secure, private, and verifiable communication.

- **Decentralised Identifier (DID)** - A globally unique identifier that enables
secure interactions. The DID is the cornerstone of Self-Sovereign Identity (SSI),
a concept that aims to put individuals or entities in control of their digital
identities.

- **DID Document** - A DID is a URI (Uniform Resource Identifier) that resolves
into a DID Document that contains information such as cryptographic public keys,
authentication methods, and service endpoints. It allows others to verify
signatures, authenticate interactions, and validate data cryptographically.

- **Envelope Encryption** - A cryptographic technique that uses multiple layers of
encryption to protect the data. A Data Encryption Key (DEK) encrypts the data, and
then the Key Encryption Key (KEK) encrypts the DEK. This layered approach enhances
security by protecting the data and the key to access it.

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

a DIDComm-based messaging framework that enables private and secure communication
between senders and receivers.

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


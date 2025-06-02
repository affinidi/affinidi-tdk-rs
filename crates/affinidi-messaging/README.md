# Affinidi Messaging

A secure, private and trusted messaging service based on DIDComm Messaging protocol. DIDComm Messaging protocol is built on top of the decentralised design of a Decentralised Identifier (DID) for secure and privacy-preserving digital communication. 

Following the DID design, it utilises public key cryptography for signing and encrypting to ensure the secure and private transport of messages to the intended recipient, establishing verifiable and trusted communication.

The Affinidi Messaging is built using [Rust](https://www.rust-lang.org/) language and works with different In-Memory data storage like Redis.

> **IMPORTANT:**
> Affinidi Messaging is provided "as is" without any warranties or guarantees, and by using this framework, users agree to assume all risks associated with its deployment and use including implementing security, and privacy measures in their applications. Affinidi assumes no liability for any issues arising from the use or modification of the project.

## Crate Structure

The `affinidi-messaging` is the overall crate and currently has the following sub-crates embedded in it:

- **affinidi-messaging-sdk** - a Software Development Kit (SDK) to simplify the implementation of Affinidi Messaging into your application.

- **affinidi-messaging-mediator** - the Mediator backend service for message handling and relaying.

- **affinidi-messaging-helpers** - it contains tools to help with setting up and managing Mediator service including running examples for Affinidi Messaging.

- **affinidi-messaging-didcomm** - Affinidi Messaging DIDComm implementation, a modified version of [didcomm-rust](https://github.com/sicpa-dlab/didcomm-rust) project.

- **affinidi-messaging-text-client** - A terminal based DIDComm chat client, useful for interacting with Mediators.

Affinidi Messaging also depends on [affinidi-did-resolver](../affinidi-did-resolver/) for resolving and caching DID Document from the list of supported DID methods.

## Running Affinidi Messaging - Mediator Service

Refer to [affinidi-messaging-mediator](./affinidi-messaging-mediator#running-affinidi-messaging-mediator-service) on setting up and managing the Mediator service on your local environment.

## Running Affinidi Messaging Examples

Go to the [affinidi-messaging-helpers](./affinidi-messaging-helpers/) crate to run the available sample codes and learn more about Affinidi Messaging.

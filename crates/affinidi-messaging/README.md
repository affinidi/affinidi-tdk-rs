# Affinidi Messaging

## Overview

A secure, private and trusted messaging framework based on DIDComm Messaging protocol.

DIDComm Messaging protocol is built on top of the decentralised design of a Decentralised Identifier (DID) for secure and privacy-preserving digital communication. By following the DID design, it utilities public key cryptography to ensure the secure and private transport of messages to the intended recipient, establishing trust.

This messaging framework is built using [Rust](https://www.rust-lang.org/) language.

> **IMPORTANT:**
> Affinidi Messaging is provided "as is" without any warranties or guarantees, and by using this framework, users agree to assume all risks associated with its deployment and use including implementing security, and privacy measures in their applications. Affinidi assumes no liability for any issues arising from the use or modification of the project.

## Crate Structure

`affinidi-messaging` is the overall crate. It currently has the following sub-crates embedded in it:

- **affinidi-messaging-sdk** - a Software Development Kit (SDK) to simplify the implementation of Affinidi Messaging into your application.
- **affinidi-messaging-mediator** - Affinidi Messaging Mediator Service is used for message handling and relaying.
- **affinidi-messaging-helpers** - Tools to help with setting up, managing and running examples against Affinidi Messaging
- **affinidi-messaging-processor** - Affinidi Messaging Processor and Management Service.
- **affinidi-messaging-didcomm** - Affinidi Messaging DIDComm implementation, a modified version of [didcomm-rust](https://github.com/sicpa-dlab/didcomm-rust) project.
- **affinidi-messaging-text-client** - A terminal based DIDComm chat client that can be useful for interacting with Mediators.

It also depends on external Affinidi crates:

- [affinidi-did-resolver-cache-sdk](https://crates.io/crates/affinidi-did-resolver-cache-sdk)
- [did-peer](https://crates.io/crates/did-peer)

both sourced [here](https://github.com/affinidi/affinidi-did-resolver).

## Prerequisites

Refer to [affinidi-messaging-mediator - Prerequisites](./affinidi-messaging-mediator#prerequisites).

## Running affinidi-messaging-mediator service

Refer to [affinidi-messaging-mediator - Running affinidi-messaging-mediator service](./affinidi-messaging-mediator#running-affinidi-messaging-mediator-service).

## Examples

Go to the [affinidi-messaging-helpers example](./affinidi-messaging-helpers/examples/) crate to run the available sample codes and learn more about Affinidi Messaging.

## Support & Feedback

If you face any issues or have suggestions, please don't hesitate to contact us using [this link](https://www.affinidi.com/get-in-touch).

### Reporting Technical Issues

If you have a technical issue with the Affinidi Messaging GitHub repo, you can also create an issue directly in GitHub.

If you're unable to find an open issue addressing the problem, [open a new one](https://github.com/affinidi/affinidi-messaging/issues/new). Be sure to include a **title and clear description**, as much relevant information as possible, and a **code sample** or an **executable test case** demonstrating the expected behavior that is not occurring.

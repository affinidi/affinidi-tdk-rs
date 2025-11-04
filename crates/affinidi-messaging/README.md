# Affinidi Messaging

A secure, private, and trusted messaging service built on the DIDComm v2 protocol,
which leverages the decentralized architecture of Decentralized Identifiers (DIDs)
to enable privacy-preserving and authenticated digital communication.

In accordance with the Decentralized Identifier (DID) framework, it utilises
public key cryptography to digitally sign and encrypt messages, ensuring their
secure and confidential transmission exclusively to the intended recipient. This
approach establishes communication that is both verifiable and trustworthy.

The Affinidi Messaging was created using [Rust](https://www.rust-lang.org/) language
and works with different in-memory data storage systems like Redis.

> **IMPORTANT:**
> Affinidi Messaging is provided "as is" without any warranties or guarantees,
> and by using this framework, users agree to assume all risks associated with its
> deployment and use including implementing security, and privacy measures in their
> applications. Affinidi assumes no liability for any issues arising from the use
> or modification of the project.

## Crate Structure

The `affinidi-messaging` crate includes the following sub-crates:

- **affinidi-messaging-didcomm** - Affinidi Messaging DIDComm implementation, a
  modified version of [didcomm-rust](https://github.com/sicpa-dlab/didcomm-rust)
  project.

- **affinidi-messaging-helpers** - contains tools to help set up and manage Mediator
  service, including running examples for Affinidi Messaging.

- **affinidi-messaging-mediator** - the Mediator backend service for message
  handling and relaying.

- **affinidi-messaging-sdk** - a Software Development Kit (SDK) to simplify the
  implementation of Affinidi Messaging into your application.

- **affinidi-messaging-text-client** - A terminal-based DIDComm chat client useful
  for interacting with mediators.

Affinidi Messaging also depends on [affinidi-did-resolver](../affinidi-did-resolver/)
which resolve and cache DID Documents from the list of supported DID methods.

## Running Affinidi Messaging - Mediator Service

Set up and manage the mediator service in your local environment.

1. Run the Redis docker container using the command below:

   ```bash
   docker run --name=redis-local --publish=6379:6379 --hostname=redis --restart=on-failure
   --detach redis:latest
   ```

   The latest supported version of Redis is version 8.0.

2. Run `setup_environment` to configure the mediator with all the required
   information to run locally.

   You must run the following from the top-level directory of `affinidi-messaging`.

   ```bash
   cargo run --bin setup_environment
   ```

   This will generate:
   - Mediator DID and secrets.
   - Administration DID and secrets.
   - SSL Certificates for local development/testing.
   - Optionally, different users with their DIDs for testing.

3. Start `affinidi-messaging-mediator` service via:

   ```bash
   cd affinidi-messaging-mediator
   export REDIS_URL=redis://@localhost:6379
   cargo run
   ```

## Running Affinidi Messaging Examples

Go to the [affinidi-messaging-helpers](./affinidi-messaging-helpers/) crate to run
the available sample codes and learn more about Affinidi Messaging.

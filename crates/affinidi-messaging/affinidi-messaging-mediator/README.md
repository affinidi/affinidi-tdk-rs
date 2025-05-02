# Affinidi Messaging - Mediator Service

## Overview

A DIDComm Messaging v2 mediator & relay service that listens to send &receive messages over https.

## Dependencies

To run the mediator, it requires these packages that is also part of the Affinidi Messaging project.

1. [affinidi-messaging-didcomm](../affinidi-messaging-didcomm/) - Affinidi Messaging DIDComm implementation, a modified version of [didcomm-rust](https://github.com/sicpa-dlab/didcomm-rust) project.
2. [affinidi-messaging-sdk](../affinidi-messaging-sdk/) - a Software Development Kit (SDK) to simplify the implementation of Affinidi Messaging into your application.

## Prerequisites

To build and run this project, you need to set up the following:

1. Install Rust on your machine if you haven't installed it yet using [this guide](https://www.rust-lang.org/tools/install).
2. Install Docker on your machine if you haven't installed it yet using [this guide](https://docs.docker.com/desktop/). We will need this to run Redis instance for the mediator.

## Running affinidi-messaging-mediator service

1. Run Redis docker container using the command below:

   ```bash
   docker run --name=redis-local --publish=6379:6379 --hostname=redis --restart=on-failure --detach redis:latest
   ```

2. Run `setup_environment` to configure the mediator with all the required information to run locally.

   You must run the following from the top-level directory of `affinidi-messaging`

   ```bash
   cargo run --bin setup_environment
   ```

   This will generate:

   - Mediator DID and secrets
   - Administration DID and secrets
   - SSL Certificates for local development/testing

3. Start `affinidi-messaging-mediator` service via:

   ```bash
   cd affinidi-messaging-mediator
   export REDIS_URL=redis://@localhost:6379
   cargo run
   ```

## Examples

_**NOTE:**_ _Ensure Mediator is configured and running before using the following examples._

### Mediator Specific Examples

1. Mediator Administration

You can add/remove/list administration accounts easily using the mediator_administration example

```bash
cargo run --bin mediator_administration
```

### Affinidi Messaging Examples

Refer to [affinidi-messaging-sdk - Examples](../affinidi-messaging-sdk#examples).

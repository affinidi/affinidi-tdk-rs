# affinidi-messaging-mediator-types

Protocol types shared by the Affinidi Messaging Mediator and the clients that
talk to it: ACL bits (`acls`, `acls_handler`), problem reports, message-pickup
envelopes (`messages`), account and audit records, and the injectable `Clock`.

This crate is the contract between client and mediator. The client SDK
(`affinidi-messaging-sdk`) depends on it and re-exports its types from their
original SDK paths; the mediator depends on it through
`affinidi-messaging-mediator-common`, which re-exports it as `types`. Neither
side has to depend on the other.

The mediator itself (`affinidi-messaging-mediator`, `-common`, the test
fixture, admin and TUI crates) lives in its own repository,
[affinidi/affinidi-messaging-mediator](https://github.com/affinidi/affinidi-messaging-mediator).
This crate stays here, beside the SDK, so a client never has to depend on the
mediator's repository to speak its protocol.

Dependencies are deliberately lean: `serde`, `serde_json`, `thiserror` and
`regex`.

## Features

- `tracing`: log a pre-epoch system clock from `SystemClock` (off by default).
- `test-clock`: compile `clock::TestClock` for tests. Never enable it in a
  production build.

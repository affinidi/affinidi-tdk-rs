# Affinidi Trust Development Kit

**IMPORTANT:**

> affinidi-tdk crate is provided "as is" without any warranties or guarantees, and
> by using this framework, users agree to assume all risks associated with its deployment
> and use including implementing security, and privacy measures in their applications.
> Affinidi assumes no liability for any issues arising from the use or modification
> of the project.

## Overview

Affinidi [Trust Development Kit](https://docs.affinidi.com/dev-tools/affinidi-tdk/)
simplifies development of privacy preserving solutions using decentralised
identity and data sharing technologies.

## Features

The following features are enabled for the TDK Crate

- default (Includes all crates by default)
  - messaging: Affinidi Messaging SDK Crates
  - did-peer: Peer DID Method support
  - data-integrity: W3C Data Integrity proof verification

To disable default, you can use the following:

1. To disable from the command line use the option `--no-default-features`
2. In Cargo.toml of a crate, use the `default-features = false` option on the crate
   dependency

## Support & Feedback

If you face any issues or have suggestions, please don't hesitate to contact us
using [this link](https://www.affinidi.com/get-in-touch).

### Reporting Technical Issues

If you have a technical issue with the Affinidi Messaging GitHub repo, you can also
create an issue directly in GitHub.

If you're unable to find an open issue addressing the problem,
[open a new one](https://github.com/affinidi/affinidi-tdk-rs/issues/new). Be sure
to include a **title and clear description**, as much relevant information as possible,
and a **code sample** or an **executable test case** demonstrating the expected
behavior that is not occurring.

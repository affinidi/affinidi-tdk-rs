# Affinidi DID Authentication

**IMPORTANT:**
> affinidi-did-authentication crate is provided "as is" without any warranties or guarantees, and by using this framework, users agree to assume all risks associated with its deployment and use including implementing security, and privacy measures in their applications. Affinidi assumes no liability for any issues arising from the use or modification of the project.

## Overview

Affinidi DID Authentication enables basic authentication using a DID and proof that you have access to the secrets to encrypt a server challenge. This can be used for services requiring some form of authentication/authorisation mechanism.

***NOTE: There are two implementations of DID Authentication that differ. As a result this library will detect and handle the two implementations in the interim. Once alignment is complete and refactored into Affinidi Messaging and Meeting Place - then this library will be streamlined.***

### Library Usage

### Binary Usage

You can run Affinidi DID Authentication as a binary, this allows for simple testing and/or using the binary in other applications.

There are two operating modes for the binary:

1. Use the environments pre-configured profiles
2. Manually enter a DID and corresponding Secrets

```bash
cargo run -- -a did:web:meetingplace.world environment -n Alice
```

NOTE: When manually entering a DID, you pass the secrets into STDIN

## Support & Feedback

If you face any issues or have suggestions, please don't hesitate to contact us using [this link](https://www.affinidi.com/get-in-touch).

### Reporting Technical Issues

If you have a technical issue with the Affinidi Messaging GitHub repo, you can also create an issue directly in GitHub.

If you're unable to find an open issue addressing the problem, [open a new one](https://github.com/affinidi/affinidi-tdk-rs/issues/new). Be sure to include a **title and clear description**, as much relevant information as possible, and a **code sample** or an **executable test case** demonstrating the expected behavior that is not occurring.

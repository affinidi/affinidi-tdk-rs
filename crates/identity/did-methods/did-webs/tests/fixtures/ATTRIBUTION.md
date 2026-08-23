# Test fixtures

`ENro7uf0.keri.cesr` and `ENro7uf0.did.json` are the artifacts published for

    did:webs:did-webs-service%3a7676:ENro7uf0ePmiK3jdTo2YCdXLqW7z7xoP6qhhBou6gBLe

reproduced verbatim from the Apache-2.0 licensed
[hyperledger-labs/did-webs-resolver](https://github.com/hyperledger-labs/did-webs-resolver)
reference implementation, at
`volume/dkr/examples/ENro7uf0ePmiK3jdTo2YCdXLqW7z7xoP6qhhBou6gBLe/`.

They are used unmodified as conformance vectors. Everything else this crate is
tested against, it also produced — these are the only bytes in the suite that
came from keripy, so they are the only ones that can catch us agreeing with
ourselves rather than with the ecosystem.

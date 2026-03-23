# did-ebsi

Implementation of the `did:ebsi` DID method for EBSI (European Blockchain
Services Infrastructure) legal entity identifiers.

## DID Format

```
did:ebsi:z<base58btc(0x01 + 16_random_bytes)>
```

Example: `did:ebsi:zfEmvX5twhXjQJiCWsukvQA`

## Resolution

DIDs are resolved via the EBSI DID Registry API:
- Pilot: `https://api-pilot.ebsi.eu/did-registry/v5/identifiers/{did}`
- Conformance: `https://api-conformance.ebsi.eu/did-registry/v5/identifiers/{did}`

## License

[Apache-2.0](https://github.com/affinidi/affinidi-tdk-rs/blob/main/LICENSE)

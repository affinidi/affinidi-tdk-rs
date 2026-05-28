# Affinidi Status List Changelog

## 28th May 2026 Release 0.1.2

### Security

- **HIGH — gzip-bomb DoS closed.** `BitstringStatusList::decode()` ran
  `GzDecoder::read_to_end()` on the attacker-supplied `encodedList` with
  no output limit. A few KB of crafted gzip can expand to gigabytes of
  zeros, OOMing any verifier that checks a credential's revocation
  status against a hostile status-list issuer. The decode path already
  knows exactly how many bytes it needs (`size.div_ceil(8)`), so the
  decoder is now wrapped in `.take(expected + 1)` and the existing
  length-check / truncate logic handles the rest. No change to the
  successful-decode path.

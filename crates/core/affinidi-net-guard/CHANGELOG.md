# Changelog

All notable changes to `affinidi-net-guard` are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this crate
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-09-11

Initial release: one egress guard for URLs an attacker can influence, extracted
from the SSRF guard in `affinidi-did-web` 0.1.4 and generalised. See
[ADR 0006](../../../docs/adr/0006-egress-guard-for-attacker-influenceable-urls.md).

### Added

- `classify` / `is_globally_routable` / `IpClass` / `Embedding`: pure address
  classification over the IANA special-purpose registries, including the
  IPv4-mapped, IPv4-compatible, NAT64 (`64:ff9b::/96`, `64:ff9b:1::/48`), 6to4
  and Teredo forms, which are classified by the IPv4 address they carry.
- `EgressPolicy`: `public_internet()` (https/wss, globally routable addresses,
  no special-use names, no userinfo); narrowing `with_allow_list`,
  `with_schemes` and `with_ports`; `allow_cidrs` for explicit internal ranges
  (never loopback, link-local, unspecified, multicast or broadcast); and
  `with_dev_loopback`, whose `DevLoopback` token exists only with the
  `dev-loopback` feature.
- `VettedUrl`, built only by `EgressPolicy::vet` / `vet_url`, with a canonical
  `host()` for operator display and `join_same_origin`.
- `GuardedResolver` / `guarded_dns_resolver`: a `reqwest` resolver that fails a
  name if any answer is blocked and returns only vetted addresses, closing DNS
  rebinding.
- `RedirectMode` / `redirect_policy`: `None` (default), `SameOrigin`, and
  `ReVet` (hop cap, every hop re-vetted, no https-to-http downgrade).
- `GuardedClientBuilder` / `GuardedClient`: both halves on one client, with no
  proxy, 10 s / 5 s timeouts, no `Referer` on redirects, `https_only` unless dev
  loopback, `execute` for externally built requests, and `read_body_capped`
  (1 MiB default).
- `EgressError` and `blocked_in_chain`, which recovers a refusal from a
  `reqwest::Error`.
- `conformance/egress-vectors.v1.json`, the vector file shared with the
  TypeScript and Swift guards, and a runner in the test suite that executes the
  `ip`, `url`, `names`, `scheme`, `dns`, `rebinding` and `redirect` sections
  (the last two against local TLS listeners) and skips `webvh` and
  `mediatorDoc` with a declared reason.

### Changed relative to the `affinidi-did-web` 0.1.4 guard

- Also refuses documentation, multicast, reserved, benchmarking and
  protocol-assignment space, and 6to4, Teredo and local-use NAT64 addresses
  that embed a non-routable IPv4 address.
- Also refuses the special-use names `*.internal`, `*.home.arpa` and
  single-label names.

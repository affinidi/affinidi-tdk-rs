# CORS and the `Origin` check

One setting, `[security] cors_allow_origin`, controls cross-origin access at
two enforcement points:

- **REST API** — a standard CORS layer. For an origin the policy does not
  admit, the mediator omits `Access-Control-Allow-Origin`, so the browser
  blocks the page from reading the response.
- **WebSocket upgrade (`/ws`)** — WebSocket upgrades are not subject to CORS,
  so the mediator checks `Origin` itself as defence in depth. An upgrade with
  a non-admitted `Origin` is refused with `403 origin not allowed`.

Both points share one matcher, so they cannot drift apart.

## The rule

- A request with **no** `Origin` header is admitted. The JWT is the gate.
- A request **with** an `Origin` header is admitted only if the policy admits
  that origin.

The header decides, not whether the client is a browser.

## React Native sends an `Origin`

React Native's WebSocket implementation sets an `Origin` header derived from
the connection URL. Under the default policy a React Native wallet is refused
exactly as a browser would be, and the mediator logs:

```
WebSocket upgrade rejected: Origin not permitted by CORS policy
```

The Rust SDK sends no `Origin`, so it is unaffected. If you deploy a mediator
for a mobile wallet, you must set `cors_allow_origin`.

## The three policies

| Value | Effect |
|---|---|
| unset (default) | Deny all cross-origin access. Any request carrying an `Origin` is refused on the WebSocket upgrade, and gets no CORS headers on REST. |
| `"*"` | Admit any origin. The mediator sends `Access-Control-Allow-Origin: *` and never sets `allow_credentials`. If `*` appears alongside other entries, it wins and a warning is logged. |
| `"https://a.example,https://*.b.example"` | Comma-separated allowlist. The matched request origin is echoed back. |

Allowlist entries:

- An exact, scheme-qualified origin, e.g. `https://app.example.com`.
- A leftmost-label wildcard, e.g. `https://*.example.com`. It matches any
  sub-domain at any depth (`a.example.com`, `a.b.example.com`) but **not** the
  apex `https://example.com` — add the apex separately if you need it. Scheme
  and port must match exactly; pin a port with `https://*.example.com:8443`.

`"*"` is safe on this service in a way it would not be on a
cookie-authenticated one. Every endpoint needs a bearer token in the
`Authorization` header (or, for a browser WebSocket, in
`Sec-WebSocket-Protocol`), never an ambient cookie, so a wildcard creates no
CSRF exposure. It is still a deliberate choice.

## Configuring it for a mobile wallet

The origin a React Native client presents depends on the platform and how
the app is served. Read it from the mediator's refusal log rather than
guessing, then allowlist it:

```toml
[security]
cors_allow_origin = "http://localhost:8081"
```

Or, if your threat model allows it, set `"*"`.

With an allowlist configured, refused REST origins are also logged (once per
origin, up to 32 distinct origins).

## Why the default stays closed

An operator who has not thought about browser access should not silently get
it. If the closed default is wrong for a deployment, the fix is one config
line. If an open default were wrong, configuration could not undo the
exposure.

## Proxy logging

With the browser WebSocket auth path, the JWT travels in the
`Sec-WebSocket-Protocol` request header. The mediator never logs it.
Configure any fronting proxy or load balancer not to log that header either,
as you would for `Authorization`.

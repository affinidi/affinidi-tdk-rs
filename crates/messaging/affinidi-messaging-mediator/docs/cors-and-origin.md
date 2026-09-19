# CORS and the `Origin` check

The mediator refuses a request that carries an `Origin` header the configured
policy does not admit. This applies to **both** the REST API (a real CORS layer)
and the WebSocket upgrade at `/ws` (a defence-in-depth check, since WebSocket
upgrades are not subject to CORS).

One setting drives both: `[security] cors_allow_origin`.

## The rule, stated exactly

> A request that sends **no** `Origin` header is admitted.
> A request that sends one is admitted only if the policy admits that origin.

That is the whole rule, and the header is the distinction — **not** whether the
client is a browser.

This matters because the older wording here, in `conf/mediator.toml` and in the
setup wizard, said "native clients (no Origin) are unaffected". Every word of
that is true and the sentence as a whole misleads, because it invites the reader
to substitute "native" for "sends no Origin". They are not the same set.

## React Native sends an `Origin`

**React Native's WebSocket implementation sets an `Origin` header derived from
the connection URL.** A React Native wallet is therefore refused by the default
policy exactly as a browser would be:

```
WebSocket upgrade rejected: Origin not permitted by CORS policy
```

The Rust SDK sends no Origin, which is why this never showed up in first-party
testing and why the guidance read as though it could not happen. If you are
deploying a mediator for a mobile wallet, you must configure this setting; it is
not optional for that client class.

## The three policies

`cors_allow_origin` unset — **the default.** Deny all cross-origin access. Any
request announcing an `Origin` is refused, on REST and on the WebSocket upgrade.

`cors_allow_origin = "*"` — admit any origin. The mediator echoes
`Access-Control-Allow-Origin: *` and never sets `allow_credentials`. This is
safe here in a way it would not be on a cookie-authenticated service: every
endpoint requires a bearer token in the `Authorization` header (or, for a
browser WebSocket, in `Sec-WebSocket-Protocol`), never an ambient cookie, so a
wildcard does not create CSRF exposure.

`cors_allow_origin = "https://a.example,https://*.b.example"` — a
comma-separated allowlist. Each request `Origin` must match an entry exactly or
fall under a `*.suffix` wildcard; the matched origin is echoed back. The REST
layer and the WebSocket check share one matcher, so the two enforcement points
cannot drift apart.

## Configuring it for a mobile wallet

The origin a React Native client presents depends on the platform and how the
app is served, so read it from the mediator's own refusal rather than guessing —
the rejected origin is logged with the warning above.

Then either allowlist that origin:

```toml
[security]
cors_allow_origin = "http://localhost:8081"
```

or, if the deployment's threat model allows it, admit any origin. Because
authentication is bearer-token only, `"*"` is a defensible choice here; it is
still a deliberate one, so make it deliberately.

## Why the default stays closed

Default-closed remains right even though a wildcard would be safe on this
service. An operator who has not thought about browser access should not
silently have it, and the cost of the default being wrong for a mobile
deployment is one configuration line plus this page — whereas the cost of a
default-open posture being wrong is not recoverable by configuration.

What was wrong was never the default. It was that the documentation asserted the
default could not affect a native client, so an operator hitting it had every
reason to look anywhere but here.

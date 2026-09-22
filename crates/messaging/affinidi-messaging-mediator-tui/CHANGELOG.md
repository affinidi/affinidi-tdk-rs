# Changelog

## Unreleased (0.1.1) — a mediator too old for most screens

Connected to a mediator older than 0.28.20, the console no longer shows blank
screens and "No response from API":
- The header shows the mediator's version, with a warning when it's too old.
- An administrator starts on the **Audit** screen, which older mediators
  serve.
- The Dashboard, Queues and Account screens explain what they need (the
  version found and the version required) instead of sending requests the
  mediator won't answer.

The header also shows the mediator's version whenever it's known. Requires
`affinidi-messaging-mediator-admin` 0.1.2.

## Unreleased (0.1.0) — first release

`mediator-console`, a terminal console for an Affinidi messaging mediator, and
the ratatui components it is built from:

- **Dashboard** (admin): mediator health, totals, forwarding and circuit
  breaker, queue pressure as gradient bars, and the busiest queues.
- **Queues** (admin): every non-empty queue ranked by depth, bytes, oldest
  message or saturation, each with a green → amber → red quota bar (OKLab
  interpolation, eighth-cell leading edge; 24-bit, 256-colour, basic and
  `NO_COLOR` fallbacks).
- **Account**: an account's two queues, its send queue by recipient ("who
  hasn't collected"), and its messages — inspect (decrypted locally when the
  session holds the key), delete, and purge with a counted confirmation.
- **Audit** (admin): the mediator's audit log.
- **Traffic monitor**: a live pane beside any screen (`m`), filterable to
  failures (`f`), showing liveness, dropped events and lost batches, and hiding
  the console's own polling.

The mode — administrator or self-service — follows the mediator's record of the
account. `App` is embeddable: the host owns the terminal and feeds keys and
background results in, or hands a terminal to `App::run`. Supersedes
`mediator-monitor`.

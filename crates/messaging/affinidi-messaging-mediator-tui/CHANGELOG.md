# Changelog

## Unreleased (0.1.7) — when each account was last active

- The Accounts screen has two new columns: **msg ago** (when the mediator
  last accepted a message for the account) and **login ago** (when it last
  authenticated).
- The Account screen's settings panel carries the same two times.
- Both read "–" against a mediator that doesn't serve them, or for an
  account with nothing recorded. The last-message time can lag by up to a
  minute, which is how the mediator keeps recording it off the message path.

## Unreleased (0.1.6) — account settings, and notices that clear

- **Account settings:** the Account screen gains a **Settings** panel showing
  the account's role (coloured), queue limits, access-list mode and size, and
  every ACL flag as ✓/✗.
- **`e` edits them:**
  - `↑↓` selects, and space toggles a flag or cycles the role or access-list
    mode.
  - Digits set a queue limit (`-1` is unlimited).
  - `s` saves only what changed, through `account/update`.
  - The mediator decides what the session may change (for example, a role
    change needs an administrator) and its refusal shows as a notice.
  - Non-administrators don't get the role row.
  - The editing logic is in the `account_edit` module (`AccountEdit`).
- **Notices clear themselves:** a notice in the footer now gives way to the
  key hints after 12 seconds instead of staying until the next one.

## Unreleased (0.1.5) — a Config screen

A new **Config** screen (`6`, administrators) lists the mediator's
configuration: key, value, where it comes from (`override` in yellow when a
patch set it) and when a change applies (`live` or `restart`). Limits come
first.

For a **rootAdmin**:
- `⏎` changes a `limits.*` value, and `x` removes an override.
- The mediator's answer shows as a notice: in effect now, applies after a
  restart, or refused with its reason. For example, a patch can tighten a
  limit but not loosen it past the configuration.

For other admins the screen is read-only, and the footer says who may change
it. It works on older mediators too, which serve `config/show`.

Requires `affinidi-messaging-mediator-admin` 0.1.4.

## Unreleased (0.1.4) — traffic totals

The traffic monitor keeps running totals from the moment it starts:
- **Title:** messages seen, messages per second over the whole run and over
  the last ten seconds, and how long it has been watching.
- **`t`:** switches the pane between the live lines and **per-account
  totals**. For each account: messages it sent, messages addressed to it,
  deliveries to it, refusals (in red), bytes sent and when it last appeared.
  The busiest accounts come first, shown by their address-book names.

A message is counted once, when it arrives, so the rate is messages per
second, not monitor events per second. Totals restart when the monitor does
(for example, on changing what it watches). They cover what the monitor saw:
events dropped for the rate limit or lost in transit, which the title already
counts, aren't in them. The counting lives in the `tally` module
(`TrafficTally`).

## Unreleased (0.1.3) — room for names, and every account

- **New Accounts screen** (`5`, administrators): every account on the
  mediator, read through all pages of `account/list`.
  - It shows each account's name, hash, role (coloured), receive and send
    depth, bytes queued and access-list size.
  - Order: the mediator and administrators first, then accounts you've named,
    then the rest. `⏎` opens one and `n` names it.
  - It also works on mediators older than 0.28.20.
- **Now `#[non_exhaustive]`:** `Tab` and `Update`, so future screens aren't
  breaking changes. Embedders pass `Update` from `next_update` to `apply` and
  don't match on either enum, so no known caller is affected.
- **Queue table:** the account column is sized to the longest name, from 15
  to 40 characters, instead of a fixed 15. The two quota bars share the
  remaining width, so the table fills the pane at any size, with the monitor
  open or not.
- **Other tables:** the recipient, message sender/recipient and audit
  actor/target columns take the spare width instead of a fixed one.
- **Monitor:** sender and recipient are aligned, fixed-width columns sized to
  the pane, and an over-long name ends with `…`. Before, lines ran together
  because names have different lengths.

## Unreleased (0.1.2) — names for accounts

Accounts show by **nickname** wherever the console shows an account hash:
queues, peers, messages, the audit log and the traffic monitor. Monitor lines
already on screen pick up a new name at once.

- **`n`** names the account in view. Paste its DID and the console checks it
  hashes to that account; with nothing selected, paste any DID or hash.
- **`b`** opens the address book: rename, add, remove.
- **Filled in for you:** your own account shows as `you`, and the mediator as
  `mediator`.
- **Where it's kept:** `~/.config/mediator-console/address-book.json`, or
  `--address-book <file>`. `default_address_book_path()` gives the same
  location to other front ends, so they share the book.
- **Pasting:** `mediator-console` turns on bracketed paste, so a pasted DID
  arrives in one piece. Embedders can call `App::handle_paste`.
- **For embedders:** `App::with_address_book(book, path)` supplies a book;
  pre-fill it with `AddressBook::know`.

Requires `affinidi-messaging-mediator-admin` 0.1.3.

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

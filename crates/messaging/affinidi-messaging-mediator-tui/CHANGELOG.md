# Changelog

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

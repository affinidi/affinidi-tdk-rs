# mediator-console

`mediator-console` is a terminal console for an Affinidi messaging mediator.
Connect as any DID with an account on the mediator:

- **as an administrator**, you run the whole mediator: its health, every
  account's queues, anyone's messages and settings, the audit log, and live
  traffic;
- **as any other account**, you manage your own queues, your own messages
  (including reading your own mail), and your own live traffic.

The same screens are also available as ratatui components, which you can embed
in another application ([Embedding](#embedding)).

```
 mediator-console  ADMIN   b48a53fa…1f29 → did:peer:2.Vz6Mkkn…      updated 1s ago
 1 Dashboard │ 2 Queues │ 3 Account │ 4 Audit
┌ Account 1f22bbf6…b9a1 ─────────────────────┐┌ Traffic — all traffic ● live ───────┐
│receive: 0 / 200    oldest –                ││22:46:24 ▶ received  didcomm   rest …│
│   send: 3 / 2000   oldest 4s               ││22:46:24 · stored    didcomm   …     │
│▏███████▊                                   ││22:46:25 ◀ delivered didcomm   websoc│
└────────────────────────────────────────────┘│22:46:26 ▶ refused   tsp       rest …│
┌ Send queue by recipient — who hasn't coll… ┐│          authorization.send         │
│recipient       waiting bytes     oldest    ││                                     │
│36c23eba…4584   3       20.5K     4s        ││                                     │
```

## Before you start

- **A mediator that serves the operations Trust Tasks.** You need
  `affinidi-messaging-mediator` **0.28.20 or later**, which serves the
  `messaging/stats`, `queue`, `message` and `monitor` tasks. On an older
  mediator the console still connects, and the header shows its version:
  - the Audit screen (and account settings) work;
  - the Dashboard, Queues and Account screens and the monitor explain what
    they need instead of loading;
  - an administrator starts on Audit.
- **An identity:** a DID and its secrets, in a TDK profile JSON file:
  ```json
  { "alias": "operator", "did": "did:…", "mediator": "did:…", "secrets": [ … ] }
  ```
  - `mediator-setup` writes one for the mediator's administrator, as
    `admin-monitor.json` next to `mediator.toml`.
  - Any other account's profile works too.
  - If you leave out `mediator`, the console uses the mediator named in the
    DID's `DIDCommMessaging` service.
- **Admin rights, for admin mode.** The console asks the mediator what the
  account is, and the mediator's answer decides the mode. To administer, the
  account must have the `admin` or `rootAdmin` role (see the mediator's
  `mediator_administration` tool, or `messaging/account/update`).
- **Signing, recommended.** The mediator verifies every Trust Task, including
  its proof, according to `security.trust_task_verification`. The SDK the
  console uses signs every request with the profile's Ed25519 key, so no extra
  setup is needed.

## Running it

```bash
cargo run --release -p affinidi-messaging-mediator-tui -- \
  --profile path/to/conf/admin-monitor.json
```

| Option | Meaning |
|---|---|
| `-p, --profile <file>` | A profile to connect with. Repeat it to offer several. |
| `--as <alias or DID>` | Which of several profiles to use. The default is the first. |
| `--mediator <DID>` | Override the mediator from the profile and the DID document. |
| `--address-book <file>` | Where to keep account nicknames ([Names for accounts](#names-for-accounts)). |

Connection errors are printed before the console takes over the screen, so a
wrong profile, an unreachable mediator, or an account the mediator doesn't know
is reported plainly.

## Screens

| Key | Screen | Shows |
|---|---|---|
| `1` | **Dashboard** *(admin)* | Version and uptime, websocket connections, message and session totals, forwarding queue and circuit breaker, and **queue pressure**: the fullest receive and send queue, as gradient bars. Below that, the busiest queues. |
| `2` | **Queues** *(admin)* | Every account with a non-empty queue, ranked by depth, bytes, oldest message or saturation (`s` cycles the ranking, `x` switches between receive and send). Each queue has a **quota bar**. The ranking comes from the mediator's once-a-minute survey, and the title shows when that survey ran. |
| `3` | **Account** | One account's two queues with quota bars, its **send queue by recipient** (who hasn't collected yet), and its messages. For a standard account, this is the whole console. |
| `4` | **Audit** *(admin)* | The mediator's audit log of privileged changes. Monitor subscriptions and cross-account reads are recorded here too. |
| `5` | **Accounts** *(admin)* | Every account on the mediator: name, hash, role (coloured), receive and send depth, bytes queued, access-list size. The mediator and administrators come first, then accounts you've named, then the rest. `⏎` opens one. Works on older mediators too. |

**Quota bars** shade smoothly from green through amber to red along the bar,
so how full a queue is shows as colour at its leading edge. They use 24-bit
colour when `COLORTERM` says the terminal supports it. Otherwise they fall back
to 256 colours, then to three plain colours; `NO_COLOR` switches colour off.

### Keys

| Key | Where | Does |
|---|---|---|
| `↑` `↓` / `j` `k` | tables | select a row |
| `⏎` | Dashboard, Queues, Accounts | open the selected account |
| `x` | Queues, Account | receive ↔ send queue |
| `s` | Dashboard, Queues | change the ranking |
| `i` | Account | **inspect** the selected message: its metadata and raw envelope, decrypted locally when you hold the recipient's key (your own mail) |
| `d` | Account | **delete** the selected message (asks for confirmation) |
| `p` / `P` | Account | **purge** the queue, or only messages exchanged with the selected message's counterparty (see below) |
| `o` | Account | back to your own account |
| `m` | anywhere | show or hide the **traffic monitor** |
| `f` | anywhere | monitor failures only |
| `n` | anywhere | **name** an account: the selected one, or any account by pasting its DID |
| `b` | anywhere | the **address book**: rename (`n`), add (`a`), remove (`x`) |
| `r` | anywhere | refresh now (screens also refresh every 5 s) |
| `Tab` | anywhere | next screen |
| `q` / `Esc` | anywhere | quit, or close a popup |

## Names for accounts

The mediator knows an account only by a hash: SHA-256 of the DID, as
lowercase hex. That is what `36c23eba…4584` in every table is. The **address
book** puts a name on it: give it a DID and a nickname, and the console shows
the nickname wherever that account appears, in tables, the audit log and the
traffic monitor.

- **`n`** names the account in view: the selected queue row, the selected
  message's counterparty, or the account on screen. Paste its DID, and the
  console checks the DID really hashes to that account. With no account
  selected, paste any DID (or a bare 64-hex hash) to name it.
- **`b`** lists the book, where you can rename or remove entries.
- **Filled in for you:** your own account shows as `you`, and the mediator as
  `mediator`. Applications that embed the console can supply more names; for
  example, `pnm` names every DID the VTA manages after its label.
- **Where it's kept:** a JSON list of `{ "name", "did" }` at
  `~/.config/mediator-console/address-book.json` (or under
  `$XDG_CONFIG_HOME`), shared by every console front end. You can edit it by
  hand. `--address-book <file>` points the console at another one.

## Deleting and purging

A purge is always counted first. The console shows how many messages (and
bytes) would go and waits for `y`. It then checks the count again and refuses,
removing nothing, if the queue has changed in the meantime, so what you
confirmed is what gets removed. Purged messages are gone; they aren't returned
to their senders.

What the mediator allows:

- **Your own queues:** always, provided your account is served locally.
- **Another account's queues:** admins only.
- **An admin's, rootAdmin's or the mediator's own queue:** rootAdmin only.
- **Another account's message body** (inspecting it): rootAdmin only. An admin
  sees the metadata.
- **Audit:** every cross-account delete, purge and read is written to the audit
  log.

## The traffic monitor

`m` splits the screen, with live traffic in a pane beside whatever you're
looking at. Each line is one step in a message's life:

- received, stored, delivered, forwarded, refused, deleted or purged
- over REST, websocket or a peer mediator
- as DIDComm or TSP
- with sender, recipient and size
- for a refusal, the problem code, in red

Opened from an account, the monitor watches that account; otherwise it watches
everything (admin) or your own traffic (everyone else).

- **Metadata only.** Message bodies never appear.
- **Honest about its own state.** The pane's title shows whether the feed is
  live, silent or stopped, how many events the mediator dropped (because of the
  rate limit, or because the console was briefly offline), and how many batches
  were lost in transit.
- **Your own polling is hidden,** so the pane shows traffic rather than the
  console talking to the mediator.

## Embedding

The console is a library as well as a binary:

```rust
use affinidi_messaging_mediator_admin::{Identity, MediatorConsole};
use affinidi_messaging_mediator_tui::{App, Control};

let console = MediatorConsole::connect(identity).await?;
let mut app = App::new(console);

// Hand over a terminal and let the console run its own loop…
app.run(&mut terminal).await?;

// …or keep your own loop and feed the console:
//   app.handle_key(key)                  on a key press (Control::Quit when done)
//   app.apply(app.next_update().await?)  when background work finishes
//   app.render(frame, area)              to draw into any area of your layout
```

- `App::open_account(did_hash)` jumps straight to one account.
- The gradient `QuotaBar` widget (and `quota_line` for table cells) works on
  its own.
- The engine underneath, including identities, purge plans and monitor feeds,
  is [`affinidi-messaging-mediator-admin`](../affinidi-messaging-mediator-admin/).

## From `pnm`

`pnm messaging console` will open this console as any DID a Verifiable Trust
Agent manages, fetching its keys from the VTA for the session, with no profile
file to keep. It's being built in the `verifiable-trust-infrastructure`
repository and implements `IdentitySource` from the engine crate.

## Replaces `mediator-monitor`

`mediator-monitor` polled `/admin/status` for a read-only dashboard. The
console's Dashboard shows the same figures and much more, over signed Trust
Tasks. `mediator-monitor` will be removed in a later release.

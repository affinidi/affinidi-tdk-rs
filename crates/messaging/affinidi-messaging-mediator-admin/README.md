# affinidi-messaging-mediator-admin

The engine behind the mediator console. It connects to an Affinidi messaging
mediator as a DID and lets you operate it: headless, or embedded in any
application.

There are two modes, and the mediator decides which one applies from its own
record of the account:

| Mode | Who | What you can do |
|---|---|---|
| **Admin** | an `admin` or `rootAdmin` account | Mediator statistics, every account's queues ranked by depth, age or saturation, any account's messages and settings, the audit log, the configuration, and live traffic for everyone. A `rootAdmin` can also read another account's message bodies and act on privileged accounts' queues. |
| **Self-service** | any other account | Your own queues and messages (including decrypting your own mail locally), the settings you're allowed to manage yourself, and your own live traffic. |

Every operation is a signed [Trust Task](https://trusttasks.org), so the
mediator authorises each one on its own. The console also checks
`Capabilities` before sending, which saves a round trip and an error for
things the mediator would refuse anyway. Your mediator needs to serve the
`messaging/*` operations tasks (`affinidi-messaging-mediator` 0.28.20 or later).

## Connecting

```rust
use affinidi_messaging_mediator_admin::{Identity, MediatorConsole, Mode};

let console = MediatorConsole::connect(Identity {
    alias: "operator".into(),
    did: "did:peer:2...".into(),
    secrets,                 // the DID's Ed25519 and key-agreement secrets
    mediator_did: None,      // None = use the mediator from the DID's DIDCommMessaging service
})
.await?;

match console.mode() {
    Mode::Admin { root } => println!("administering (rootAdmin: {root})"),
    Mode::SelfService => println!("managing {}", console.did_hash()),
}
```

To share an existing SDK instance with your application, use
`MediatorConsole::connect_with(atm, identity)`.

## Where identities come from

An `IdentitySource` lists the identities you can pick from and loads the one
you choose, including its secrets:

- **`ProfileFileSource`** reads TDK profile JSON files. That's the
  `{ alias, did, mediator, secrets }` file `mediator-setup` writes for its
  administrator.
- **`StaticIdentities`** holds identities already in memory, for embedding
  applications and tests.
- **Anything else:** implement the trait yourself. `pnm` implements it against
  a Verifiable Trust Agent, so a console can act as any DID the VTA manages
  without a secrets file. This crate deliberately doesn't depend on the VTA
  SDK; the dependency points the other way.

## Destructive operations are two-step

```rust
use affinidi_messaging_mediator_admin::PurgeRequest;
use affinidi_messaging_mediator_admin::specs::queue::purge::v0_1::Queue;

let plan = console
    .purge_preview(PurgeRequest {
        target: Some(stuck_account),
        queue: Queue::Send,
        peer: Some(stalled_recipient),
        older_than_seconds: None,
    })
    .await?;
// Show plan.matched to the user and ask them to confirm it.
console.purge(plan).await?;
```

If the queue has changed since the preview, `purge` returns
`ConsoleError::PlanStale` and removes nothing, so what the user confirmed is
what gets removed.

## Live traffic

```rust
use affinidi_messaging_mediator_admin::{MonitorFilter, MonitorUpdate};

let filter: MonitorFilter = serde_json::from_value(serde_json::json!({
    "dids": [account_hash],
    "failuresOnly": true,
}))?;
let mut feed = console.monitor(filter).await?;
while let Some(update) = feed.next().await {
    match update {
        MonitorUpdate::Events { events, dropped } => { /* render */ }
        MonitorUpdate::Gap { missing } => { /* batches lost in transit */ }
        MonitorUpdate::Heartbeat => { /* the tap is alive */ }
        MonitorUpdate::Ended(reason) => break,
    }
}
```

- **What the feed does for you:** it renews its lease, reports lost batches as
  `Gap` and a quiet-but-alive tap as `Heartbeat`, and unsubscribes when dropped.
- **What an event contains:** metadata only. Stage, direction, channel,
  protocol (DIDComm or TSP), sender, recipient, size and refusal code.
  Never a message body.
- **Accountability:** every administrator subscription is recorded in the
  mediator's audit log.

## How the console reads its connection

The console runs a single reader over its live stream. That reader hands each
monitor batch to the feed it belongs to, and leaves every other pushed message
in the queue untouched (the console isn't a mail client). Request/response
calls on the same connection are safe alongside it, because the SDK
(0.26.19 and later) hands each reply to the call waiting for it before any
reader sees it.

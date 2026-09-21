# Changelog

## Unreleased (0.28.22) — the monitor sees every step, with both parties

The traffic monitor (0.28.20) now reports a message's whole life, not just its
arrival and storage:

- **`received` names the recipient.** It is read from the envelope's cleartext
  header (a DIDComm JWE's `kid`, a TSP envelope's receiver) and hashed like
  every other party. Nothing is decrypted, and the header is only parsed while
  someone is subscribed. DIDComm v1 and signed-only messages carry no DID in
  the clear and still report none.
- **Pickups and deletes report their channel.** A request handled deep in the
  protocol layer (message pickup, v1 batch pickup and ack) reports the channel
  it arrived on, REST or websocket.
- **Collection is a `delivered` event.** Fetching over REST, message pickup
  (`delivery-request`, live delivery), DIDComm v1 batch pickup and websocket
  redelivery all report what they handed over, with sender and recipient.
  Before, only websocket pushes did.
- **`deleted` carries both parties.** Deletes over REST, pickup's
  `messages-received`, the v1 ack and websocket delete-on-send now all name
  the sender and the recipient. A REST delete looks each message up first to
  do this, but only while someone is subscribed.

The mediator's own management traffic with a subscriber is now filtered on the
server in every case, because requests to the mediator carry it as the
recipient.

## Unreleased (0.28.21) — TSP is a default feature

`tsp` joins `didcomm` in the mediator's default features, so a mediator built
with defaults routes TSP and — for a self-hosted `did:web` — advertises a
`TSPTransport` service beside its `DIDCommMessaging` one. TSP is the preferred
transport across the stack: a peer that sees `#tsp` on a party whose mediator
is this one sends TSP here, and a default build that could not receive it sent
those peers into nothing (Keyring VTI-33). A `did:webvh` mediator DID cannot be
rewritten at boot; mint it with TSP (the setup wizard now does by default) or
add the service in a new log entry. `--no-default-features` builds are
unchanged, and a build without `tsp` still warns when its DID advertises it.

## Unreleased (0.28.20) — a live traffic monitor

`messaging/monitor/subscribe` / `unsubscribe` open a leased (default 5 min, at
most 1 h, renewable), filtered live tap on the mediator's traffic **metadata**,
delivered as signed `messaging/monitor/event` batches over the subscriber's live
connection: what arrived and over which channel (REST / websocket) and protocol
(DIDComm v2, DIDComm v1, TSP), what was refused and with which problem code,
what was stored, delivered, forwarded to another mediator, deleted or purged —
with sender, recipient, size and message id. Never a message body.

Filters: DIDs (either party), direction, stage, protocol, channel, message-type
prefix, failures only. An administrator may watch anything; any other account
only its own traffic — an omitted `dids` filter is narrowed to it, and naming
another account is refused. Three subscriptions per account.

A monitor must not hurt what it watches: emitting costs one atomic load when
nobody subscribes; events are **never queued or stored** — over the rate
ceiling, lagging, or with the subscriber offline they are counted in `dropped`;
batches (≤500, flushed each second, a heartbeat every 30 s) go straight to the
streaming publisher and emit nothing themselves; and a subscriber's own
management traffic with the mediator (its console polling) is left out.

Not yet observed (a following release): forwarding-processor outcomes (relayed,
failed, abandoned), per-message expiry, deliveries on DIDComm pickup, TSP-socket
drain and redelivery, and subscribers on a raw-TSP socket. Scope is per instance
behind a shared Redis.

**Accountability and disclosure.** Every administrator subscribe, renew and
unsubscribe is written to the audit log (`monitorSubscribe` /
`monitorUnsubscribe`: who watched which accounts, for how long, with what
filter) — an administrator's tap can see every account's correspondence
metadata, so it must be on the record. A refusal carries the problem-report
code and comment the sender was already sent; an internal failure is reported
as `internalError` with no detail, the full text staying in the server log.
Requires `affinidi-messaging-mediator-common` 0.16.15.

## Unreleased (0.28.19) — `messaging/message/delete` and `messaging/queue/purge`

The two destructive mediator-operations Trust Tasks:

- **`message/delete`** — up to 100 message ids from one account's queues, each
  reported in request order. An id not in that account's queues is a per-item
  `notFound` (indistinguishable from a missing one), never a whole-task failure,
  and nothing is reported deleted that the store did not remove.
- **`queue/purge`** — one account queue, optionally only one counterparty's
  messages or those older than an age, with `dryRun` to count first. Built on
  the same `purge_folder_filtered` as REST `/purge`. What the spec's response has
  no member for — messages examined, matched-but-not-removed, and whether the
  walk hit its scan ceiling — is under `ext["com.affinidi.mediator"]`, so a
  partial purge is never reported as complete.

The account's own queues need `local`, as the REST routes do. Another account's
need admin standing, and an admin, rootAdmin or mediator account's queue needs a
**rootAdmin** (`…:rootAdminRequired`) — an admin cannot wipe another admin's
mailbox. Deleting another account's messages is audited (`messageDelete`), and
every real purge is audited (`queuePurge`), including one that removed nothing.
REST `/purge` still cannot touch another account's queue; the admin gate on the
Trust Task is what makes the cross-account form safe.

## Unreleased (0.28.18) — `messaging/message/list` and `messaging/message/get`

- **`message/list`** — stored-message metadata for one queue, oldest first,
  never bodies: id, size, arrival time, sender/recipient and delivery state
  (`queued`, or `delivered` with when). `peer` narrows to one counterparty and
  is applied while paging, so a page can come back short with a cursor.
- **`message/get`** — one stored message verbatim and undecrypted, with its
  metadata and detected protocol. Not a pickup: the delivery state is untouched.

The requester's own queues need the `local` capability (as REST `/list` does);
another account's metadata needs admin standing, and another account's message
**body** needs a rootAdmin (`messaging/message/get:rootAdminRequired`) — the
one read that can expose content, e.g. a signed-only DIDComm message. Such a
read is recorded in the audit log (`messageRead`). A message id from another
account's queue is indistinguishable from one that does not exist. Requires
`affinidi-messaging-mediator-common` 0.16.14.

## Unreleased (0.28.17) — `messaging/queue/status`

One account's two queues, read live: depth, bytes, effective limit (the
account's own, else the mediator default), saturation and the age of the oldest
message — the Trust Task counterpart of `GET /queue/status`, for any account an
administrator names or for the requester's own (self needs no admin rights;
another account needs admin, else `authorization.account.denied`).

`includePeers: n` also breaks each queue down by its top `n` counterparties over
its oldest 2,000 messages. In the send queue that is *who has not collected*: a
message is held against its sender until the recipient deletes it, so a stalled
recipient is the top entry in every one of its senders' send queues.

## Unreleased (0.28.16) — `messaging/stats/show` and `messaging/queue/list`

Two admin-only Trust Tasks for operator tooling (trustoverip/dtgwg-trust-tasks-tf#549):

- **`messaging/stats/show`** — version, start time and uptime, live and maximum
  websocket connections, the lifetime message/session/invitation counters,
  forwarding queue length and limit, circuit-breaker state, and the latest queue
  survey's totals (depth, bytes, worst saturation, oldest probed message). The
  Trust Task counterpart of `/admin/status`, without the database URL.
- **`messaging/queue/list`** — accounts ranked by the depth, bytes, oldest
  message or saturation of their receive or send queue, paged by a cursor pinned
  to one survey.

Both are served from the queue survey the statistics task already runs every
minute, which now keeps a per-account row for every non-empty queue (with the
probed ages) and publishes it — so an admin console polling them costs the store
nothing. `snapshotAt` says how old the ranking is; before the first survey
completes, `queue/list` answers `message.trust_task.unavailable`.

`tasks::statistics::statistics` keeps its signature; `statistics_with_snapshot`
is the variant that publishes the survey. Requires `trust-tasks-rs` 0.21.10.

## Unreleased (0.28.15) — Trust Task responses are signed

Every success response to a Trust Task — over DIDComm and TSP — now carries an
`eddsa-jcs-2022` Data Integrity proof made with the mediator DID's Ed25519 key
(`assertionMethod` if the DID declares one, else `authentication`), so a client
can keep the answer as evidence independent of the transport. `issuedAt` is
stamped, and `issuer` is the mediator DID. `messaging/message/get` — which can
return another account's stored envelope — requires a signed response; the
other `messaging/*` specs recommend one.

A mediator whose DID has no Ed25519 signing key among its secrets answers
unsigned and logs once that it cannot answer `message/get` conformantly. A
signing failure with a key in hand is an error, never a silent downgrade.
Clients that ignore `proof` are unaffected.

## Unreleased (0.28.14) — a Trust Task runs once

A consequential Trust Task (one whose spec requires a proof or `issuedAt`) is
now recorded in the store once it passes its acceptance checks, keyed by the
authenticated sender and the document `id`. The same document again is refused
with `message.trust_task.duplicate`; a different document under a used `id` with
`message.trust_task.id_conflict`; a store that cannot be consulted with
`message.trust_task.unavailable` (503). Before, a captured `account/update` could
be replayed for as long as its envelope was accepted — and to any other
instance sharing the store.

The record is claimed last, after every other check, so a refused document never
burns its `id`. It is kept until the end of the acceptance window (`issuedAt` +
5 minutes + skew), or `expiresAt` if sooner — a far-future `expiresAt` cannot make
the mediator hold it longer. Reads are not recorded. Like the other checks, a
duplicate is only logged under `security.trust_task_verification = "warn"` and
refused under `"enforce"`. Lapsed records are swept on the session-sweep cadence
(Redis expires them itself). Requires `affinidi-messaging-mediator-common` 0.16.13.

## Unreleased (0.28.13) — Trust Tasks are checked before they run

Every served management Trust Task (everything but `messaging/ping`, which keeps
its own pipeline) now passes the Trust Tasks §7.2 acceptance checks before its
handler runs, over DIDComm and TSP alike:

- **freshness** — `issuedAt` inside the acceptance window; a task whose spec
  requires a proof or `issuedAt` must carry `issuedAt` and be under 5 minutes old;
- **issuer binding** — an in-band `issuer` must be the authenticated sender;
- **proof** — a present proof must verify (`eddsa-jcs-2022` / `eddsa-rdfc-2022`)
  with an Ed25519 key the issuer lists under `authentication` or
  `assertionMethod`, published as Multikey **or JWK**;
- **spec policy** — `proofRequired` / `issuedAtRequired` / `recipientRequired`.

Until now only `ping` was checked at all, with proofs accepted unverified.

**Nothing that works today stops working.** A new `[security]` setting,
`trust_task_verification` (env `TRUST_TASK_VERIFICATION`), defaults to `"warn"`:
a failing task is logged, counted in `trust_task_acceptance_failures_total{reason,mode}`,
and still executed, and the mediator warns at boot that it is in `warn` mode.
Set `"enforce"` once clients sign — `affinidi-messaging-sdk` 0.26.13 and later
sign every Trust Task — and a failing task is refused with a problem report:
`message.trust_task.proof_required`, `.proof_invalid`, `.stale`,
`.identity_mismatch` or `.rejected`. A later release will make `"enforce"` the
default. An unrecognised value is a startup error, not a silent fallback.

The proof is verified over the document **as received**, not as re-serialised:
`trust_tasks_proof::affinidi::Verifier` re-serialises the parsed document, so a
genuine proof over, say, an `issuedAt` written `+00:00` rather than `Z` failed
there. Duplicate-execution (replay) protection follows separately.

New dependencies (under `didcomm`): `trust-tasks-proof` 0.21 (`affinidi` backend)
and `affinidi-data-integrity` 0.7 — both already in the build graph.

## Unreleased (0.28.12) — one list declares every served trust task

Internal refactor, no behaviour change. The trust-task dispatch in `consume()`
and the `served_type_uris()` array the TSP arm reads had to be edited in step;
a type dispatched but not listed was filed into the mediator's inbox when it
arrived over TSP, and its caller timed out with nothing logged. A
`served_tasks!` macro now declares each served type once and generates a
`ServedTask` enum that `consume()` matches exhaustively — a registered type
without a handler no longer compiles — and that `parse_if_served` reads. The
same eleven types are served, with the same handlers and the same
`protocol.trust_task.unsupported` report for anything else.

## Unreleased (0.28.11) — a path in the config file means "relative to the config file"

`functions_file`, `ssl_certificate_file` and `ssl_key_file` now resolve against
the directory of the configuration file that names them, not the process's
working directory. Starting the mediator with `--config
/etc/mediator/mediator.toml` from anywhere else used to fail with
`Couldn't ready database functions_file (./conf/atm-functions.lua)` (Keyring
VTI-07). The TLS paths had the same defect and only ever worked because the
mediator was started from the repository root.

**Nothing that works today stops working.** A path absent beside the config but
present relative to the working directory still resolves, and logs a
deprecation warning naming the setting — emitted once the logging subscriber is
up, since config is read before it exists and a warning then is dropped. The
one case whose answer changes is a file present in *both* places, where the one
beside the config now wins.

A path set by **environment variable** (`DATABASE_FUNCTIONS_FILE`,
`SSL_CERTIFICATE_FILE`, `SSL_KEY_FILE`) is taken as given: it was not written in
the config file, so "relative to the config file" is not what it means.

The shipped `conf/mediator.toml` now writes its paths relative to `conf/`
(`./atm-functions.lua`, `keys/end.cert`, `keys/end.key`), so a default start
does not warn. A deployment carrying a copy of the **old** default keeps
working through the fallback and warns until the paths are updated.

## Unreleased (0.28.10) — a re-submitted message is stored once, and its counters no longer leak

Storing a message is now idempotent on its hash, in all three backends. The
same bytes stored twice for the same recipient used to add a second inbox and
outbox entry and a second queue-counter increment over a single message row.
The one delete then released one of each and left the rest behind for good:
the sender's `send_queue_count`, the recipient's `receive_queue_count` and the
per-peer depth each kept one per duplicate. Expiry could not recover them
either, because both copies share one expiry key. The recipient also saw the
duplicate's delete refused with `NOT_FOUND`.

Duplicates are ordinary traffic, not an edge case: the delivery layer's outbox
re-sends the identical packed bytes whenever a send errors, including when the
mediator had in fact stored it and only the acknowledgement was lost to a reset
connection. On a live deployment the leak was one of the things behind a
did-hosting control DID crossing `limits.queue.sender`, after which it could
answer nobody.

The check runs under the store's write lock (the Lua function is atomic in
Redis), so two concurrent stores of the same bytes cannot both pass. The same
bytes addressed to a *different* recipient are unchanged by this release.

Redis deployments pick up the changed `conf/atm-functions.lua` at startup via
`FUNCTION LOAD REPLACE`; a deployment that ships its own copy of that file must
update it, which `redis_functions_match_build` reports.
## Unreleased (0.28.9) — `limits.pickup_round_robin`, on by default

A pickup now gives each sender a turn instead of serving an inbox strictly
head-first, so one sender's backlog stops hiding the sender behind it.

**On by default**, unlike `delivered_expiry_seconds`, and the difference is the
point: this destroys nothing. Order **within** a sender is preserved exactly,
only the interleaving between senders changes, and nothing guarantees that. A
recipient talking to one peer sees byte-identical results.

Turn it off with `pickup_round_robin = "false"` if a client genuinely depends
on cross-sender arrival order.

The WebSocket redelivery drain passes `false` explicitly: it pages with
`start_id` and is re-covering a socket's whole inbox in order, not choosing
between competing senders.

## Unreleased (0.28.8) — how much of a queue is work already done

The queue survey now samples the queues it already probes and reports how many
of their oldest messages have **already been handed to their recipient**:
`queue_delivered_unacked_messages` and `queue_delivered_unacked_sample_size`,
both labelled by folder.

**This pair is what says whether `limits.delivered_expiry_seconds` is worth
turning on.** That limit ships off, because shortening a delivered message's
life is a real durability trade — and until now an operator had no way to see
what turning it on would do. A high ratio means queues are holding work that is
already done and occupying senders' allowances for nothing; a ratio near zero
means enabling it would change little and the trade is not worth making. It is
the same principle as `dryRun` on a purge: see the impact before taking it.

A **sample, not a census**, and reported as a pair so it reads as a ratio — a
full count would mean reading every queued message's delivery state every
cycle, which is the scan the survey exists to avoid. Taken from the **oldest**
end of the deepest queues, because that is where a delivered-and-still-queued
message accumulates; the newest end is mostly messages nobody has had a chance
to collect. Cost is one extra listing and one batched state read per
already-probed queue, bounded by the existing probe cap.

An empty queue contributes nothing rather than a zero-of-zero that would drag
the fleet ratio toward "nothing is delivered", and a failed sample costs that
queue's sample without losing the age reading that already succeeded.

### `queued_send_messages_per_peer` is checked against the receive limit

Warned at boot for the configured defaults, and **again when an account's own
`queue_receive_limit` is set** — a boot check of the globals structurally
cannot cover the per-account case, because the limit that matters is the
effective one, and an account granted a receive limit at or below `per_peer`
becomes monopolisable by a single sender the moment it is set.

## Unreleased (0.28.7) — `limits.delivered_expiry_seconds`, off by default

Lets an operator say how long a message is kept **after** its recipient has
collected it, counted from that first handover, instead of holding it for the
full week against its sender's queue allowance.

**Off by default, and it stays off on upgrade.** Shortening this is a real
reduction in durability rather than a free win: a message can be marked
delivered and still not have reached an application, because the delivery layer
deliberately does *not* acknowledge a message that reached no consumer — that
is what makes the mediator redeliver it. Set shorter than a client's worst
restart window, this destroys exactly those messages. `conf/mediator.toml`
says so where an operator will read it.

All five delivery paths pass the limit through, so the clock starts on whichever
one hands the message over.

New counters: `messages_first_delivered_total`, `messages_redelivered_total`,
`messages_poison_suspected_total`, `messages_delivered_expiry_advanced_total`.
The last is absent rather than zero on a default deployment.

## Unreleased (0.28.6) — every delivery path records the handover

The five paths that hand a message to its recipient — REST fetch, the WebSocket
handler, the streaming task, message-pickup 3.0 and v1 mediation — now go
through `fetch_messages_delivering`, which fetches and records the handover in
one place.

One place on purpose: a stamp that five callers have to remember is a stamp
that will be missing from the sixth.

Only messages that actually came back are marked. A `get_error` is a message
the fetch could not read, and stamping it would record a handover that never
happened.

A marking failure never fails the pickup it belongs to. The delivery already
succeeded, and trading a real delivery for a statistic is the wrong way round.

## Unreleased (0.28.5) — a queue can be inspected, and cleared precisely

Two recovery gaps, both of which made a full queue worse than it needed to be.

### `GET /queue/status`

A sender learned its queue was full by being **refused** — at which point it is
already failing, and the messages it was refused are the ones it most wanted to
send. Everything needed to see it coming sat in the account record and was
unreachable: a DID could read neither its own depth nor the limit it was being
measured against, so "slow down at 80%" was not expressible.

Returns, for the calling DID only: send and receive depth and bytes, the
**effective** limit for that account (its own override, or the configured
default), the resulting saturation, the oldest queued message's age, and the
per-peer send limit — which is separate because it is the gate that moves
first: a sender fanning out to many peers stays well under its send total while
a single stuck relationship crosses the per-peer cap.

`saturation` is `None` rather than `0.0` for an unlimited queue. Reporting zero
would make the one account that can never be full read as the emptiest.

Depth comes from the account record, which already held it, so this adds no
accounting. The ages are one range read each against the arrival-ordered
streams.

### `DELETE /purge/{folder}` takes `?peer=`, `?olderThanSecs=` and `?dryRun=`

The whole-folder purge is rarely the operation an operator wants. The queue
that strands a deployment is usually full of messages for **one** peer that
stopped collecting, or old enough to be certain nobody is coming for them — and
destroying the rest of the outbox to clear those is a second incident.

`dryRun` reports what would go and removes nothing. A purge is unrecoverable
and the operator reaching for it is usually mid-incident; being able to ask
first is the difference between a recovery tool and another outage.

`peer` is the **counterparty**, which end depending on the folder: in an outbox
who the message went to, in an inbox who sent it. A message whose counterparty
is unrecorded — an anonymous sender — never matches a `peer` filter, because it
cannot be shown to be the peer asked for and a purge must not delete on a
maybe.

With no parameters the behaviour is exactly as before, including the faster
whole-folder path that drops the stream key rather than walking it.

`PurgeQueueResponse` gains `scanned` and `dryRun`, both `#[serde(default)]`, so
a response from an older mediator still deserialises.

## Unreleased (0.28.4) — a queue can be watched before it becomes an outage

The only queue a deployment could see was the forwarding one
(`forward_queue_length`). A per-DID inbox or outbox backing up was invisible
until it crossed a limit and the mediator started refusing traffic, so the
first signal of a stuck queue was an outage. Every queue-depth gate added in
0.27.0 and 0.28.0 was enforceable and unobservable at the same time.

The statistics task now also runs a queue survey each cycle and publishes:

- `queue_depth_messages` / `queue_depth_bytes` (label: `folder`);
- `queue_oldest_age_seconds` (label: `folder`);
- `queue_max_saturation_ratio` (label: `folder`), where 1.0 is the depth at
  which an account starts being refused — the one gauge here that moves
  *before* anything breaks;
- `queue_accounts_surveyed` and `queue_survey_truncated`;
- `queue_limit_refusals_total` (label: `gate` = `peer|sender|recipient`),
  counted where the three gates refuse in `messages::queue_limits`.

**Age is the point.** Depth cannot tell a busy queue from a stuck one — a deep
queue that is draining is healthy and looks identical on a depth gauge. Age
separates them, and a value climbing toward `message_expiry_seconds` means
nothing is collecting and only expiry will clear the queue.

Two limits on the age gauge, both deliberate and both documented on the metric
rather than left to be discovered. It covers the deepest queues probed that
cycle (capped at 32 per folder), so a shallow but very old queue can be missed
while deeper ones exist. And the outbox series is blind to anonymous senders,
because an outbox entry is only allocated when the sender is known — anonymous
traffic appears in the inbox series alone. Read the pair, not either half.

Bounded by construction: at most 10,000 account records per survey, paged
through the existing cursor, and at most 32 age probes per folder. Account
records already carry the depth counters, so the depth half costs one paged
walk and no per-queue reads at all. A survey that hits the account cap sets
`queue_survey_truncated`, because for a metric whose job is to catch an
unwatched queue, under-reporting silently would be the worst available failure.

Age is read from the inbox/outbox streams, which are arrival-ordered in every
backend, and **not** from the expiry index. `expires_at` is
`min(client_expires_time, now + TTL)` and that clamp is upper-bound only, so a
short client-supplied expiry passes through and sorts below a genuinely old
message carrying the default. The minimum of that index is the
newest-but-shortest-lived message, not the oldest, and a client sending
short-expiry traffic would have pinned the gauge near "healthy" indefinitely.
Arrival order cannot be reordered by a client; expiry order can.

### The Redis stored functions are checked against the build

`load_scripts` already fails loudly if `FUNCTION LOAD` is rejected, so "did the
library load" was answered. What was not answered is loading the *wrong* one.
Function names are stable across releases and only the bodies change, so an
older `atm-functions.lua` loads perfectly, every call still succeeds, and the
mediator runs indefinitely with a capability it believes it has. 0.27.0's
per-relationship accounting is the worked example: a library predating it never
writes `PEER_Q`, so `peer_queue_count` reads 0 for every relationship for ever
and `limits.queue.peer` never fires, with nothing logged.

Startup now compares the file at `database.functions_file` against the copy
compiled into the binary and publishes `redis_functions_match_build`: `1`
match, `0` mismatch, `-1` the check could not be performed. Three states
because a check that could not read its file has reached no verdict, and
collapsing that into either of the other two gives one value two meanings —
one benign, one not. A mismatch logs at `error` with both digests and the
path, and shows as `degraded` on `/readyz` (200, still in rotation) via a
non-load-bearing `redis_stored_functions` component.

It **reports rather than refuses**, and the reason is what a stale library
actually costs. `limits.queue.peer` is a fairness and resource-exhaustion
control, not an authorization one: with an old library loaded that gate is
inert, but the sender-total and recipient-total gates still apply and nothing
becomes reachable that was not already. The failure is degraded fairness, not
unauthorized access. That is deliberately a narrower argument than "refusing to
boot would be an outage", which would equally justify failing open on an
authorization check — where it would be wrong.

Presence checks and function-name listings were both considered and rejected:
they report healthy for exactly the case that matters.

Additive: no configuration change, no API change, no behaviour change on any
message path. `tasks::statistics::statistics` gains two parameters (a clock and
`SurveyDefaults`), which affects embedded callers that spawn it themselves.

## Unreleased (0.28.3) — the send stream was trimmed at the receive limit

On the Redis backend the `store_message` Lua applies one `queue_maxlen`
argument to **both** `RECEIVE_Q` and `SEND_Q`, and the mediator passed
`queued_receive_messages_hard` as that argument. The send stream was therefore
bounded by the receive limit.

That was latent while the send soft limit was 200, far below the 1000 trim.
0.28.0 raised send soft to 2000 and send hard to 10000 and did not move the
trim, making it reachable in ordinary use. A trim removes the stream entry and
nothing decrements `SEND_QUEUE_COUNT` or `PEER_Q` — only `delete_message` does —
so past roughly 1000 queued messages a sender was refused by counters for
messages it could no longer list (`list_messages` reads the stream) or purge
(`DELETE /purge/{folder}` walks it), recovering only when the 7-day message
TTL expired. The same shape as a stuck queue, arriving by a second route.

`MAXLEN` is now derived — `LimitsConfig::queue_stream_maxlen()` — as the larger
of the two hard limits plus one, or 0 (no trimming) if either is unlimited.
Deriving it rather than configuring it is the point: the bound moves whenever a
limit does, so this cannot be walked past again by changing one number and not
the other. Trimming is a backstop against state the gates should have
prevented, never a bound on traffic they allow.

Redis only — the fjall and memory backends ignore `queue_maxlen`. No Lua change
and no `FUNCTION LOAD` needed for this fix.

**Also syncs `docker/test/conf/atm-functions.lua`**, which 0.28.0 left on the
pre-`PEER_Q` version. Anything running that config had `peer_queue_count`
reading 0 and the `limits.queue.peer` gate permanently inert — the headline fix
of that release, absent, with nothing failing, since the stale copy is valid Lua
that loads cleanly and defines every function by the same name. A new test
compares the two copies byte for byte, because any check short of that (does it
load? does it define the right functions?) passes on exactly this drift.


## Unreleased (0.28.2) — the Origin rule, stated correctly

No behaviour change. The `Origin` check is unchanged and the default stays
closed; what changes is that the documentation no longer contradicts it.

`conf/mediator.toml`, the setup wizard and this crate's own code comment all
said native clients send no Origin and are unaffected. Each sentence was true
and the set of them misled, because a reader substitutes "native" for "sends no
Origin" and those are not the same set. **React Native's WebSocket sends an
Origin derived from the URL**, so a mobile wallet is refused by the default
policy exactly as a browser is — and an integrator hitting it had three
documents telling them it could not be happening.

The rule is the header, not the client class: a request with no `Origin` is
admitted; one carrying an `Origin` the policy does not admit is refused, on REST
and on the WebSocket upgrade alike.

The refusal now names `[security] cors_allow_origin` and the new
`docs/cors-and-origin.md` in the operator-facing log. The response body to the
caller is unchanged.

Two tests were renamed for the same reason — `origin_check_allows_header_less_native_clients`
became `origin_check_admits_a_request_with_no_origin_header` — and
`origin_check_refuses_a_react_native_client_under_the_default` pins the case
that was missed.


## Unreleased (0.28.1) — a dropped live notification now says so

When a client's send queue was full, or the global byte budget exhausted, the
live notification was dropped. Nothing durable was lost — the message stays in
the recipient's inbox — and the drop was already counted. But nothing was said
on the wire, so a client that only *listens* never learned there was anything
to collect, and did not collect it. The drop was never the bug; the silence was.

The streaming task now raises a per-connection resync flag when it drops a
notification, and the socket handler sends a message-pickup 3.0 `status`
carrying the live `message_count` as soon as the socket is moving again. A
client already understands that message — it is the same one it receives for a
`status-request` — so the recovery needs no new protocol on the client side. In
TSP mode, where a notification is only ever a wake-up, the resync *is* the
drain and no separate signal is sent.

A flag rather than another queued frame, because the drop happens exactly when
there is no room to queue one. Repeated drops for a congested client collapse
into a single signal: the client's answer to any number of them is the same
single drain, and a congested socket is the worst place to add traffic.

Sending the signal is not free — an inbox read, a DID resolution and a
`pack_encrypted` — and the party deciding how often it happens is the congested
client, by choosing how slowly to read. A per-socket floor of 5s bounds that.
While the floor holds, the flag stays **raised** rather than being cleared, so a
deferred signal is delayed and never lost.

New counters `ws_live_resync_sent_total` and `ws_live_resync_suppressed_total`.
They deliberately do not match `ws_live_delivery_dropped_total` one for one:
drops coalesce, and a further signal is held back until the floor passes. A flat
sent-count beside climbing drops is therefore *correct* under sustained
congestion — drops climbing while **both** stay flat is the shape that means the
signal is not going out at all.

Additive: no configuration or API change.

## Unreleased (0.28.0) — the queue gates reach direct delivery

The three queue-depth gates lived in `protocols::routing`, which exists only in
a `didcomm` build and is reached only by a `forward`. Direct delivery — a client
handing the mediator an already-packed envelope for a local DID — and the TSP
bridge stored to a recipient's inbox with **no depth limit of any kind**: not
the sender total, not the recipient total, and not the per-relationship count
added in 0.27.0. A sender on that path could fill any inbox without bound, and
the VTI-29 fix did not reach it.

The gates move to `messages::queue_limits`, outside the `didcomm` gate, and
identify a message by id rather than by a parsed `Message` — the direct path
carries an opaque envelope. Direct delivery and the TSP bridge now run all
three before storing.

**Mediator-generated replies stay exempt**, and that is load-bearing rather
than a convenience: they are how a client is told its queue is full. Gating
them would turn a full inbox into an unreportable one, leaving the peer with a
silence it cannot distinguish from a dead mediator. The exemption falls out of
where the check sits — the `Envelope` arm is client traffic, the `Message` arm
is the mediator's own.

Breaking for operators: traffic on the direct path that was previously always
accepted can now be refused with `limits.queue.peer`,
`limits.queue.sender` or `limits.queue.recipient`.

## Unreleased (0.27.0) — forwards are gated per relationship

A sender was refused with `limits.queue.sender` once its per-DID send total
reached `queued_send_messages_soft` (default 200), counted across every
recipient at once. That total cannot tell a community holding one uncollected
membership card for each of 200 members from a sender aiming 200 messages at one
victim — and capping it punishes the first, so a community went silent to
*everyone* because enough of its members had not yet collected. An unresponsive
recipient degraded the sender globally, which is the wrong blast radius.

The gate that refuses a forward is now per-relationship: how many messages this
sender has queued for *this* recipient, against the new
`queued_send_messages_per_peer` (default 50), reported as `limits.queue.peer`.
Flooding one peer moves it; fanning out to many peers does not.

The per-DID send total remains as a coarse ceiling, raised 200 to 2000, and
`queued_send_messages_hard` 1000 to 10000 so the default no longer exceeds the
maximum an account may set for itself. Raising it is safe rather than a
relaxation: every queued message is counted in exactly one recipient's inbox, so
the receive limits already bound total storage on their own. The send total was
never a storage bound — only an abuse heuristic, and the wrong one.

**Operators on Redis must reload `atm-functions.lua`.** Until they do,
`peer_queue_count` reads 0 and the new gate is inert; the recipient-total and
sender-total gates still apply, so this fails safe rather than open.

Breaking: `LimitsConfig` gains a public field.

## Unreleased (0.26.5) — `DELETE /purge/{folder}`

Lets a DID empty one of its own queues in a single call. Clearing a queue
otherwise meant paging it (`/list` is capped at 100 with no cursor) and deleting
by id 100 at a time, every batch separately authenticated — the recovery path a
node needs precisely when it is already being rate-limited, which is to say
precisely when it cannot use it. `purge_folder` existed in every store the whole
time, reachable only as a side effect of deleting the account.

Scoped strictly to the caller: the DID comes from the authenticated session,
never the request, so there is no way to purge another DID's queue. Same
`Capability::Local` gate as `/delete`, since emptying a queue is a superset of
deleting from it. Destructive and unrecoverable, so the count and bytes are
logged at `info`.


## Unreleased (0.26.4) — `vta-sdk` 0.43

Moves the `vta-sdk` pin from `0.40` to `0.43`, which is where the
post-quantum provisioning chain lands: a VTA can now mint a signing key beyond
the classical pair, and the sealed bundle carries it.

No mediator behaviour changes. The pin had been two minors behind, so this also
picks up everything in 0.41–0.42.

## Unreleased (0.26.3) — the TSP relay path is capability-gated, and `/readyz` stops leaking

Two security fixes from the SEC-4045 review.

- **TSP routed-relay requires `SEND_FORWARDED` (T1 sub-fix).** The DIDComm
  `routing/2.0/forward` path refuses to relay for a sender that lacks the
  `SEND_FORWARDED` capability; the TSP routed/nested relay path
  (`handle_inbound_tsp` → `forward_to_next` → `forward_tsp_remote`) reached the
  same enqueue sink with no such check, so an authenticated DID whose
  `SEND_FORWARDED` was never granted (or was revoked) could still drive a relay.
  The authenticated TSP relay arms now run
  `authz::require_capability(&from_acls, Capability::SendForwarded)`, authorised
  on the envelope sender's own ACLs — matching the DIDComm 403. (The egress
  guard for the forwarding client itself is in
  `affinidi-messaging-mediator-common` 0.16.1.)
- **`/readyz` no longer folds backend error detail into the public body (T3).**
  The unauthenticated readiness probe echoed `format!("… {e}")` for the Redis,
  forward-queue and VTA-cache checks and each component's `last_error` verbatim —
  host:port and internal paths to any scanner that can reach the LB probe. It
  now emits a static per-check message and a `has_error` boolean, with the detail
  logged at `warn` for operators, the same treatment the secrets-backend probe
  already used.

## Unreleased (0.26.2) — `did_rate_limit_per_second` is enforced

`limits.did_rate_limit_per_second` / `did_rate_limit_burst` were parsed, built
into a `DidRateLimiter`, garbage-collected and announced at startup as "Per-DID
rate limiting enabled" — and refused nothing, because nothing called the
limiter. They now do what the configuration says.

- **Where it is charged.** Once per authenticated HTTP request, in
  `authenticate_token`, after the JWT, the session record and the blocked check
  have passed. That is every route that authenticates a caller: `/inbound`
  (DIDComm and TSP), `/outbound`, `/fetch`, `/list`, `/delete`, `/whoami`,
  `/oob`, `/admin/status` and the `/ws` upgrade. Charging after validation is
  deliberate: charging before it would let a forged token naming a victim DID
  spend that DID's quota.
- **The refusal** is the same `429` contract as the per-IP limiter's:
  `x-rate-limit-source: mediator`, `Retry-After: <secs>`, and
  `{"error":"rate_limited","limiter":"mediator","scope":"did","message":…,
  "retryAfterSecs":N}`. `limiter` names the refusing *service*, as before,
  because `affinidi-messaging-sdk` falls back to it when a proxy strips the
  header; the added `scope` member says which of the mediator's limiters
  refused. `affinidi-messaging-sdk` reads it as `ATMError::HttpStatus` with
  `is_rate_limited()`. New `AuthError::RateLimited { retry_after_secs }`
  (`AuthError` is `#[non_exhaustive]`).
- **`0` still disables it**, and is still the default.
- **Never charged:** the mediator's own DID and the configured `admin_did`
  (throttling the operator's management plane is how an incident response locks
  itself out), and anonymous sessions — the inter-mediator relay session and
  the DIDComm v1 anonymous-forward session. Those carry no DID; an
  inter-mediator hop is always posted anonymously, so forwarded traffic is never
  keyed on a peer mediator's DID, and a forward a client submits is charged to
  that client, the authenticated sender. The per-IP limit still applies to all
  of them.
- **Metrics.** `rate_limited_total` now carries a `scope` label: `ip` for the
  per-IP limiter, `did` for this one. A query that sums the metric is
  unaffected; one that matches the series without labels is not.
- **Startup log** now says what is metered and what is not.
- `DidRateLimiter` gains `try_acquire` (the decision plus a `Retry-After` hint),
  `with_exempt_did_hashes`, `is_enabled` and a `Debug` impl;
  `did_rate_limiter::refusal_response` builds the `429`. `check` is unchanged.

### Bounded distinct-DID tracking (CWE-770)

`governor` caps the request rate *within* each DID's bucket but never the
*number* of distinct DIDs, and the GC only reclaims fully-replenished buckets
every 60s. Between sweeps, an adversary cycling through many distinct
*authenticated* DIDs faster than they replenish could grow the keyed `DashMap`
without bound. `DidRateLimiter` now caps distinct tracked DIDs at
`MAX_TRACKED_DIDS` (100_000): when the store is full and a *new* DID arrives it
first attempts a throttled reclaim of replenished buckets and, if still full,
fails that new DID closed with the same `429` contract rather than growing the
map. A DID already tracked is never refused for capacity or evicted mid-window,
and disabled mode (`did_rate_limit_per_second == 0`) is unaffected. The inline
reclaim is throttled (≤ one pass per 100ms) so the admission check can't itself
become a CPU-exhaustion lever. The shared per-IP limiter
(`affinidi-rate-limit` 0.1.2) gained the same bound.

### Known gap: frames on an established WebSocket are not metered

The `/ws` upgrade is charged; the messages a socket then carries are not. A
client that sends over its socket is bounded by how often it can re-upgrade and
by the queue limits, not by `did_rate_limit_per_second`. This is left open
rather than guessed at: an in-session refusal has no HTTP status to carry it,
DIDComm's problem-report registry has no rate-limit descriptor (and none is
invented here — reusing `limits.queue.sender` would tell the client the wrong
thing), and closing the socket would drop a frame the client already believes it
sent. Choosing the signal is a protocol decision. `conf/mediator.toml` says so
next to the key.

## Unreleased (0.26.1) — a `429` says it came from the mediator

The per-IP limiter's refusals now carry the ecosystem's rate-limit attribution
contract (`affinidi-rate-limit` 0.1.1):

- `x-rate-limit-source: mediator`;
- `Retry-After: <seconds>`, as before;
- a JSON body `{"error":"rate_limited","limiter":"mediator","message":"…",
  "retryAfterSecs":N}` in place of the old plain-text body.

The limiter wraps every application route: REST, the websocket upgrade (`/ws`)
and DIDComm/TSP ingress (`/inbound`). So every `429` the mediator produces is
labelled. The health, readiness, liveness, admin-status and metrics routes are
outside it, as before. A client can now tell the mediator's limit from a VTA's,
a DID host's or a proxy's. `affinidi-messaging-sdk` 0.26.2 reads it as
`ATMError::HttpStatus` with `is_rate_limited()`.

**BEHAVIOUR:** a `429` body is JSON, not text. A client showing the raw body
will show the JSON.

### Known gaps (unchanged by this release)

- **`did_rate_limit_per_second` / `did_rate_limit_burst` enforce nothing.**
  *(Fixed in 0.26.2 for HTTP requests.)*
  `DidRateLimiter` is built, garbage-collected and logged as "Per-DID rate
  limiting enabled" when configured, but nothing calls `check`. No request and
  no websocket frame is ever refused per DID. So there is no in-session refusal
  to label, and no problem-report code for one. DIDComm's problem-report
  registry has no rate-limit descriptor, and none is invented here. Enforcing it
  needs a refusal signal on an established websocket, and that needs a spec
  first.
- `max_websocket_connections_per_did` is a concurrency cap, not a rate limit.
  It closes the socket with `POLICY` ("per-DID connection limit reached"), as
  before. The queue limits (`limits.queue.sender` / `limits.queue.recipient`)
  still answer `503`.

## Unreleased (0.26.0) — `trust-tasks-rs` 0.21

Dependency move only; no source change here. Minor for the same reason as
`affinidi-messaging-sdk` 0.26.0 — `trust_tasks_rs` types reach this crate's
public surface, so two versions in one graph is a type error rather than a
duplicate.

## Unreleased (0.25.0) — TSP Rev 3: a uniform delivery refusal, and no DIDComm bridge

**Breaking, deliberately.**

- **Every refused delivery now answers the same way**, over TSP and DIDComm
  alike. These five codes are retired:

  ```text
  direct_delivery.recipient.unknown
  authorization.receive
  authorization.receive_anon
  authorization.receive_forwarded
  authorization.access_list.denied
  ```

  All ten sites that raised them now answer `delivery.refused` /
  "Message not accepted for delivery" with `403`, and log the real reason
  against the session so operators keep full diagnostics.

  Each of the retired codes told an unauthenticated sender something it had no
  business learning — whether a DID has an account here, and if so which of
  several ACL rules turned it away. Distinguishing them is a probing oracle,
  and the distinction was never actionable by a legitimate sender, who can do
  nothing differently on learning which rule refused. A refusal is now a
  refusal.

  A consumer matching on any of these will stop matching. The scan across the
  VTI repos found no code that does — the only occurrences are two doc comments
  in `openvtc-core/src/tsp.rs` recalling a past debugging session, which will
  read as stale once this lands.

- **The DIDComm↔TSP bridge is removed.** It re-packed a TSP message as DIDComm
  and back, which cannot be done without breaking the end-to-end guarantee the
  ESSR signature exists to provide: the bridge is by construction a point where
  the message is decrypted and re-signed by someone who is not the sender. Rev 3
  makes this explicit and the bridge unimplementable as specified. Deployments
  relying on it must move both ends to one protocol.

- **A relayed endpoint-to-endpoint VID is no longer written to disk.** Rev 3
  §5.3.3 says an intermediary "SHOULD not process the endpoint-to-endpoint VIDs
  `VID_a2` and `VID_b2` and MUST NOT store `VID_a2` and `VID_b2` in any
  persistent storage". When this mediator unwrapped a metadata-privacy nesting
  and the inner recipient was not local, it enqueued the forward with the inner
  receiver's VID in plaintext — and the forward queue is durable by design, a
  retry queue that survives restarts and holds entries for
  `message_expiry_seconds`. So a transit intermediary accumulated
  `(sender → far endpoint)` pairs from relationships that were not its own,
  which is the exposure the rule exists to prevent.

  Processing the VID is unavoidable — the message cannot be routed onward
  without resolving its destination — but retaining it is not, and retention is
  the part the specification forbids outright. The queue now carries only the
  hash and the resolved endpoint URL on that path, which is everything delivery
  used; the plaintext only ever fed diagnostics and the abandonment report, and
  those fall back to the hash. Local delivery was already clean: it works
  entirely on hashes.

  Ordinary forwards are unchanged. A route hop, or the destination's VID at its
  own intermediary, is a routing-layer identifier this mediator is addressed by
  and may keep — the new `Destination` enum draws that line at the three call
  sites, which are otherwise indistinguishable.

- Requires `affinidi-tsp` 0.2 when built with `--features tsp`.

## Unreleased (0.24.3) — `vta-sdk` 0.32 → 0.38

No source change in this crate. The bump matters for what it removes from the
graph rather than what it adds.

`vta-sdk` 0.32.4 depended on `affinidi-tdk` ^0.11 and `affinidi-messaging-sdk`
^0.21, neither of which the workspace copies (0.14.0 and 0.24.0) satisfied, so
`[patch.crates-io]` could not redirect them and cargo built the published
copies **alongside** the local ones. The lockfile carried two `affinidi-tdk`,
two `affinidi-messaging-sdk`, two `didwebvh-rs` and two `did-scid` nodes. This
crate's own manifest already warned that a stale `vta-sdk` ceiling is how a
second `trust-tasks-rs` got in; it had happened again, one layer over.

0.38 wants `affinidi-tdk` 0.14, `affinidi-messaging-sdk` 0.24, `didwebvh-rs`
0.7 and `trust-tasks-rs` 0.20.5 — what this workspace holds — so every patch
now applies and each resolves to exactly one copy.

Also carried: `persona/facet`, client-side verification of Trust-Task replies
(0.35), the domain-separated opaque signing oracle (0.37), and did:webvh
public-host-only resolution (0.38).

## Unreleased (0.24.2) — `aws-smithy-types` held below 1.7

No behaviour change; a resolver bound only.

`aws-smithy-types` 1.7.0 replaced `Document::Object`'s payload and added a
variant to a `#[non_exhaustive]` enum in a MINOR release, which
`aws-smithy-json` 0.63.0 — what `aws-config` 1.12.0 still pulls — does not
compile against. This workspace ships no `Cargo.lock`, so every clone resolved
from scratch and took the break — including this crate's `aws` and
`secrets-aws` builds.

`aws-smithy-types` is now a declared (optional) dependency under the same
feature as `aws-config`, contributing the `>=1.6.1, <1.7` bound from
`[workspace.dependencies]`. Remove it once `aws-config` ships on json 0.64.

## Unreleased (0.24.1) — `didwebvh-rs` 0.7

- Bumps `didwebvh-rs` 0.6 → 0.7. There is no source change: this crate reads
  its own did:webvh log through `LogEntry`, which 0.7 leaves unchanged.
- **Behaviour, through `affinidi-did-resolver-cache-sdk` 0.8.37:** the resolver
  this mediator builds from `[did_resolver]` now refuses did:webvh DIDs on
  non-public hosts, as it already did for did:web. `[did_resolver]` has no
  setting for this. Two consequences:
  - A mediator whose own DID is `did:webvh:…:localhost%3A<port>`, and which
    does not self-host that DID, logs the existing "Could not resolve our own
    published DID document at boot" warning and skips the operating-secret
    coverage check.
  - Peers whose DIDs are on such hosts no longer resolve.

  An embedder can pass a `DIDCacheConfig` built with
  `with_host_policy(HostPolicy::AllowPrivate)` to `MediatorBuilder::did_resolver`.

## Unreleased (0.24.0) — `trust-tasks-rs` 0.20

- Bumps `trust-tasks-rs` 0.19 → 0.20. **No source change** — only manifests.
  0.20 is additive for everything this crate uses: its one breaking change is a
  `process-attestation` schema tightening (digest floor 16 → 43 base64url
  characters, a category correction, a dropped duplicate member), and no crate
  in this workspace references that spec.
- **Moves because it is the path, not because its own code changed.** This crate
  re-exports `affinidi-messaging-sdk`, so a consumer reaching a generated type
  through the facade sees the same API change. Leaving it unbumped would publish
  a move that never arrives — and the version guard cannot see it, because only
  its manifest changed.

## Unreleased (0.22.3) — answer management Trust Tasks over TSP

A TSP-only deployment could not manage its own accounts. The dispatcher that
turns a `TrustTaskEnvelope` into `account/update`, `acl/get`,
`access-list/update` and the rest — `MessageType::process` — is wholly
`#[cfg(feature = "didcomm")]` and takes a DIDComm `Message`, so a TSP
`Direct`/`Control` message addressed to the mediator never reached it. It went
to `deliver_tsp_local` → `deliver_opaque`, which files it for pickup. There was
no packet a TSP-only client could send to set its own account ACL.

That bites where it is least visible. An account is created at authentication
with `global_acl_default`, so a permissive default hides the gap entirely; a
restrictive one leaves the client unable to fix its own ACL over any transport.
TSP delivery is not exempt from ACLs — `deliver_opaque` applies existence,
`RECEIVE_MESSAGES` and the access-list verdict through `delivery_decision`.

The handlers were already transport-agnostic: each takes the document, the
authenticated sender, `state` and `session`, and nothing about them is DIDComm.
So the dispatch splits into a core plus a wrapper per transport.

- `consume` runs the dispatch and returns the response document. It requires the
  caller to have established the sender cryptographically — the handlers
  authorise against that sender, so a caller passing an unverified claim would
  hand over the admin surface.
- The DIDComm wrapper is unchanged in behaviour: sender from `UnpackMetadata`,
  document from the message body, reply packed as a DIDComm message.
- The TSP wrapper unpacks a `Direct`/`Control` message addressed to this
  mediator, dispatches, then seals the reply to the sender and delivers it
  through the ordinary local path — so it arrives on the client's existing
  pickup socket. No second socket, and no new delivery mechanism.

The TSP sender carries the same standing as the DIDComm one: `direct::unpack`
verifies Ed25519 over envelope‖ciphertext against the key resolved from the
VID's DID document *and* opens with HPKE-Auth, binding the sender's static key.
Two independent proofs, which is what lets the handlers authorise on it
unchanged.

Requests are recognised by payload rather than a binding type URI, because the
client packs the bare task document and there is no envelope tag to switch on. A
document that parses *and* names a served type is claimed; everything else falls
through to delivery unchanged, so ordinary traffic addressed to the mediator is
unaffected.

**Behavioural note for operators.** A message that previously landed in the
mediator's own inbox is now answered if it is a served management task. Nothing
else changes, and no client is required to move — the DIDComm path is
untouched.

## Unreleased (0.22.2) — admit an inter-mediator relay over WebSocket

The WebSocket route now admits an anonymous inter-mediator relay hop, on the
same terms `/inbound` has always used: only when the operator has opted in via
`security.enable_inter_mediator_relay` (or the legacy implicit
`SEND_FORWARDED` in `global_acl_default`), and only for a socket that
identifies itself by offering the `relay-ack` subprotocol. The admission
decision itself now lives in one place — `jwt_auth::anonymous_relay_session` —
so the two routes cannot drift on *who* is let in.

What such a socket may do is deliberately narrow, and structurally so rather
than by enumeration:

- **It is never registered with the streaming task.** A relay session has no
  DID, so registering would claim the empty `did_hash`'s stream for an
  anonymous peer. Skipping it is what makes "a relay can only send" a property
  of the code rather than of which message types we happen to handle: the
  socket's inbound channel can never yield.
- **It is gated on `SEND_MESSAGES`, not `LOCAL`** — the same capability
  `message_inbound_handler` requires of the REST relay session. `LOCAL` gates
  access to an inbox this session does not have.
- **It gets a `RelayAck` per frame instead of a problem report.** A problem
  report is packed *to* `session.did`, which a relay session does not have,
  and the peer is a mediator waiting on a transport answer rather than a client
  reading its inbox. The ack carries the mediator error code and reason on
  refusal, so the rejection reaches the relaying peer's logs and — once retries
  are exhausted — the original sender.
- **Raw-TSP mode is forced off, and a binary frame closes the socket.** Neither
  can arise from a correct peer; both are enforced rather than assumed, because
  the cost of being wrong is an anonymous socket registered as a live streaming
  client.
- **`relay-ack` is echoed if and only if the socket will actually be acked.**
  An authenticated client that offers it is not a relay — a relay hop presents
  no credential — so the entry is dropped from the echo rather than reflected
  back. Same honesty requirement as `tsp-ack`, and here it is load-bearing: the
  relaying peer relays over the socket *because* of that echo.
- **The socket has a bounded lifetime** (one hour). There is no token expiry to
  inherit, and re-admission re-runs the relay-enabled check against current
  configuration — so turning relay off takes effect without a restart.

`docs/multi-mediator.md` §7 is updated, and its §11 "known gaps" is now empty:
this was the gap.

The `affinidi-messaging-mediator-common` requirement moves from `0.15.37` to
`0.15.44`, the version that introduces `relay_ack`. The old floor allowed a
consumer resolving from the registry to pick a `0.15.x` without the module and
fail to build this crate — normally masked by cargo picking the newest patch,
but not under a lockfile pinning an older one. (`publish dry-run` is expected
to be red on this PR: it resolves each crate against the registry in isolation
and cannot see an unpublished sibling from the same PR. mediator-common 0.15.44
verifies and publishes cleanly on its own, so the release job's dependency
ordering resolves it.)

## Unreleased (0.22.1) — a multi-mediator guide, and the gaps writing it exposed

`docs/multi-mediator.md` documents federating two or more independent
mediators. The material existed only as scattered fragments — a section of
`docs/acls.md`, a section of the test-mediator README, `TestTopology`'s
rustdoc, and the config file's per-key comments — with nothing tying them
together.

What it covers, and the parts that were not written down anywhere before:

- **The two hop shapes land on different code paths at the receiving
  mediator.** A double forward arrives as a forward and needs
  `RECEIVE_FORWARDED`; a single forward (`ATM::send_to`'s DIDComm shape)
  arrives as a *direct delivery* and needs `local_direct_delivery_allowed`.
- **The four accounts one cross-mediator delivery consults**, with the error
  code each produces — including the non-obvious one: the *peer mediator's*
  DID needs an account with `RECEIVE_FORWARDED` on the relaying mediator, and
  nothing but `global_acl_default` creates it. The shipped default grants
  neither forwarded bit, so it is not a federation configuration.
- **Endpoint classification** — DID vs URL, one hop of indirection, and the
  three "Storing locally — it will not be delivered" warnings that follow a
  `200` to the sender.
- Blind vs rewrap, relay admission, delivery mechanics, the TSP differences, a
  `TestTopology` recipe, and a symptom-to-cause table.

Every claim is sourced from the code path named in its section and from the
cross-mediator e2e suites, which the document lists as its executable form.

**`ERRORS.md`:** the table stopped at 89 while the code reaches 94. Adds 90
(`me.res.forwarding.enqueue`), 91, 92, 94 (`protocol.forwarding.loop_detected`)
and the second variants of 58 (`message.tsp.no_endpoint`) and 60
(`authorization.relay.untrusted_peer`) — the last two both on relay paths this
document sends readers to. Corrects the access-list batch limit row, which was
still filed under 82 after the code moved it to 93.

**`conf/mediator.toml`:** documents `max_hops` (previously defaulted at 10 with
no mention in the file) and names `LOCAL_ENDPOINTS`. The `Env:` lines for
`PROCESSOR_FORWARDING_RELAY_MODE` and
`PROCESSOR_FORWARDING_RELAY_TRUSTED_MEDIATORS` were describing overrides that
did not exist; they do now — see mediator-config 0.2.2.

Also picks up mediator-common 0.15.43, which stops the forwarding processor
re-attempting a WebSocket upgrade that an anonymous relay hop can never pass.

Documentation, configuration comments and a dependency bump — no behaviour
change in this crate.

## Unreleased (0.22.0) — `jsonwebtoken` is now a private dependency, and moves to 11

Closes [#770]. **Breaking:** `SecurityConfig::jwt_encoding_key` and
`jwt_decoding_key` are no longer public fields. Set them with the new
[`SecurityConfig::set_jwt_keys_from_pkcs8`], which takes the Ed25519 PKCS#8
document — the same bytes the production path already reads from the
`JWT_SECRET` well-known entry — and derives both keys from it.

**Why this was worth a breaking change.** Those fields are `jsonwebtoken` types,
so while they were public, `jsonwebtoken` was a *public dependency* of this
crate: anyone constructing a `SecurityConfig` had to name `EncodingKey` /
`DecodingKey` and therefore had to compile against the same `jsonwebtoken`
major we did. Every bump of it was then source-breaking for consumers rather
than routine currency.

That is not theoretical. It was caught in #767, where bumping to 11 as ordinary
dependency currency made `affinidi-messaging-test-mediator` fail to build
against the published mediator with `expected jsonwebtoken::decoding::DecodingKey,
found DecodingKey`. It would have gone green at release time, because crates
publish in dependency order — so a breaking change would have shipped as a patch
bump, and any consumer mixing versions would have got a type error pointing at
neither crate.

**`jsonwebtoken` 10 → 11** now lands as part of this, and from here on such
bumps are internal.

Two smaller consequences worth naming:

- The key derivation lived in two places (the config loader and the test
  fixture), each doing `Ed25519KeyPair::from_pkcs8` then `DecodingKey::from_ed_der`.
  It now lives only in `set_jwt_keys_from_pkcs8`, so the signing and verification
  keys cannot drift apart.
- New `install_jwt_crypto_provider()` at the crate root. `jsonwebtoken`'s
  `aws_lc_rs` provider is registered per *instance* of that crate, so a consumer
  installing it against its own copy installs nothing for the copy this mediator
  verifies with. While the key fields were public that mismatch was at least a
  compile error; with the dependency private it would have become a silent
  runtime failure, so the installation has to be callable from here.

[#770]: https://github.com/affinidi/affinidi-tdk-rs/issues/770

## Unreleased (0.21.0) — `trust-tasks-rs` 0.18

**`trust-tasks-rs` 0.17 → 0.18.** Follows `affinidi-messaging-sdk` 0.22.0. No
source change; the generated types this crate uses are unaffected by 0.18's
only change. Minor rather than patch because the SDK's move is breaking for
consumers — `trust-tasks-rs` is a public dependency of its API — and this
crate's requirement moves with it.

## 0.20.11 — dependency currency

Published. No behaviour change. Two major-version dependency bumps, verified
against the full suite (242 unit tests, 30 e2e suites) rather than a compile:

- **`itertools` 0.14 → 0.15.**
- **`tikv-jemallocator` 0.6 → 0.7** — the allocator behind the `jemalloc`
  feature. The memory work in 0.17.0 measured against jemalloc, so this is worth
  re-measuring if RSS is ever in question again.

`jsonwebtoken` 10 → 11 was attempted here and pulled back out: `SecurityConfig`
exposes `pub jwt_encoding_key: EncodingKey` and `pub jwt_decoding_key:
DecodingKey`, so jsonwebtoken is a **public dependency** of this crate's API and
bumping it is semver-breaking rather than routine currency. Tracked separately.

## Unreleased (0.20.10) — TSP relay honours the peer-mediator allowlist

Closes [#758], raised by the AgenticSec review on #756 (alert 67) and by the
correction it prompted: `relay_peer_trusted` was DIDComm-only, so a TSP
deployment that needed its relaying peer authenticated had no lever at all.

`processors.forwarding.relay_trusted_mediators` now applies to TSP relay hops,
and TSP gets a stronger form of it than DIDComm. A routed or nested hop is
sealed to this mediator, so `handle_inbound_tsp` unpacks it — verifying an
Ed25519 signature over envelope‖ciphertext against the key in the sender's DID
document, *and* opening the payload with HPKE **Auth**, which binds the sender's
static key. Two independent proofs, so the peer identity the allowlist is
checked against is cryptographically established rather than claimed.

**No `RelayMode` distinction is needed.** DIDComm can only identify its peer in
`RelayMode::Rewrap`, where a layer addressed to this mediator can be
authcrypt-opened; in `Blind` the peer is invisible and the allowlist is ignored.
TSP routed relay is re-wrap-like *by construction* — every hop is sealed to the
next and authenticated as the previous — so there is no mode to select and no
blind variant to except.

Two scoping rules, both load-bearing:

- **Anonymous sessions only.** This is the part that differs from DIDComm and is
  easy to get wrong. Only a peer mediator ever produces a DIDComm re-wrap layer,
  so peeling one is inter-mediator by construction; a TSP *routed* message is
  not — an ordinary client sends one through its own mediator for metadata
  privacy (TSP §5.5). Gating those on a list of peer *mediators* would refuse
  every routed client the moment an operator populated it. An inter-mediator hop
  arrives with no `Authorization` header, on the anonymous session, which is
  exactly the traffic this list exists to admit or refuse.
- **Relay arms only.** `Direct` and `Control` addressed to this mediator are
  messages *to* it — Trust Tasks over TSP arrive that way — not relays through
  it.

What this does **not** cover, stated plainly: TSP opaque pass-through (a message
addressed to a local recipient rather than to this mediator) has nothing
addressed to us to open, so there is no peer to identify and no allowlist can
apply. That is the true analogue of DIDComm blind relay. `security.enable_inter_mediator_relay`,
which gates anonymous inbound at all, and `security.local_direct_delivery_allowed`
are the levers there. The comment added in 0.20.7 saying TSP had no equivalent
hardening has been corrected to say precisely which hops are now covered.

Not a behaviour change for any deployment leaving `relay_trusted_mediators`
empty, which is the default and means "accept any peer".

[#758]: https://github.com/affinidi/affinidi-tdk-rs/issues/758

## Unreleased (0.20.9) — TSP direct delivery honours `local_direct_delivery_allowed`

Closes [#757], the gap deliberately left open by 0.20.7 and independently
confirmed by the security review on that PR.

`security.local_direct_delivery_allowed` exists so an operator can refuse
unwrapped direct delivery and force everything through a routing envelope, where
the relay layer can audit it, scrub metadata, or inspect it. The DIDComm path
enforced it; `handle_inbound_tsp` did not, so any TSP-capable sender walked
straight past that control and the operator got no such enforcement for TSP
traffic.

- The `receiver != mediator` branch of `handle_inbound_tsp` — the genuine
  direct-delivery case — now returns the same `direct_delivery.denied` (code 71)
  report the DIDComm branch does when the switch is off.
- **No TSP analogue of `local_direct_delivery_allow_anon`, deliberately.** That
  hatch exists because a DIDComm envelope can be anon-packed with no sender at
  all; a TSP envelope always names its sender in the clear, so there is no
  anonymous TSP case to admit. `docs/acls.md` now records this as the single
  remaining asymmetry between the two protocols, in place of the deviation note
  0.20.7 added.
- Relay and nested submissions are unaffected: they are addressed to the
  mediator, not to a local account, so they never reach this branch.

**Behaviour change.** A deployment running with direct delivery disabled — the
code default when the setting is absent, though the shipped `conf/mediator.toml`
sets `"true"` — will now refuse direct TSP delivery that it previously accepted.
That is the point of the fix, but it is a break for anyone who had (knowingly or
not) been relying on TSP bypassing the switch (R3.6).

**Test-harness change (`affinidi-messaging-test-mediator` 0.4.4).** The fixture
defaults the flag off, and 23 TSP tests across nine files were written against a
path that ignored it. Rather than 23 hand-rolled builders, the harness gained
`TestEnvironment::spawn_with_direct_delivery()`, and the two TSP-specific spawns
(`spawn_with_tsp_auth`, `spawn_with_tsp_policy`) now enable direct delivery
themselves — every caller of those needs it, since protocol selection and pure-TSP
auth are only observable once a message is accepted. Tests whose subject *is* the
policy state it at the call site instead.

[#757]: https://github.com/affinidi/affinidi-tdk-rs/issues/757

## Unreleased (0.20.8) — state the v2 addressing contract: DID-addressed, no keylist

Answers [#755]. A downstream transport binding measured that delivery to a
`did:key` client works purely on the authenticated session DID, with no keylist
update, and asked whether that is a contract or an accident.

It is structural, and now it is written down.

- **New `docs/mediation-and-routing.md`.** DIDComm v2 routing is DID-addressed:
  a `routing/2.0` forward names its next hop as a DID, which hashes straight
  into the recipient's account lookup. There is no verkey indirection for a
  keylist to populate, so a v2 client registers nothing. The mediator maintains
  the account itself — `resolve_next_account` creates one on first forward, and
  authentication registers the DID too.
- **The keylist that exists is v1-only, and the document says why.** A DIDComm
  v1 (Aries RFC 0019) envelope carries no DID, so the recipient is identified by
  verkey and the mediator must hold the verkey→account mapping; the keylist is
  how a wallet populates it. It exists to manufacture a stable identifier for a
  client that has none — which a v2 `did:key` client already has.
- **The advertised protocol set is now a named constant**,
  `messages::protocols::discover_features::ADVERTISED_PROTOCOLS`, which
  `server.rs` builds its `DiscoverFeatures` state from. The list was previously
  inline in a long startup function and could not be asserted on.
- **`coordinate_mediation_is_not_advertised`** pins the absence, so implementing
  v2 mediation becomes a deliberate act — amending a contract other people have
  built on — rather than an incidental change that silently invalidates it.
  `did_addressed_delivery_protocols_are_advertised` is its control: without it
  the first test would pass just as happily against an empty list.

The document is also explicit that "no keylist" is not "no requirements", since
that is the part most likely to bite a client author. `mediator_acl_mode =
"explicit_allow"`, the `LOCAL` / `RECEIVE_MESSAGES` / `RECEIVE_FORWARDED`
capabilities, the recipient's access list and `local_direct_delivery_allowed`
all gate reachability without any keylist being involved — and direct delivery
to a DID that has never authenticated is refused (`direct_delivery.recipient.unknown`)
where a forward to the same DID would auto-create the account.

No behaviour change: documentation, one extracted constant, and three tests.

[#755]: https://github.com/affinidi/affinidi-tdk-rs/issues/755

## Unreleased (0.20.7) — bind a TSP envelope's sender to the authenticated session

**Security fix: the TSP ingress trusted the envelope's claimed sender.**
Reported as [#754], measured against a public deployment: a TSP frame sent on a
socket authenticated as DID A, carrying envelope sender DID E (never
authenticated), was forwarded normally.

A TSP envelope names its sender in the clear and the mediator does not decrypt
it, so `meta.sender` is a claim. `handle_inbound_tsp` never consulted the
session at all — it passed that claim straight to `deliver_opaque`, which hashes
it into the recipient's `delivery_decision` access-list lookup. An authenticated
client could therefore borrow any allow-listed VID and be admitted to an inbox
that does not admit it.

This is the TSP twin of the DIDComm direct-delivery bypass fixed in 0.15.5. The
TSP path was written after that fix and did not carry it. `docs/acls.md` §6 has
documented the flow as "Direct delivery (DIDComm and TSP)" — including the
session-DID match — the whole time, so the contract was already stated; only the
implementation was missing.

- The cleartext envelope sender is now bound to the session DID under the same
  `security.force_session_did_match` switch the DIDComm paths use, reusing the
  same `check_direct_delivery_session_match` predicate and returning the same
  `authorization.did.session_mismatch` problem report.
- Checked on the **outer** envelope, before the receiver branch, so it covers
  relayed and nested submissions too: a client must have authored the layer it
  hands over. Inner layers are exempt by construction — they are sealed to
  someone else.
- **Anonymous sessions are exempt**, exactly as on the DIDComm side since 0.20.4:
  an inter-mediator relay hop is POSTed to `/inbound` with no `Authorization`
  header and lands on the anonymous `ANON-INBOUND` session, whose DID is empty.
  Without the exemption cross-mediator TSP delivery would stop entirely. The
  residual cost is the one already named for blind relay: on an anonymous hop the
  claimed sender stays unverified, which is inherent to relaying. Note the
  asymmetry: DIDComm deployments that need the relaying peer authenticated can run
  `RelayMode::Rewrap` with `processors.forwarding.relay_trusted_mediators`, and
  **TSP has no equivalent yet** — `relay_peer_trusted` is DIDComm-only. Anonymous
  inbound is itself opt-in (`security.enable_inter_mediator_relay`, or the legacy
  implicit `SEND_FORWARDED` in `global_acl_default`), which bounds the exposure to
  relay-enabled deployments.
- Direct TSP delivery now also checks the sender's own `SEND_MESSAGES`, mirroring
  the DIDComm direct-delivery branch. This is load-bearing on the **WebSocket**
  ingress in particular, which gates only on `LOCAL` at upgrade: a DID whose
  `SEND_MESSAGES` had been revoked could still post TSP frames over a socket.

**Behaviour change.** A client that deliberately sends under a VID other than the
one it authenticated as will now be refused with
`e.p.authorization.did.session_mismatch` unless the deployment sets
`security.force_session_did_match = "false"`. Deployments relying on the split
between connection identity and egress identity should move to TSP **routed**
mode, where the outer sender is the connection identity and the egress identity
travels inside the sealed layer — that shape satisfies the binding by
construction (R3.6: coordinate with consuming repos).

**Still outstanding, tracked separately:** TSP direct delivery does not honour
`security.local_direct_delivery_allowed`, so a deployment that has turned direct
delivery off to force everything through a routing envelope still accepts direct
TSP. That is a policy change with far wider blast radius than this fix — it
changes the default fixture's behaviour for ~20 existing tests — and is being
handled on its own rather than folded in here.

[#754]: https://github.com/affinidi/affinidi-tdk-rs/issues/754

## Unreleased (0.20.6) — TSP forwarding follows a next hop that names its mediator by DID

**Bug fix: TSP remote forwarding could not deliver to a mediated peer.** Observed
on a live mediator:

```text
WARN forwarding::processor: FORWARD_FAILED
  endpoint=did:webvh:Qmb…:dids.firstperson.dev:firstperson-mediator
  error=Connection error to did:webvh:…/inbound:
        builder error for url (did:webvh:…/inbound)
  retry_count=5  → FORWARD_ABANDONED
```

The `endpoint` is a DID, not a URL. Two documents are involved, and the mediator
was only reading the first:

```text
persona     #tsp  TSPTransport  serviceEndpoint: did:webvh:…firstperson-mediator
that mediator #tsp TSPTransport  serviceEndpoint: https://mediator.firstperson.dev/mediator/v1
```

- `forward_tsp_remote` no longer takes `endpoints.first()` as a URL. A new
  `classify_tsp_relay` decides — without I/O — between a direct transport URL, a
  mediator DID to follow, a hop that comes back to us, and nothing usable. A
  mediator DID is resolved **one hop**, and that document's own `TSPTransport`
  URL is what the forward is enqueued against.
- **One hop only**, mirroring `protocols::routing::service_endpoint_for_remote`
  on the DIDComm side (added in #705 for exactly this shape): a mediator's own
  document is expected to publish a URL, and chasing further would let a chain of
  documents steer this mediator's relay.
- The loop guard is extended, not weakened: a transport URL on one of our own
  authorities still fails as a loop, and so does a next hop that names *this*
  mediator as its mediator while holding no account here.
- Failure now names the next hop and distinguishes its causes —
  `message.tsp.no_endpoint`, `message.tsp.mediator.unresolvable` (the named
  mediator did not resolve) and `protocol.forwarding.loop_detected` — at the
  point the forward is accepted, rather than five retries later inside an HTTP
  client that has no idea whose message it is.
- `tsp_endpoint_is_self` is gone; the TSP path now shares
  `server::uri_points_at_self` with the DIDComm relay. That also fixes an IPv6
  mismatch in the TSP copy, which compared `Url::host_str()` (`"[::1]"`)
  against the bare form the authority set stores (`"::1"`) and so never matched.

## Unreleased (0.20.5) — pack the forwarding-abandonment problem report

**Bug fix (host side of mediator-common 0.15.37): the mediator now packs the
problem report it sends when it gives up on a forward.**

The report went out as bare DIDComm plaintext, which every SDK client on the
default (authcrypt-only) receive policy discards — the mediator logged
`FORWARD_PROBLEM_REPORT: stored problem report … for sender …` while the sender
logged `UnexpectedEnvelope("envelope wrapping Plaintext is not in the accepted
set …")`. Every forwarding abandonment was silent to the sender.

- New `tasks::system_packer::MediatorSystemPacker` implements
  `mediator-common`'s `SystemMessagePacker` over the same
  `didcomm_compat::pack_encrypted` every protocol reply already goes through.
  Only compiled with the `didcomm` feature; a TSP-only build has no DIDComm
  packer to offer and the processor logs the abandonment instead.
- The forwarding processor is now spawned *after* the DID resolver is built and
  the mediator's own document preloaded — authcrypt resolves both ends, and a
  `did:web`/`did:webvh` mediator may not reach its own document over the
  network from inside its deployment. No other ordering depends on it.

## Unreleased (0.20.4) — blind cross-mediator relay is no longer refused as a session mismatch

**Bug fix: with the default `RelayMode::Blind`, a mediator refused every
message relayed to it by a peer mediator.**

Observed in production: mediator M2 relays to M1, and M1 answers
`HTTP 400 / errorCode 52` —
`e.p.authorization.did.session_mismatch`, "Sender DID (…) doesn't match
session DID", on session `ANON-INBOUND`. No cross-mediator DIDComm delivery
completed.

`inbound.rs` enforces `security.force_session_did_match` in two places, and
only one of them was guarded. The **forward** branch (the message is addressed
to the mediator) already skipped the check for an unauthenticated session,
because an inter-mediator relay hop arrives anonymously and has no session DID
to match against. The **direct-delivery** branch (the message is addressed to
a local account) did not, so it compared the claimed sender against the
anonymous session's empty DID and could only ever fail.

Which branch a relayed message lands on is decided by the relay mode.
`RelayMode::Blind` — the default — relays the peer's inner envelope
byte-for-byte, and that envelope is addressed to the *recipient*, not to the
receiving mediator: a direct delivery. So the unguarded branch is exactly the
one every blind relay hop takes. `RelayMode::Rewrap` re-wraps the envelope as
a forward addressed to the next mediator and therefore took the already-guarded
branch, which is why rewrap deployments were unaffected.

The direct-delivery check now carries the same `session.authenticated` guard as
its sibling.

**The security tradeoff, stated plainly.** A directly-delivered envelope cannot
be decrypted by the mediator, so its sender is only a *claim* (the JWE `skid`),
and that claim is what feeds `from_hash` in the recipient's access-list
verdict. Exempting the anonymous relay session means a blind-relayed message's
sender is not verified against anything: a relaying peer can present any sender
DID. This is inherent to blind relay rather than introduced here — by
construction the receiving mediator cannot see which peer relayed — and the
alternative is the bug being fixed, refusing the hop outright.
`RelayMode::Rewrap` together with
`processors.forwarding.relay_trusted_mediators` exists precisely so a
deployment can authenticate and allowlist the relaying peer; deployments that
need the peer authenticated should run it.

Unchanged: an **authenticated** session's direct delivery is still bound to its
session DID, so a client cannot claim someone else's sender DID.

## Unreleased (0.20.3) — say which origin CORS refused, and whether CORS is on

**Observability fix: a CORS refusal was invisible from both ends.**

The browser gets an opaque `TypeError: Failed to fetch` with the reason
confined to its devtools console, and the mediator logs a clean `200` — the
`CorsLayer` does not reject anything, it simply omits the header. Operator and
user are left with no shared evidence. `curl` cannot reproduce the fault
either, because a terminal sends no `Origin` header, so the endpoint answers
perfectly and the refusal looks like it never happened.

- The `List` predicate now logs a refused origin at `warn`, naming it and
  pointing at `security.cors_allow_origin`. Logged **once per distinct
  origin** and capped at 32: the origin is attacker-controlled, so an
  unbounded record of it is a log-flooding and memory-growth primitive for
  anyone who can reach the port. A misconfigured deployment has one or two
  distinct origins to report, so the cap loses nothing real.
- The effective policy is now stated at boot. This is the half that matters
  most: `CorsOriginPolicy::None` (the default) installs **no predicate** — it
  never emits the header at all — so there is no per-request hook to log from,
  and a mediator refusing every browser client otherwise says so nowhere.
- The WebSocket path already logged its equivalent refusal and returns a
  readable `403`; only the REST path was silent, which is the one a browser
  client reaches first.

No behaviour change: the layer, the matchers and the policy are untouched, and
refusals are still refusals.

## Unreleased (0.20.2) — `rotate-admin` works against a VTA with no REST URL

**Bug fix: `mediator rotate-admin` could not authenticate to a VTA that
exposes no REST endpoint.**

The command pinned `TransportPreference::PreferRest`, which vta-sdk maps to
`TransportPlan::RestOnly` with **no DIDComm fallback**. Against a DIDComm-only
VTA there is no REST endpoint to resolve, so rotation failed before it began.
Newly reachable: until 0.20.1 an admin credential naming a VTA with no URL
could not be stored at all, so the command had no way to load one.

- The transport preference is now chosen from whether the credential carries a
  usable REST URL. With a URL, `PreferRest` is kept — it is known-good, and it
  avoids dialling DIDComm in the self-mediated topology, where the VTA's
  DIDComm mediator is the very process the operator is running the CLI against.
  Without one, `Auto` lets the SDK resolve the VTA's mediator from its DID
  document and try DIDComm with a REST fallback; a VTA advertising no
  `DIDCommMessaging` service degrades to `RestOnly`, exactly as before.
- The original rationale for pinning REST — that `get_acl` / `create_acl`
  needed the synchronous REST API — no longer holds. Both go through
  `rpc_tt` -> `dispatch_trust_task`, which is identical across the REST,
  DIDComm and TSP transports; the operation is a Trust Task on every transport
  and REST's bespoke per-operation routes were removed upstream.
- No behaviour change for any deployment whose admin credential has a REST URL.

**Known gap: TSP-only VTAs still cannot be rotated against.** `Auto` cannot
select TSP — `decide_transport` has no TSP arm, and `Transport::Tsp` is only
reachable through the explicit `VtaClient::connect_tsp`. Closing that belongs
in vta-sdk's preference matrix, not here.

## Unreleased (0.20.1) — `vta-sdk` 0.32.1

- Bumps `vta-sdk` 0.25 → 0.32.1. No source changes were required across the
  seven intervening minor releases, and `ContextProvisionBundle` is unchanged.
- Realigns this crate with the VTI workspace copy. Per the `vta` feature's
  comment, VTI's `[patch.crates-io] vta-sdk = { path = "vta-sdk" }` only
  deletes the registry node while our requirement admits their workspace
  version; holding at 0.25 while they shipped 0.32 is what re-opens the
  cross-repo dependency cycle.
- **`vta-sdk` is a public dependency of this crate's API** — `tasks::VtaRefresher`
  exposes a `VtaServiceConfig` field — so this is source-breaking for a consumer
  that builds with `--features vta` against `vta-sdk` 0.25. Shipped as a patch
  deliberately: `affinidi-messaging-test-mediator` pins `"0.20"`, and a minor
  would drop out of that range and duplicate this crate in the graph. Consumers
  that do not enable `vta` (including `test-mediator`, which builds
  `default-features = false`) never compile `vta-sdk` and are unaffected.

## Unreleased (0.20.0) — `trust-tasks-rs` 0.17

- Bumps `trust-tasks-rs` 0.12 → 0.17; sixteen response and component
  constructions moved to the generated builders behind one `build()` helper.
- **Behaviour change: three refusals that did not exist before.** 0.17 marks
  the generated *enums* `#[non_exhaustive]`, so a match on one needs a wildcard
  — and a wire enum can now carry a variant added to the registry after this
  binary was built. What the mediator does with one is a decision per site:
  - `account/list`'s role **filter** treats an unknown role as
    `AccountType::Unknown`, which selects nothing. Widening it to `Standard`
    would answer the request with a confident list of the wrong accounts.
  - `account/update` and `account/add` **refuse** an unknown role
    (`message.trust_task.rejected`, 400). They write it, and storing a
    privilege level this mediator cannot reason about — while telling the
    caller it set the role they asked for — is worse than a refusal.
  - `merge_wire_acl` **refuses** an unknown `accessListMode`. That member
    decides whether the access list allows or denies; guessing it inverts the
    ACL.
- No wire change for any known variant.

## Unreleased (0.19.0) — `trust-tasks-rs` 0.12, and `ping` gains freshness bounds

- Bumps `trust-tasks-rs` 0.11 → 0.12, and adapts the one `consume_inbound`
  call site: 0.12 requires a `ConsumeChecks` argument and `ConsumeOutcome`
  gains a `Duplicate` variant.
- **Behaviour change.** `ping` now refuses two document shapes it previously
  accepted, both as `malformedRequest`: an `issuedAt` beyond the 60s clock-skew
  tolerance, and an `expiresAt` at or before its own `issuedAt`. Before 0.12
  the only temporal check was `expiresAt` and `issuedAt` was parsed and never
  looked at, so a document stamped a year ahead was accepted — and accepted
  again for the whole of that year. A peer with a badly skewed clock will start
  seeing refusals.
- `ping` is declared `ConsumeChecks::not_consequential()`. Answering it grants
  no access, moves no value, discloses nothing beyond a nonce echo and the
  protocol list, and executing it twice leaves the mediator exactly as
  executing it once did — so SPEC §7.2 item 11 is knowingly disapplied and no
  duplicate-execution record is kept. On the hottest path in this module, a
  per-document record would be pure cost.
- The `Duplicate` arm is matched rather than `unreachable!()`, so that making
  this call consequential later is a compile-time prompt to decide what to
  return, not a panic on the first retried ping.
- `PayloadPolicy::AcceptUnvalidated` is unchanged, for the reason already
  recorded at that call site: moving it to `Validate` can start refusing
  documents a peer sends today, and belongs in its own change with its own
  rollout.
## Unreleased (0.18.22) — dependency refresh

- Bumps `base64` 0.22 → 0.23.
- Bumps `tokio-tungstenite` 0.29 → 0.30.
- Bumps `tower-http` 0.6 → 0.7.
- No source or API change; the bumps are declaration-only and the crate
  compiles unmodified against them. Bumped workspace-wide in the same
  change so no two versions of these crates are compiled side by side.

## [0.18.21] - 2026-08-22

### Fixed

- **A websocket close now states why**, so a refused duplicate connection stops
  reading as a network fault.

  `WebSocketCommands::Close` carried no reason, so the handler answered all three
  of its senders identically — the `duplicate-channel` problem report and the
  close reason `"replaced by a newer connection"`:

  - the incumbent, displaced by a newer connection — true;
  - a newcomer **refused** by the duel damper, whose own connection was never
    displaced and whose peer kept the slot — the inverse of true;
  - a session that reached registration with no authenticated DID — not a
    duplicate at all.

  A refused client was told it had been replaced, so the most it could honestly
  render was "the connection dropped". Two app instances presenting one DID
  therefore looked like a transport problem.

  `Close` now carries a `CloseReason`, and each maps to its own problem-report
  code and close reason:

  | Reason | Problem-report code | Close reason |
  |---|---|---|
  | `Replaced` | `w.websocket.duplicate-channel` | `replaced by a newer connection` |
  | `Refused` | `w.websocket.duplicate-channel-refused` | `this DID already has a live connection` |
  | `Unauthenticated` | `w.websocket.unauthenticated-session` | `session has no authenticated DID` |

  **`duplicate-channel` is preserved verbatim** for `Replaced`: it is the code
  existing clients already match on, and that socket is the one whose meaning
  never changed. Clients keying on it need no change.

  The eviction *policy* is deliberately untouched — newest-wins on an isolated
  duplicate still lets a client reclaim a half-open slot, the duel damper still
  holds the slot for a live incumbent, and displacement still triggers the
  stored-mail re-cover. The defect was never the policy; it was that the
  policy's outcome was unsayable.

## [0.18.20] - 2026-08-19

### Changed

- **Track `trust-tasks-rs` 0.11.0**, up from 0.9.0. Both releases in between are
  additive — new task families, no change to any type this crate uses — so
  nothing here had to move but the requirement:

  - **0.10.0** added the `vta/contexts/*` and `vta/webvh/*` families (the
    did:webvh lifecycle: DIDs, hosting servers, agent names) and the eight
    `vta/services/*` families that supersede a VTA's `/services/*` REST routes.
  - **0.11.0** corrected two of those `vta/services/*` schemas after writing the
    handlers found them unable to express the operation: rollback can
    legitimately publish no log entry, and disable takes a drain window the
    agent may refuse to honour.

  The reason to take it here is that a VTA cannot: `vta-sdk` must speak the same
  `trust-tasks-rs` these crates do, because `acl_setup` builds a `MediatorAcl`
  and hands it to `TrustTasks::account_update`. Two semver-incompatible copies
  make that a type error, so the VTA stays on 0.9 until this workspace moves.

  A second `trust-tasks-rs` 0.9 remains in the lockfile via this crate's
  `vta-sdk` dependency, and both coexist cleanly — no `trust-tasks-rs` type
  crosses that boundary. It clears when VTI ships a `vta-sdk` built on 0.11.



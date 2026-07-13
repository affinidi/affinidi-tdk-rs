# Mediator Memory Tuning

The mediator ships with defaults chosen to hold a single node **under ~256 MB
RSS** while idle-to-moderately loaded. Every structure that grows with load is
bounded by a **byte budget** you can raise, not by a message count you have to
reason about:

```toml
[limits]
ws_send_buffer = "33554432"   # 32 MiB — all WebSocket send queues, combined
pubsub_buffer  = "16777216"   # 16 MiB — the live-delivery pub/sub ring

[storage.fjall]               # embedded backend only; ignored for Redis
block_cache  = "16777216"     # 16 MiB — read cache
write_buffer = "33554432"     # 32 MiB — memtables, all keyspaces combined
max_journal  = "134217728"    # 128 MiB — the real global memory bound
```

This document is the operator reference for what the mediator holds in memory,
which knob to turn for more performance, and what it costs you.

---

## Where the memory goes

| Component | Default | Grows with | Knob |
|---|---|---|---|
| Base process (tokio, axum, TLS) | ~25 MB | nothing | — |
| Storage write buffer (Fjall) | up to 32 MiB | sustained writes | `storage.fjall.write_buffer` |
| Storage read cache (Fjall) | up to 16 MiB | reads (warms once) | `storage.fjall.block_cache` |
| WebSocket send queues | up to 32 MiB | slow live-delivery clients | `limits.ws_send_buffer` |
| Live-delivery pub/sub ring | up to 16 MiB | message throughput | `limits.pubsub_buffer` |
| DID document cache | ~2–8 MB | distinct DIDs seen | `did_resolver.cache_capacity` |

Measured on the shipped defaults with the Fjall backend: **~23 MB idle**, and
**~44 MB after writing 500 MB of message bodies** — resident memory tracks the
budget, not the data volume.

## Storage: the backends differ completely

**This is the most important thing to understand before tuning.** The two
backends put their memory in different *places*, so they need different knobs.

### Fjall (embedded)

Fjall runs **inside the mediator process**, so its caches are the mediator's RSS.
Everything under `[storage.fjall]` applies, and the mediator is the only thing
you need to size.

Fjall's own defaults are sized for a general-purpose embedded database, and are a
poor fit here: it allows **64 MiB of write buffer per keyspace**, and the
mediator opens 14 keyspaces. Left alone, that permits roughly **900 MiB** of
memtable. The shipped `[storage.fjall]` defaults exist to bring that down.

Two Fjall behaviours are worth knowing, because they are not obvious:

1. **There is no global write-buffer cap.** Fjall exposes a
   `max_write_buffer_size` setting, but in 3.1.x it is a dead field — declared,
   with a setter, never read. Each keyspace flushes only when *its own* memtable
   fills. So `write_buffer` is divided up front across keyspaces (weighted by how
   much each one writes), and `max_journal` acts as the real ceiling: once the
   journal outgrows it, Fjall force-flushes the keyspaces holding it open.
   **`max_journal` is the knob that actually bounds memory.**

2. **`write_buffer` only applies to a new data directory.** Fjall persists each
   keyspace's memtable size when the keyspace is first created, and offers no way
   to change it afterwards. Editing `write_buffer` against an existing `data_dir`
   will not resize keyspaces that already exist — you would need a fresh data
   directory. `block_cache` and `max_journal` **do** apply on every start,
   including to existing directories, so `max_journal` remains your lever there.

### Redis

Redis holds its data in the **Redis server**, a separate process. The mediator
keeps only a connection and a small local ring, so **`[storage.fjall]` is ignored
and there is nothing equivalent to tune on the mediator side.** Size Redis in
`redis.conf`:

```conf
maxmemory 512mb
maxmemory-policy noeviction   # do NOT evict: the mediator's queues are durable state
```

Use `noeviction`. An LRU policy would let Redis silently discard queued messages
and session state under pressure. You want writes to fail loudly instead.

`limits.ws_send_buffer` and `limits.pubsub_buffer` are mediator-side and apply to
**both** backends.

## Tuning for throughput

All four knobs trade memory for speed. Raise the one that matches your
bottleneck.

**Write-heavy** (high message ingest) — raise `storage.fjall.write_buffer` and
`max_journal` together. A bigger write buffer means fewer, larger flushes and
less write amplification. Remember `write_buffer` needs a fresh `data_dir` to
take effect; `max_journal` does not.

**Read-heavy** (frequent message pickup, large ACLs) — raise
`storage.fjall.block_cache`. This is a straight cache-hit-rate trade: more memory,
fewer disk reads. Costs exactly what you give it, once warm.

**Many live-streaming clients** — raise `limits.ws_send_buffer`. Watch
`ws_live_delivery_dropped_total` (below) to decide.

**Bursty throughput with lag warnings** — raise `limits.pubsub_buffer`.

**Many distinct DIDs** — raise `did_resolver.cache_capacity` (a count, not bytes;
each cached DID document is roughly 1–10 KB).

## What happens when a budget is exhausted

**No messages are lost.** Every message is durably stored in the recipient's
inbox *before* it is ever pushed live. Live delivery is an optimisation on top of
that, so when a buffer fills the mediator drops the *push*, not the message — the
client receives it on its next poll or when it reconnects.

Two signals tell you a budget is too small:

| Signal | Means | Fix |
|---|---|---|
| `ws_live_delivery_dropped_total` rising | A client's send queue or the global byte pool filled | Raise `limits.ws_send_buffer`, or find the slow client |
| `Streaming subscriber lagged` in logs | The pub/sub ring was overwritten before it could be read | Raise `limits.pubsub_buffer` |

Both are latency symptoms, not correctness ones. A steadily rising drop count
usually means one slow WebSocket consumer, not an undersized buffer — check
before you raise the budget.

## Message size

```toml
[limits]
message_size = "1048576"    # 1 MiB — enforced at ingress
http_size    = "10485760"   # 10 MiB — transport cap
ws_size      = "10485760"   # 10 MiB — transport cap
```

`message_size` is the ceiling on a single message the mediator will accept, copy,
queue, and fan out. **Every in-memory budget above is sized against it**, so it is
the multiplier on all of them: doubling `message_size` halves how many messages
fit in the same `pubsub_buffer`.

`http_size` and `ws_size` are *transport* caps — they bound one request or one
frame. Keep them at or above `message_size`.

> **Upgrade note.** `message_size` was documented but never enforced before
> mediator 0.16.46; the effective ceiling was `http_size`/`ws_size` (10 MiB).
> If your clients send messages larger than 1 MiB, they will now be rejected with
> `message.size.exceeded`. Raise `message_size` to restore the old behaviour.

## The allocator

The mediator binary uses **jemalloc** (the `jemalloc` feature, on by default).

This is not a micro-optimisation. With the system allocator (glibc malloc), the
storage backend's write-buffer churn — large, short-lived allocations — is not
returned to the OS. RSS ratchets up to its high-water mark and stays there, which
looks exactly like a leak on a memory graph even though the live heap is flat.
jemalloc's decay-based purging returns those pages, so **RSS tracks live memory**
and the numbers in this document are meaningful.

Build with `--no-default-features` to fall back to the system allocator (for
profiling, or on a target jemalloc does not support) — and expect resident memory
to read high and flat if you do.

## Cross-references

- [`conf/mediator.toml`](../conf/mediator.toml) — every knob, with `Env:` names
- [setup-guide.md](setup-guide.md) — operator walkthrough
- [secrets-backend.md](secrets-backend.md) — secret storage reference

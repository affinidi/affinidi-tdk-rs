//! Cross-Mediator Forwarding Example
//!
//! Demonstrates DIDComm message forwarding between two *different* mediators.
//! Alice is registered with mediator 1, Bob with mediator 2. Each message is
//! routed Alice -> mediator-1 -> mediator-2 -> Bob (and the reverse), so it
//! exercises mediator-to-mediator routing in both directions.
//!
//! The default mode renders the exchange as a side-by-side timeline — Alice on
//! the left, Bob on the right — showing every wrap (plaintext -> authcrypt ->
//! inner forward -> outer forward), the wire hop between the two mediators, and
//! the unwrap on the far side. Every step is stamped with an absolute wall-clock
//! time, the delta since the previous step, and the elapsed total.
//!
//! ## Random-DID mode (default — just point it at two mediators)
//!
//! Fresh `did:peer` identities are generated for Alice and Bob at runtime; you
//! only supply the two mediator DIDs:
//!
//!   cargo run --example cross_mediator_forwarding -- \
//!     --mediator1 did:web:mediator-a.example.com \
//!     --mediator2 did:web:mediator-b.example.com
//!
//! `--mediator1`/`--mediator2` are mediator *DIDs* (e.g. `did:web:...`), not raw
//! URLs — the DID is resolved to discover the mediator's HTTP/WebSocket endpoints.
//!
//! ## Environment mode (use pre-configured profiles)
//!
//! If `--mediator1`/`--mediator2` are omitted, the example falls back to loading
//! `Alice` and `Bob` profiles from TDK environment files (the original behaviour):
//!
//!   cargo run --example cross_mediator_forwarding -- \
//!     --alice-environment alice_env --bob-environment bob_env
//!
//! ## Ping-pong latency mode
//!
//! Add `--ping-pong [--rounds N]` (works in either mode) to follow the visual
//! exchange with a compact round-trip latency measurement loop.

use affinidi_messaging_didcomm::message::Message;
use affinidi_messaging_sdk::{
    ATM,
    errors::ATMError,
    profiles::ATMProfile,
    protocols::mediator::acls::{AccessListModeType, MediatorACLSet},
};
use affinidi_tdk::{
    TDK,
    common::{config::TDKConfig, profiles::TDKProfile},
    dids::{DID, KeyType, PeerKeyRole},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use clap::Parser;
use serde_json::{Value, json};
use std::{
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tracing::info;
use tracing_subscriber::filter;
use uuid::Uuid;

#[derive(Parser, Debug)]
#[command(
    version,
    about = "Cross-mediator forwarding example with a visual timeline and latency measurement"
)]
struct Args {
    /// Alice's mediator DID. When set together with --mediator2, the example
    /// generates random did:peer identities (random-DID mode).
    #[arg(long)]
    mediator1: Option<String>,

    /// Bob's mediator DID (must differ from --mediator1 for true cross-mediator routing).
    #[arg(long)]
    mediator2: Option<String>,

    /// Environment name for Alice (environment mode; used when --mediator1/2 are absent).
    #[arg(long, default_value = "alice")]
    alice_environment: String,

    /// Environment name for Bob (environment mode; must have a DIFFERENT mediator).
    #[arg(long, default_value = "bob")]
    bob_environment: String,

    /// Path to the environments file (defaults to environments.json).
    #[arg(short, long)]
    path_environments: Option<String>,

    /// The message text Alice sends to Bob.
    #[arg(
        long,
        default_value = "Hello Bob! This message is routed through two mediators."
    )]
    message: String,

    /// After the visual exchange, run a ping-pong loop measuring round-trip latency
    /// (max 1 message per second).
    #[arg(long)]
    ping_pong: bool,

    /// Number of ping-pong rounds (0 = infinite).
    #[arg(long, default_value = "10")]
    rounds: u32,
}

/// One participant in the exchange: a DID + the mediator it is registered with,
/// plus the ATM client and active profile used to send/receive on its behalf.
struct Party {
    label: &'static str,
    side: Side,
    did: String,
    mediator_did: String,
    atm: ATM,
    profile: Arc<ATMProfile>,
}

#[derive(Clone, Copy, PartialEq)]
enum Side {
    Left,
    Right,
}

#[tokio::main]
async fn main() -> Result<(), ATMError> {
    let args: Args = Args::parse();

    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(filter::EnvFilter::from_default_env())
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("Logging failed, exiting...");

    println!("=== Cross-Mediator Forwarding Example ===");

    // `_guards` keeps the TDK instance(s) alive for the duration of the run;
    // the Party values hold cloned ATM handles + Arc profiles.
    let env_mode = args.mediator1.is_none() || args.mediator2.is_none();
    let (_guards, alice, bob) =
        if let (Some(m1), Some(m2)) = (args.mediator1.clone(), args.mediator2.clone()) {
            println!("Mode: random did:peer identities");
            println!("  Alice mediator: {m1}");
            println!("  Bob   mediator: {m2}");
            setup_random(&m1, &m2).await?
        } else {
            println!("Mode: environment-loaded profiles");
            println!("  Alice environment: {}", args.alice_environment);
            println!("  Bob   environment: {}", args.bob_environment);
            setup_env(&args).await?
        };

    print_header(&alice, &bob);

    if alice.mediator_did == bob.mediator_did {
        println!("WARNING: Alice and Bob are using the same mediator.");
        println!("For true cross-mediator forwarding, point them at different mediators.\n");
    }

    // Ensure Alice and Bob are allowed to message each other.
    setup_acls(&alice, &bob).await?;

    let mut tl = Timeline::new();

    println!("\n========================= Alice -> Bob =========================\n");
    if !deliver(&mut tl, &alice, &bob, &args.message, true).await? {
        eprintln!("ERROR: Bob did not receive the message within the timeout.");
        return Ok(());
    }

    println!("\n========================= Bob -> Alice =========================\n");
    if !deliver(
        &mut tl,
        &bob,
        &alice,
        "Hi Alice! Got your message — routing works both ways.",
        true,
    )
    .await?
    {
        eprintln!("ERROR: Alice did not receive the reply within the timeout.");
        return Ok(());
    }

    if args.ping_pong {
        ping_pong(&mut tl, &alice, &bob, args.rounds).await?;
    }

    // Tidy up. In random-DID mode both parties share one ATM, so only shut it
    // down once; in environment mode each party owns its own ATM.
    alice.atm.graceful_shutdown().await;
    if env_mode {
        bob.atm.graceful_shutdown().await;
    }

    println!("\n=== Example complete ===");
    Ok(())
}

// ---------------------------------------------------------------------------
// Setup
// ---------------------------------------------------------------------------

/// Random-DID mode: one headless TDK + ATM, two freshly generated did:peers.
async fn setup_random(
    mediator1: &str,
    mediator2: &str,
) -> Result<(Vec<TDK>, Party, Party), ATMError> {
    let tdk = TDK::new(
        TDKConfig::builder()
            .with_load_environment(false)
            .with_use_atm(true)
            .build()?,
        None,
    )
    .await?;
    let atm = tdk.atm.clone().expect("ATM should be enabled");

    let alice = make_random_party(&tdk, &atm, "Alice", Side::Left, mediator1).await?;
    let bob = make_random_party(&tdk, &atm, "Bob", Side::Right, mediator2).await?;

    // The borrows of `tdk` end with the calls above, so it can now be moved
    // into the guard vec to outlive the parties.
    Ok((vec![tdk], alice, bob))
}

/// Generate a random did:peer whose DIDComm service endpoint is the mediator's
/// DID, register its secrets + profile, and connect (live stream) to the mediator.
async fn make_random_party(
    tdk: &TDK,
    atm: &ATM,
    label: &'static str,
    side: Side,
    mediator_did: &str,
) -> Result<Party, ATMError> {
    // The recipient's DID delegates to its mediator: the did:peer's `dm`
    // service endpoint is the mediator's DID (routing 2.0 shape).
    let (did, secrets) = DID::generate_did_peer(
        vec![
            (PeerKeyRole::Verification, KeyType::Ed25519),
            (PeerKeyRole::Encryption, KeyType::X25519),
        ],
        Some(mediator_did.to_string()),
    )?;

    let tdk_profile = TDKProfile::new(label, &did, Some(mediator_did), secrets);
    tdk.add_profile(&tdk_profile).await;

    let profile = atm
        .profile_add(
            &ATMProfile::from_tdk_profile(atm, &tdk_profile).await?,
            true,
        )
        .await?;

    Ok(Party {
        label,
        side,
        did,
        mediator_did: mediator_did.to_string(),
        atm: atm.clone(),
        profile,
    })
}

/// Environment mode: load `Alice` and `Bob` from their respective TDK environments.
async fn setup_env(args: &Args) -> Result<(Vec<TDK>, Party, Party), ATMError> {
    let alice_tdk = TDK::new(
        TDKConfig::builder()
            .with_environment_name(args.alice_environment.clone())
            .build()?,
        None,
    )
    .await?;
    let alice = load_env_party(&alice_tdk, "Alice", Side::Left, &args.alice_environment).await?;

    let bob_tdk = TDK::new(
        TDKConfig::builder()
            .with_environment_name(args.bob_environment.clone())
            .build()?,
        None,
    )
    .await?;
    let bob = load_env_party(&bob_tdk, "Bob", Side::Right, &args.bob_environment).await?;

    Ok((vec![alice_tdk, bob_tdk], alice, bob))
}

async fn load_env_party(
    tdk: &TDK,
    profile_name: &'static str,
    side: Side,
    env_name: &str,
) -> Result<Party, ATMError> {
    let atm = tdk.atm.clone().expect("ATM should be enabled");
    let shared = tdk.get_shared_state();
    let environment = shared.environment();

    let tdk_profile = environment.profiles().get(profile_name).ok_or_else(|| {
        ATMError::ConfigError(format!(
            "{profile_name} profile not found in environment: {env_name}"
        ))
    })?;

    tdk.add_profile(tdk_profile).await;
    let mediator_did = tdk_profile.mediator.clone().unwrap_or_default();
    let profile = atm
        .profile_add(
            &ATMProfile::from_tdk_profile(&atm, tdk_profile).await?,
            true,
        )
        .await?;

    Ok(Party {
        label: profile_name,
        side,
        did: profile.inner.did.clone(),
        mediator_did,
        atm,
        profile,
    })
}

/// Make sure both DIDs have an account on their mediator and are allowed to
/// message each other (resets any stale ACL state from previous runs).
async fn setup_acls(alice: &Party, bob: &Party) -> Result<(), ATMError> {
    let (alice_hash, alice_acls) = ensure_account(alice).await?;
    let (bob_hash, bob_acls) = ensure_account(bob).await?;

    apply_access(alice, alice_acls, &bob_hash).await?;
    apply_access(bob, bob_acls, &alice_hash).await?;

    info!("ACLs configured for cross-mediator communication");
    Ok(())
}

/// Fetch the party's mediator account (creating it if the mediator allows
/// self-registration). Returns (did_hash, acls).
async fn ensure_account(party: &Party) -> Result<(String, u64), ATMError> {
    match party
        .atm
        .mediator()
        .account_get(&party.profile, None)
        .await?
    {
        Some(account) => Ok((account.did_hash, account.acls)),
        None => {
            let hash = sha256::digest(party.profile.inner.did.as_str());
            let account = party
                .atm
                .mediator()
                .account_add(&party.profile, &hash, None)
                .await?;
            Ok((account.did_hash, account.acls))
        }
    }
}

/// Allow `peer_hash` to reach `party` regardless of the mediator's ACL mode.
async fn apply_access(party: &Party, acls: u64, peer_hash: &str) -> Result<(), ATMError> {
    let mode = MediatorACLSet::from_u64(acls).get_access_list_mode().0;
    if let AccessListModeType::ExplicitAllow = mode {
        party
            .atm
            .mediator()
            .access_list_add(&party.profile, None, &[peer_hash])
            .await?;
    } else {
        party
            .atm
            .mediator()
            .access_list_remove(&party.profile, None, &[peer_hash])
            .await?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Delivery (the core: wrap -> forward -> forward -> send -> unwrap)
// ---------------------------------------------------------------------------

/// Send `text` from `sender` to `recipient`, routing through both mediators when
/// they differ, then wait for the recipient to receive and unwrap it.
///
/// When sender and recipient use different mediators, two forward layers are
/// required: the OUTER forward (encrypted for the sender's mediator,
/// next = recipient's mediator) wraps the INNER forward (encrypted for the
/// recipient's mediator, next = recipient). Each mediator only ever decrypts
/// its own layer.
///
/// When `verbose` is true, every step is rendered to the side-by-side timeline.
/// Returns `Ok(true)` if delivered, `Ok(false)` on receive timeout.
async fn deliver(
    tl: &mut Timeline,
    sender: &Party,
    recipient: &Party,
    text: &str,
    verbose: bool,
) -> Result<bool, ATMError> {
    let now = unix_secs();

    // 1. Compose the plaintext message.
    let msg = Message::build(
        Uuid::new_v4().to_string(),
        "https://didcomm.org/basicmessage/2.0/message".to_string(),
        json!({ "content": text }),
    )
    .to(recipient.profile.inner.did.clone())
    .from(sender.profile.inner.did.clone())
    .created_time(now)
    .expires_time(now + 60)
    .finalize();
    let msg_id = msg.id.clone();

    if verbose {
        tl.event(
            sender.side,
            &format!("{}: compose plaintext", sender.label),
            &[
                "type  basicmessage/2.0/message".to_string(),
                format!("to    {}", short(&recipient.profile.inner.did)),
                format!("body  \"{text}\""),
            ],
        );
    }

    // 2. Authcrypt (encrypt + sign) for the recipient.
    let packed = sender
        .atm
        .pack_encrypted(
            &msg,
            &recipient.profile.inner.did,
            Some(&sender.profile.inner.did),
            Some(&sender.profile.inner.did),
        )
        .await?;

    if verbose {
        let w = summarize(&packed.0);
        tl.event(
            sender.side,
            &format!("{}: authcrypt for {}", sender.label, recipient.label),
            &[
                format!("alg   {}", w.alg),
                format!("enc   {}", w.enc),
                format!("recip {}", w.recipients.join(", ")),
                format!("size  {} bytes", w.size),
            ],
        );
    }

    // 3. INNER forward: encrypted for the recipient's mediator, next = recipient.
    let (_inner_id, inner_fwd) = sender
        .atm
        .routing()
        .forward_message(
            &sender.profile,
            false,
            &packed.0,
            &recipient.mediator_did,
            &recipient.profile.inner.did,
            None,
            None,
        )
        .await?;

    if verbose {
        let w = summarize(&inner_fwd);
        tl.event(
            sender.side,
            &format!("{}: wrap INNER forward", sender.label),
            &[
                format!(
                    "to    {}  (recipient mediator)",
                    short(&recipient.mediator_did)
                ),
                format!("next  {}  (recipient)", short(&recipient.profile.inner.did)),
                format!("size  {} bytes", w.size),
            ],
        );
    }

    // 4. OUTER forward (cross-mediator only): encrypted for the sender's
    //    mediator, next = recipient's mediator so it relays the inner forward.
    let forward_msg = if sender.mediator_did != recipient.mediator_did {
        let (_outer_id, outer_fwd) = sender
            .atm
            .routing()
            .forward_message(
                &sender.profile,
                false,
                &inner_fwd,
                &sender.mediator_did,
                &recipient.mediator_did,
                None,
                None,
            )
            .await?;

        if verbose {
            let w = summarize(&outer_fwd);
            tl.event(
                sender.side,
                &format!("{}: wrap OUTER forward", sender.label),
                &[
                    format!("to    {}  (own mediator)", short(&sender.mediator_did)),
                    format!(
                        "next  {}  (recipient mediator)",
                        short(&recipient.mediator_did)
                    ),
                    format!("size  {} bytes", w.size),
                ],
            );
        }
        outer_fwd
    } else {
        inner_fwd
    };

    // 5. Send to the sender's own mediator.
    sender
        .atm
        .send_message(&sender.profile, &forward_msg, &msg_id, false, false)
        .await?;

    if verbose {
        tl.event(
            sender.side,
            &format!("{}: send to own mediator", sender.label),
            &[short(&sender.mediator_did)],
        );
        tl.wire(sender, recipient);
    }

    // 6. Recipient receives and unwraps via the live stream.
    match recipient
        .atm
        .message_pickup()
        .live_stream_get(&recipient.profile, &msg_id, Duration::from_secs(15), true)
        .await?
    {
        Some((received, meta)) => {
            if verbose {
                let body = received
                    .body
                    .get("content")
                    .and_then(|c| c.as_str())
                    .unwrap_or("<no content>");
                tl.event(
                    recipient.side,
                    &format!("{}: unwrap + decrypt", recipient.label),
                    &[
                        format!(
                            "from  {}",
                            meta.encrypted_from_kid
                                .as_deref()
                                .map(short)
                                .unwrap_or_else(|| "<anonymous>".to_string())
                        ),
                        format!(
                            "encrypted={}  authenticated={}",
                            meta.encrypted, meta.authenticated
                        ),
                        format!("re_wrapped_in_forward={}", meta.re_wrapped_in_forward),
                        format!("body  \"{body}\""),
                    ],
                );
            }
            Ok(true)
        }
        None => {
            if verbose {
                tl.event(
                    recipient.side,
                    &format!("{}: TIMEOUT (no message)", recipient.label),
                    &[],
                );
            }
            Ok(false)
        }
    }
}

// ---------------------------------------------------------------------------
// Ping-pong latency mode
// ---------------------------------------------------------------------------

async fn ping_pong(
    tl: &mut Timeline,
    alice: &Party,
    bob: &Party,
    rounds: u32,
) -> Result<(), ATMError> {
    println!("\n========================= Ping-Pong Latency =========================");
    println!(
        "Rounds: {} (max 1 msg/sec)\n",
        if rounds == 0 {
            "infinite".to_string()
        } else {
            rounds.to_string()
        }
    );

    let mut round = 0u32;
    let mut total_rtt_ms = 0u128;
    let mut completed = 0u32;

    loop {
        round += 1;
        if rounds > 0 && round > rounds {
            break;
        }

        let rtt_start = Instant::now();

        if !deliver(tl, alice, bob, &format!("Ping #{round}"), false).await? {
            println!("  Round {round}: TIMEOUT waiting for ping");
            continue;
        }
        if !deliver(tl, bob, alice, &format!("Pong #{round}"), false).await? {
            println!("  Round {round}: TIMEOUT waiting for pong");
            continue;
        }

        let rtt = rtt_start.elapsed();
        total_rtt_ms += rtt.as_millis();
        completed += 1;
        println!(
            "  Round {round}: RTT = {}ms (avg: {}ms)",
            rtt.as_millis(),
            total_rtt_ms / completed as u128
        );

        // Rate limit: max 1 round per second.
        let elapsed = rtt_start.elapsed();
        if elapsed < Duration::from_secs(1) {
            tokio::time::sleep(Duration::from_secs(1) - elapsed).await;
        }
    }

    if completed > 0 {
        println!(
            "\nPing-Pong complete: {} rounds, avg RTT: {}ms",
            completed,
            total_rtt_ms / completed as u128
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Visual timeline rendering
// ---------------------------------------------------------------------------

/// Column width for each side of the side-by-side layout.
const COL_W: usize = 56;

/// Tracks wall-clock + monotonic time and renders timestamped events into the
/// Alice (left) / Bob (right) columns.
struct Timeline {
    start_inst: Instant,
    start_sys: SystemTime,
    last: Instant,
}

impl Timeline {
    fn new() -> Self {
        let now = Instant::now();
        Self {
            start_inst: now,
            start_sys: SystemTime::now(),
            last: now,
        }
    }

    /// Returns (absolute HH:MM:SS.mmm UTC, delta-ms-since-last, total-ms-since-start).
    fn stamp(&mut self) -> (String, u128, u128) {
        let now = Instant::now();
        let delta = now.duration_since(self.last).as_millis();
        let total = now.duration_since(self.start_inst).as_millis();
        self.last = now;

        let wall = self.start_sys + now.duration_since(self.start_inst);
        let since_epoch = wall.duration_since(UNIX_EPOCH).unwrap_or_default();
        let ms = since_epoch.as_millis() % 1000;
        let secs = since_epoch.as_secs();
        let abs = format!(
            "{:02}:{:02}:{:02}.{:03}",
            (secs / 3600) % 24,
            (secs / 60) % 60,
            secs % 60,
            ms
        );
        (abs, delta, total)
    }

    fn timestamp_line(&mut self) {
        let (abs, delta, total) = self.stamp();
        println!("  {abs} UTC   Δ +{delta:>5} ms   T +{total:>6} ms");
    }

    /// Render an event (a title plus detail lines) into the appropriate column.
    fn event(&mut self, side: Side, title: &str, lines: &[String]) {
        self.timestamp_line();
        let mut rows = vec![format!("> {title}")];
        rows.extend(lines.iter().map(|l| format!("    {l}")));
        for row in rows {
            match side {
                Side::Left => println!("{:<width$} |", clip(&row, COL_W), width = COL_W),
                Side::Right => println!("{:<width$} | {}", "", clip(&row, COL_W), width = COL_W),
            }
        }
        println!();
    }

    /// Render the wire hop between the two mediators, oriented by sender side.
    fn wire(&mut self, sender: &Party, recipient: &Party) {
        self.timestamp_line();
        let line = if sender.side == Side::Left {
            format!(
                "[{}] --> [{}] --> {}",
                short(&sender.mediator_did),
                short(&recipient.mediator_did),
                recipient.label
            )
        } else {
            format!(
                "{} <-- [{}] <-- [{}]",
                recipient.label,
                short(&recipient.mediator_did),
                short(&sender.mediator_did)
            )
        };
        println!(
            "{:^width$}",
            "~~ forward relayed over the wire ~~",
            width = COL_W * 2 + 3
        );
        println!("{:^width$}", line, width = COL_W * 2 + 3);
        println!();
    }
}

fn print_header(alice: &Party, bob: &Party) {
    println!();
    println!("{:<width$} | BOB  (right)", "ALICE  (left)", width = COL_W);
    println!(
        "{:<width$} | {}",
        clip(&format!("did:      {}", short(&alice.did)), COL_W),
        clip(&format!("did:      {}", short(&bob.did)), COL_W),
        width = COL_W
    );
    println!(
        "{:<width$} | {}",
        clip(&format!("mediator: {}", short(&alice.mediator_did)), COL_W),
        clip(&format!("mediator: {}", short(&bob.mediator_did)), COL_W),
        width = COL_W
    );
    println!("{}-+-{}", "-".repeat(COL_W), "-".repeat(COL_W));
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

/// A parsed summary of a packed DIDComm JWE (general-JSON serialization), used
/// to make each wrapping step legible.
struct WrapInfo {
    size: usize,
    alg: String,
    enc: String,
    recipients: Vec<String>,
}

fn summarize(packed: &str) -> WrapInfo {
    let size = packed.len();
    let mut info = WrapInfo {
        size,
        alg: "?".to_string(),
        enc: "?".to_string(),
        recipients: Vec::new(),
    };

    let Ok(jwe) = serde_json::from_str::<Value>(packed) else {
        return info; // compact form or non-JSON: size is still useful.
    };

    if let Some(protected_b64) = jwe.get("protected").and_then(|p| p.as_str())
        && let Ok(bytes) = URL_SAFE_NO_PAD.decode(protected_b64)
        && let Ok(header) = serde_json::from_slice::<Value>(&bytes)
    {
        if let Some(alg) = header.get("alg").and_then(|v| v.as_str()) {
            info.alg = alg.to_string();
        }
        if let Some(enc) = header.get("enc").and_then(|v| v.as_str()) {
            info.enc = enc.to_string();
        }
    }

    if let Some(recipients) = jwe.get("recipients").and_then(|r| r.as_array()) {
        info.recipients = recipients
            .iter()
            .filter_map(|r| {
                r.get("header")
                    .and_then(|h| h.get("kid"))
                    .and_then(|k| k.as_str())
                    .map(short)
            })
            .collect();
    }

    info
}

/// Abbreviate a long DID / key id for display.
fn short(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    if chars.len() <= 24 {
        return s.to_string();
    }
    let head: String = chars[..16].iter().collect();
    let tail: String = chars[chars.len() - 6..].iter().collect();
    format!("{head}...{tail}")
}

/// Truncate a string to `width` chars (so column padding stays aligned).
fn clip(s: &str, width: usize) -> String {
    let chars: Vec<char> = s.chars().collect();
    if chars.len() <= width {
        return s.to_string();
    }
    let mut out: String = chars[..width - 1].iter().collect();
    out.push('~');
    out
}

fn unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

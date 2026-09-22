//! The console rendered against a live in-process mediator, into a test
//! terminal: the screens fill in from real data.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use affinidi_messaging_didcomm::message::Message;
use affinidi_messaging_mediator_admin::{Identity, MediatorConsole};
use affinidi_messaging_mediator_common::types::accounts::AccountType;
use affinidi_messaging_mediator_tui::{App, ColorDepth, Control};
use affinidi_messaging_test_mediator::{TestEnvironment, TestUser};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::{Terminal, backend::TestBackend};
use serde_json::json;

async fn send(env: &TestEnvironment, from: &TestUser, to: &TestUser) {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let msg = Message::build(
        uuid::Uuid::new_v4().to_string(),
        "https://didcomm.org/basicmessage/2.0/message".to_string(),
        json!({ "content": "render test" }),
    )
    .to(to.did.clone())
    .from(from.did.clone())
    .created_time(now)
    .expires_time(now + 600)
    .finalize();
    let id = msg.id.clone();
    let (packed, _) = env
        .atm
        .pack_encrypted(&msg, &to.did, Some(&from.did), Some(&from.did))
        .await
        .unwrap();
    env.atm
        .send_message(&from.profile, &packed, &id, false, false)
        .await
        .unwrap();
}

/// Apply background results for `window`.
async fn settle(app: &mut App, window: Duration) {
    let until = tokio::time::Instant::now() + window;
    while let Ok(Some(update)) = tokio::time::timeout_at(until, app.next_update()).await {
        app.apply(update);
    }
}

fn screen(terminal: &Terminal<TestBackend>) -> String {
    let buf = terminal.backend().buffer();
    (0..buf.area.height)
        .map(|y| {
            (0..buf.area.width)
                .map(|x| buf[(x, y)].symbol().to_string())
                .collect::<String>()
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn key(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}

#[tokio::test(flavor = "multi_thread")]
async fn an_admin_console_renders_real_data() {
    let env = TestEnvironment::spawn_with_direct_delivery().await.unwrap();
    let alice = env.add_user("alice").await.unwrap();
    let bob = env.add_user("bob").await.unwrap();
    let op = env.add_user("operator").await.unwrap();
    env.mediator
        .store()
        .account_set_role(&op.did_hash(), &AccountType::Admin)
        .await
        .unwrap();
    for _ in 0..3 {
        send(&env, &alice, &bob).await;
    }

    let console = MediatorConsole::connect(Identity {
        alias: "operator".into(),
        did: op.did.clone(),
        secrets: op.secrets.clone(),
        mediator_did: Some(env.mediator.did().to_string()),
    })
    .await
    .unwrap();
    let mut app = App::new(console).with_color_depth(ColorDepth::TrueColor);
    let mut terminal = Terminal::new(TestBackend::new(140, 40)).unwrap();

    settle(&mut app, Duration::from_secs(2)).await;
    terminal.draw(|f| app.render(f, f.area())).unwrap();
    let dashboard = screen(&terminal);
    println!("{dashboard}");
    assert!(dashboard.contains("ADMIN"), "mode badge");
    assert!(
        dashboard.contains("Mediator") && dashboard.contains("version"),
        "stats panel"
    );
    assert!(dashboard.contains("Queue pressure"), "gradient panel");

    // Open the monitor pane and the Account tab for the busiest queue.
    assert_eq!(app.handle_key(key(KeyCode::Char('m'))), Control::Continue);
    app.handle_key(key(KeyCode::Char('2')));
    settle(&mut app, Duration::from_secs(2)).await;
    terminal.draw(|f| app.render(f, f.area())).unwrap();
    let queues = screen(&terminal);
    println!("{queues}");
    assert!(queues.contains("Traffic"), "monitor pane beside the queues");

    // Alice's account: the three messages she sent bob wait in her send
    // queue, and bob is the recipient who has not collected them.
    app.open_account(Some(alice.did_hash()));
    settle(&mut app, Duration::from_secs(2)).await;
    terminal.draw(|f| app.render(f, f.area())).unwrap();
    let account = screen(&terminal);
    println!("{account}");
    assert!(
        account.contains("who hasn't collected"),
        "send queue by recipient"
    );
    let bob_short = format!("{}…", &bob.did_hash()[..8]);
    let peer_row = account
        .lines()
        .find(|l| l.contains(&bob_short) && l.contains(" 3 "))
        .unwrap_or_else(|| panic!("bob waiting on 3 messages:\n{account}"));
    assert!(!peer_row.is_empty());
    assert!(account.contains("Receive queue"), "message table");
}

/// A long nickname gets the width it needs, even with the monitor pane open
/// beside it, instead of being cut at a fixed width.
#[tokio::test(flavor = "multi_thread")]
async fn a_named_account_gets_room_beside_the_monitor() {
    use affinidi_messaging_mediator_admin::AddressBook;

    let env = TestEnvironment::spawn_with_direct_delivery().await.unwrap();
    let alice = env.add_user("alice").await.unwrap();
    let bob = env.add_user("bob").await.unwrap();
    let op = env.add_user("operator").await.unwrap();
    env.mediator
        .store()
        .account_set_role(&op.did_hash(), &AccountType::Admin)
        .await
        .unwrap();
    send(&env, &alice, &bob).await;

    let console = MediatorConsole::connect(Identity {
        alias: "operator".into(),
        did: op.did.clone(),
        secrets: op.secrets.clone(),
        mediator_did: Some(env.mediator.did().to_string()),
    })
    .await
    .unwrap();
    let name = "Verifiable Data Rooms · vdr-host";
    let mut book = AddressBook::new();
    book.insert(&bob.did, name);
    let mut app = App::new(console)
        .with_color_depth(ColorDepth::TrueColor)
        .with_address_book(book, None);
    let mut terminal = Terminal::new(TestBackend::new(200, 30)).unwrap();

    // Alice's account, live: bob is the recipient who hasn't collected.
    app.handle_key(key(KeyCode::Char('m')));
    app.open_account(Some(alice.did_hash()));
    app.handle_key(key(KeyCode::Char('x'))); // her send queue
    settle(&mut app, Duration::from_secs(3)).await;
    terminal.draw(|f| app.render(f, f.area())).unwrap();
    let account = screen(&terminal);
    println!("{account}");
    assert!(
        account.contains(name),
        "the whole nickname fits beside the monitor:\n{account}"
    );

    // Every account on the mediator, the named one by its name.
    app.handle_key(key(KeyCode::Char('5')));
    settle(&mut app, Duration::from_secs(2)).await;
    terminal.draw(|f| app.render(f, f.area())).unwrap();
    let accounts = screen(&terminal);
    println!("{accounts}");
    assert!(
        accounts.contains("Accounts —"),
        "accounts screen:\n{accounts}"
    );
    assert!(accounts.contains(name), "named account listed:\n{accounts}");
    assert!(
        accounts.contains("admin"),
        "the operator's role shown:\n{accounts}"
    );

    // The monitor's totals: a message sent while it watches is counted, and
    // the account it went to is listed by its name.
    send(&env, &alice, &bob).await;
    settle(&mut app, Duration::from_secs(3)).await;
    app.handle_key(key(KeyCode::Char('t')));
    terminal.draw(|f| app.render(f, f.area())).unwrap();
    let totals = screen(&terminal);
    println!("{totals}");
    assert!(
        totals.contains("1 msgs"),
        "the arrival is counted:\n{totals}"
    );
    assert!(
        totals.contains("delivered") && totals.contains("to it"),
        "the totals table:\n{totals}"
    );
    assert!(totals.contains(name), "the recipient by name:\n{totals}");

    // The configuration, limits first; an admin (not root) may read it only.
    app.handle_key(key(KeyCode::Char('6')));
    settle(&mut app, Duration::from_secs(2)).await;
    terminal.draw(|f| app.render(f, f.area())).unwrap();
    let config = screen(&terminal);
    println!("{config}");
    assert!(
        config.contains("Configuration —"),
        "config screen:\n{config}"
    );
    assert!(config.contains("limits."), "limits listed:\n{config}");
    assert!(
        config.contains("needs a rootAdmin"),
        "an admin is told who may change it:\n{config}"
    );

    // Alice's settings, and an edit: the first ACL flag toggled and saved.
    app.open_account(Some(alice.did_hash()));
    settle(&mut app, Duration::from_secs(2)).await;
    terminal.draw(|f| app.render(f, f.area())).unwrap();
    let before = screen(&terminal);
    assert!(before.contains("Settings"), "settings panel:\n{before}");
    assert!(before.contains("role standard"), "the role:\n{before}");
    let anon_before = before.contains("✓anonReceive");

    app.handle_key(key(KeyCode::Char('e')));
    app.handle_key(key(KeyCode::Down)); // past the role row, to anonReceive
    app.handle_key(key(KeyCode::Char(' ')));
    app.handle_key(key(KeyCode::Char('s')));
    settle(&mut app, Duration::from_secs(3)).await;
    terminal.draw(|f| app.render(f, f.area())).unwrap();
    let after = screen(&terminal);
    println!("{after}");
    assert!(after.contains("account updated"), "saved:\n{after}");
    assert_eq!(
        after.contains("✓anonReceive"),
        !anon_before,
        "the flag changed:\n{after}"
    );
}

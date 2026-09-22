//! `config/reload` re-reads the limits from the configuration file the
//! mediator was started from. Its own test binary: the recorded path is
//! process-wide.

use affinidi_messaging_mediator_common::types::accounts::AccountType;
use affinidi_messaging_test_mediator::{TestEnvironment, TestMediator};
use serde_json::json;

#[tokio::test]
async fn a_reload_picks_up_a_changed_limit_and_keeps_overrides() {
    let env = TestEnvironment::new(TestMediator::builder().spawn().await.expect("mediator"))
        .await
        .expect("environment");
    let root = env.add_user("root").await.expect("root");
    env.mediator
        .store()
        .account_set_role(&root.did_hash(), &AccountType::RootAdmin)
        .await
        .expect("promote");
    env.atm
        .profile_add(&root.profile, true)
        .await
        .expect("root live");
    let tt = env.atm.trust_tasks();

    // Embedded (no configuration file yet): nothing to reload.
    let refused = tt.config_reload(&root.profile).await;
    assert!(refused.is_err(), "{refused:?}");

    // The shipped template, with `listed_messages` lowered to 70.
    let template = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../affinidi-messaging-mediator/conf/mediator.toml"
    ))
    .expect("template");
    assert!(template.contains("listed_messages = \"100\""));
    let path = std::env::temp_dir().join(format!("reload-{}.toml", std::process::id()));
    std::fs::write(
        &path,
        template.replace("listed_messages = \"100\"", "listed_messages = \"70\""),
    )
    .expect("write config");
    affinidi_messaging_mediator::common::config::overrides::record_config_path(
        path.to_str().unwrap(),
    );

    // An override stays on top of the reloaded value.
    let mut overrides = serde_json::Map::new();
    overrides.insert("limits.deleted_messages".into(), json!(5));
    tt.config_patch(&root.profile, overrides)
        .await
        .expect("patch");

    let answer =
        serde_json::to_value(tt.config_reload(&root.profile).await.expect("reload")).unwrap();
    let reloaded: Vec<String> = serde_json::from_value(answer["keysReloaded"].clone()).unwrap();
    assert!(
        reloaded.contains(&"limits.listed_messages".to_string()),
        "{answer}"
    );

    let shown = serde_json::to_value(
        tt.config_show(
            &root.profile,
            Some(vec![
                "limits.listed_messages".into(),
                "limits.deleted_messages".into(),
            ]),
        )
        .await
        .expect("show"),
    )
    .unwrap();
    let value = |key: &str| {
        shown["fields"]
            .as_array()
            .unwrap()
            .iter()
            .find(|f| f["key"] == key)
            .map(|f| f["value"].clone())
            .unwrap()
    };
    assert_eq!(value("limits.listed_messages"), 70);
    assert_eq!(value("limits.deleted_messages"), 5, "the override survives");
    let _ = std::fs::remove_file(path);
}

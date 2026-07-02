//! End-to-end coverage of **proactive** TSP capability discovery (issue #576):
//! a sender learns a peer speaks TSP from a DIDComm Discover Features 2.0
//! disclosure — *before* any relationship or observed inbound TSP — so the
//! next `atm.send_to` upgrades DIDComm → TSP.
#![cfg(feature = "tsp")]

use affinidi_messaging_didcomm::Message;
use affinidi_messaging_sdk::protocols::discover_features::{
    DiscoverFeaturesDisclosure, DiscoverFeaturesQuery,
};
use affinidi_messaging_sdk::{SendProtocol, TSP_DISCOVER_FEATURE_URI, TspPolicy, TspSupport};
use affinidi_messaging_test_mediator::TestEnvironment;
use serde_json::json;
use uuid::Uuid;

fn basic_message(from: &str, to: &str, text: &str) -> Message {
    Message::build(
        Uuid::new_v4().to_string(),
        "https://didcomm.org/basicmessage/2.0/message".to_string(),
        json!({ "content": text }),
    )
    .to(to.to_string())
    .from(from.to_string())
    .finalize()
}

/// The disclosure a responder would return for `query`, calculated from its own
/// live discoverable state — the real production path
/// (`get_discoverable_state` → `calculate_disclosure`).
async fn disclosure_for_query(
    env: &TestEnvironment,
    query: &Message,
) -> DiscoverFeaturesDisclosure {
    let query_body: DiscoverFeaturesQuery =
        serde_json::from_value(query.body.clone()).expect("parse query body");
    let state = env.atm.discover_features().get_discoverable_state();
    let features = state.read().await;
    features.calculate_disclosure(&query_body)
}

/// The headline #576 behaviour: alice discovers bob's TSP capability via a
/// Discover Features query/disclosure round-trip, with no prior relationship or
/// inbound TSP, and her next `send_to` upgrades to TSP.
#[tokio::test]
async fn discover_features_disclosure_upgrades_send_to() {
    // Preferred policy auto-advertises the TSP URI in the discoverable state, so
    // bob's disclosure will list it.
    let env = TestEnvironment::spawn_with_tsp_policy(TspPolicy::Preferred)
        .await
        .expect("spawn env with Preferred policy");
    let alice = env.add_user("alice").await.expect("add alice");
    let bob = env.add_user("bob").await.expect("add bob");

    // No signal yet → DIDComm.
    assert_eq!(
        env.atm
            .tsp()
            .peer_capability(&alice.profile, &bob.did)
            .await
            .unwrap(),
        None
    );
    let m1 = basic_message(&alice.did, &bob.did, "first");
    let via1 = env
        .atm
        .send_to(&alice.profile, &m1, &bob.did, Some(&alice.did), None)
        .await
        .expect("send_to bob (1)");
    assert_eq!(via1, SendProtocol::DidComm, "no TSP signal yet → DIDComm");

    // Alice asks bob what he supports; bob answers from his discoverable state.
    let query = env
        .atm
        .tsp()
        .capability_query(&alice.did, &bob.did)
        .expect("build capability query");
    let disclosure = disclosure_for_query(&env, &query).await;
    assert!(
        disclosure
            .disclosures
            .iter()
            .any(|d| d.id == TSP_DISCOVER_FEATURE_URI),
        "bob's disclosure advertises the TSP capability URI"
    );

    // Alice consumes the disclosure → bob cached Supported (source DiscoverFeatures).
    let learned = env
        .atm
        .tsp()
        .learn_from_disclosure(&alice.profile, &bob.did, &disclosure)
        .await
        .expect("learn from disclosure");
    assert!(learned, "disclosure advertised TSP");
    assert!(
        matches!(
            env.atm
                .tsp()
                .peer_capability(&alice.profile, &bob.did)
                .await
                .unwrap()
                .map(|c| c.tsp),
            Some(TspSupport::Supported)
        ),
        "discovery marks bob Supported"
    );

    // send_to now upgrades to TSP — before any relationship or inbound TSP.
    let m2 = basic_message(&alice.did, &bob.did, "second");
    let via2 = env
        .atm
        .send_to(&alice.profile, &m2, &bob.did, Some(&alice.did), None)
        .await
        .expect("send_to bob (2)");
    assert_eq!(
        via2,
        SendProtocol::Tsp,
        "discovered capability upgrades to TSP"
    );
}

/// A disclosure that does not advertise the TSP URI leaves the peer unknown and
/// `send_to` stays on DIDComm (no false positive, no `Unsupported` write).
#[tokio::test]
async fn disclosure_without_tsp_uri_stays_didcomm() {
    let env = TestEnvironment::spawn_with_tsp_policy(TspPolicy::Preferred)
        .await
        .expect("spawn env with Preferred policy");
    let alice = env.add_user("alice").await.expect("add alice");
    let bob = env.add_user("bob").await.expect("add bob");

    // A disclosure listing only an unrelated protocol.
    let disclosure = DiscoverFeaturesDisclosure {
        disclosures: vec![
            affinidi_messaging_sdk::protocols::discover_features::Disclosure {
                feature_type:
                    affinidi_messaging_sdk::protocols::discover_features::FeatureType::Protocol,
                id: "https://didcomm.org/trust-ping/2.0".to_string(),
                roles: vec![],
            },
        ],
    };
    let learned = env
        .atm
        .tsp()
        .learn_from_disclosure(&alice.profile, &bob.did, &disclosure)
        .await
        .expect("learn from disclosure");
    assert!(!learned, "no TSP URI → nothing learned");
    assert_eq!(
        env.atm
            .tsp()
            .peer_capability(&alice.profile, &bob.did)
            .await
            .unwrap(),
        None,
        "peer stays unknown"
    );

    let m = basic_message(&alice.did, &bob.did, "hello");
    let via = env
        .atm
        .send_to(&alice.profile, &m, &bob.did, Some(&alice.did), None)
        .await
        .expect("send_to bob");
    assert_eq!(via, SendProtocol::DidComm);
}

/// Under the default `Off` policy the TSP URI is not auto-advertised and
/// consuming a disclosure that lists it is inert — capability tracking stays off.
#[tokio::test]
async fn discovery_is_inert_under_off_policy() {
    let env = TestEnvironment::spawn()
        .await
        .expect("spawn default (Off) env");
    let alice = env.add_user("alice").await.expect("add alice");
    let bob = env.add_user("bob").await.expect("add bob");

    // Off policy does not auto-advertise, so a query against our own state finds
    // no TSP URI.
    let query = env
        .atm
        .tsp()
        .capability_query(&alice.did, &bob.did)
        .expect("build capability query");
    let disclosure = disclosure_for_query(&env, &query).await;
    assert!(
        disclosure.disclosures.is_empty(),
        "Off policy advertises no TSP URI"
    );

    // Even handed a disclosure that *does* advertise TSP, learning is a no-op.
    let forced = DiscoverFeaturesDisclosure {
        disclosures: vec![
            affinidi_messaging_sdk::protocols::discover_features::Disclosure {
                feature_type:
                    affinidi_messaging_sdk::protocols::discover_features::FeatureType::Protocol,
                id: TSP_DISCOVER_FEATURE_URI.to_string(),
                roles: vec![],
            },
        ],
    };
    let learned = env
        .atm
        .tsp()
        .learn_from_disclosure(&alice.profile, &bob.did, &forced)
        .await
        .expect("learn from disclosure");
    assert!(learned, "the URI was present in the disclosure");
    assert_eq!(
        env.atm
            .tsp()
            .peer_capability(&alice.profile, &bob.did)
            .await
            .unwrap(),
        None,
        "Off policy tracks no capability even when told"
    );
}

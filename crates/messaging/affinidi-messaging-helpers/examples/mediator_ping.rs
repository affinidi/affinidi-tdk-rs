//! Example Trust Ping using the Affinidi Trust Messaging SDK
//! Pings the mediator from Alice
//! Will use HTTPS and then WebSocket

use affinidi_messaging_sdk::{
    ATM,
    config::ATMConfig,
    errors::ATMError,
    messages::{GetMessagesRequest, sending::InboundMessageResponse},
    profiles::ATMProfile,
    transports::SendMessageResponse,
};
use affinidi_tdk::common::{TDKSharedState, environments::TDKEnvironments};
use clap::Parser;
use std::{
    env,
    sync::Arc,
    time::{Duration, SystemTime},
};
use tokio::time::sleep;
use tracing::{debug, error, info};
use tracing_subscriber::filter;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Environment to use
    #[arg(short, long)]
    environment: Option<String>,

    /// Path to the environments file (defaults to environments.json)
    #[arg(short, long)]
    path_environments: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), ATMError> {
    let args: Args = Args::parse();

    let environment_name = if let Some(environment_name) = &args.environment {
        environment_name.to_string()
    } else if let Ok(environment_name) = env::var("TDK_ENVIRONMENT") {
        environment_name
    } else {
        "default".to_string()
    };

    let mut environment =
        TDKEnvironments::fetch_from_file(args.path_environments.as_deref(), &environment_name)?;
    println!("Using Environment: {}", environment_name);

    // Instantiate TDK
    let tdk = Arc::new(TDKSharedState::default().await);

    // construct a subscriber that prints formatted traces to stdout
    let subscriber = tracing_subscriber::fmt()
        // Use a more compact, abbreviated log format
        .with_env_filter(filter::EnvFilter::from_default_env())
        .finish();
    // use that subscriber to process traces emitted after this point
    tracing::subscriber::set_global_default(subscriber).expect("Logging failed, exiting...");

    let alice = if let Some(alice) = environment.profiles.get("Alice") {
        tdk.add_profile(alice).await;
        alice
    } else {
        return Err(ATMError::ConfigError(
            format!("Alice not found in Profile: {}", environment_name).to_string(),
        ));
    };

    let mut config = ATMConfig::builder();

    config = config.with_ssl_certificates(&mut environment.ssl_certificates);

    // Create a new ATM Client
    let atm = ATM::new(config.build()?, tdk).await?;

    debug!("Enabling Alice's Profile");
    let alice = atm
        .profile_add(&ATMProfile::from_tdk_profile(&atm, alice).await?, false)
        .await?;

    let mut success_count = 0;
    let mediator = alice.inner.mediator.clone();
    let mediator_did = match &*mediator {
        Some(mediator) => mediator.did.clone(),
        _ => {
            error!("No mediator found in Alice's profile");
            return Ok(());
        }
    };
    println!("Mediator = {}", mediator_did);

    // Ready to send a trust-ping to ATM
    let start = SystemTime::now();

    // Send a trust-ping message to ATM, will generate a PONG response
    let response = atm
        .trust_ping()
        .send_ping(&alice, &mediator_did, true, true, false)
        .await?;
    let after_ping = SystemTime::now();

    info!("PING sent: {}", response.message_hash);
    let msg_id = if let SendMessageResponse::RestAPI(response) = response.response {
        let a: InboundMessageResponse =
            match serde_json::from_value(response.get("data").unwrap().to_owned()) {
                Ok(a) => a,
                Err(e) => {
                    error!("Error parsing response: {}", e);
                    return Ok(());
                }
            };

        if let InboundMessageResponse::Stored(details) = a {
            details.messages[0].1.clone()
        } else {
            error!("Expected a Stored response");
            return Ok(());
        }
    } else {
        error!("Expected a RestAPI response");
        return Ok(());
    };

    // Get the PONG message from ATM
    let msgs = atm
        .get_messages(
            &alice,
            &GetMessagesRequest {
                delete: true,
                message_ids: vec![msg_id],
            },
        )
        .await?;
    let after_get = SystemTime::now();
    debug!("After get_messages: {:?}", msgs);

    // Unpack the messages retrieved
    for msg in msgs.success {
        atm.unpack(&msg.msg.unwrap()).await?;
        info!("PONG received: {}", msg.msg_id);
    }
    let after_unpack = SystemTime::now();

    // Print out timing information
    info!(
        "Sending Ping took {}ms :: total {}ms to complete",
        after_ping.duration_since(start).unwrap().as_millis(),
        after_ping.duration_since(start).unwrap().as_millis()
    );
    info!(
        "Get response took {}ms :: total {}ms to complete",
        after_get.duration_since(after_ping).unwrap().as_millis(),
        after_get.duration_since(start).unwrap().as_millis()
    );
    info!(
        "Unpack took {:0.2}ms :: total {:0.2}ms to complete",
        after_unpack.duration_since(after_get).unwrap().as_micros() as f64 / 1000.0,
        after_unpack.duration_since(start).unwrap().as_micros() as f64 / 1000.0
    );

    info!(
        "Total trust-ping took {}ms to complete",
        after_unpack.duration_since(start).unwrap().as_millis()
    );
    success_count += 1;
    info!(" counters: success: {}", success_count);

    sleep(Duration::from_millis(2000)).await;

    // Send a WebSocket message
    info!(" *****************************************************  ");
    info!("Starting WebSocket test...");
    let start = SystemTime::now();
    atm.profile_enable_websocket(&alice).await?;
    let after_connect = SystemTime::now();

    let response = atm
        .trust_ping()
        .send_ping(&alice, &mediator_did, true, true, false)
        .await?;
    let after_ping_send = SystemTime::now();
    info!("PING sent: {}", response.message_id);

    let response = atm
        .message_pickup()
        .live_stream_get(&alice, &response.message_id, Duration::from_secs(10), true)
        .await?;
    let after_pong_receive = SystemTime::now();

    if let Some((msg, _)) = response {
        info!("PONG received: {}", msg.id);
    } else {
        error!("No response from live stream");
    }

    // Print out timing information
    info!(
        "Connecting WebSocket took {}ms :: total {}ms to complete",
        after_connect.duration_since(start).unwrap().as_millis(),
        after_connect.duration_since(start).unwrap().as_millis()
    );
    info!(
        "Sending Ping took {:0.2}ms :: total {:0.2}ms to complete",
        after_ping_send
            .duration_since(after_connect)
            .unwrap()
            .as_micros() as f64
            / 1000.0,
        after_ping_send.duration_since(start).unwrap().as_micros() as f64 / 1000.0
    );

    info!(
        "Receiving unpacked Pong took {}ms :: total {}ms to complete",
        after_pong_receive
            .duration_since(after_ping_send)
            .unwrap()
            .as_millis(),
        after_pong_receive
            .duration_since(start)
            .unwrap()
            .as_millis()
    );
    info!(
        "Total WebSocket trust-ping took {}ms to complete",
        after_pong_receive
            .duration_since(start)
            .unwrap()
            .as_millis()
    );

    sleep(Duration::from_millis(1000)).await;
    // 2nd WebSocket message
    info!(" *****************************************************  ");
    info!("2nd WebSocket test...");
    let start = SystemTime::now();
    let response = atm
        .trust_ping()
        .send_ping(&alice, &mediator_did, true, true, false)
        .await?;
    let after_ping_send = SystemTime::now();
    info!("PING sent: {}", response.message_id);

    let response = atm
        .message_pickup()
        .live_stream_get(&alice, &response.message_id, Duration::from_secs(10), true)
        .await?;
    let after_pong_receive = SystemTime::now();

    if let Some((msg, _)) = response {
        info!("PONG received: {}", msg.id);
    } else {
        error!("No response from live stream");
    }

    // Print out timing information
    info!(
        "Sending Ping took {:0.2}ms :: total {:0.2}ms to complete",
        after_ping_send.duration_since(start).unwrap().as_micros() as f64 / 1000.0,
        after_ping_send.duration_since(start).unwrap().as_micros() as f64 / 1000.0
    );

    info!(
        "Receiving unpacked Pong took {}ms :: total {}ms to complete",
        after_pong_receive
            .duration_since(after_ping_send)
            .unwrap()
            .as_millis(),
        after_pong_receive
            .duration_since(start)
            .unwrap()
            .as_millis()
    );
    info!(
        "Total WebSocket trust-ping took {}ms to complete",
        after_pong_receive
            .duration_since(start)
            .unwrap()
            .as_millis()
    );
    info!(" ***************************************************** ");
    atm.graceful_shutdown().await;
    Ok(())
}

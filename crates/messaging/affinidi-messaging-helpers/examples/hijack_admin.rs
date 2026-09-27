/*! Reproducible attack vector to hijack an admin account
 *
 * This is a demonstration of a potential attack vector that can be used to hijack an admin account.
 * Prior to versions 0.10.3 this could be used
 *
 *  1. Start with an admin account
 *  2. Apply the authorization tokens to a non-admin account
 *  3. Use the non-admin account to access an admin function
 *
 * Each attempt sends a `messaging/account/update` Trust Task promoting Mallory to admin,
 * and every one must be refused:
 * 0. Ask for it in Mallory's own name, over Mallory's own session
 * 1. Hijack the admin session credentials, send anonymously
 * 2. Hijack the admin session credentials and send as Mallory to bypass anon messaging checks
 * 3. Create a valid Admin Trust Task from the admin, but sent via Mallory
 *
 * */

use affinidi_messaging_didcomm::message::Message;
use affinidi_messaging_sdk::{
    ATM, errors::ATMError, profiles::ATMProfile, protocols::trust_tasks::ENVELOPE_TYPE,
};
use affinidi_tdk::{TDK, common::config::TDKConfig, did_authentication::AuthorizationTokens};
use clap::Parser;
use sha256::digest;
use std::{env, str::FromStr, sync::Arc, time::SystemTime};
use tracing::{info, warn};
use tracing_subscriber::filter;
use trust_tasks_rs::TrustTask;
use trust_tasks_rs::specs::messaging::account::{self, get::v0_1::AccountType};
use uuid::Uuid;

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

    // construct a subscriber that prints formatted traces to stdout
    let subscriber = tracing_subscriber::fmt()
        // Use a more compact, abbreviated log format
        .with_env_filter(filter::EnvFilter::from_default_env())
        .finish();
    // use that subscriber to process traces emitted after this point
    tracing::subscriber::set_global_default(subscriber).expect("Logging failed, exiting...");

    let environment_name = if let Some(environment_name) = &args.environment {
        environment_name.to_string()
    } else if let Ok(environment_name) = env::var("TDK_ENVIRONMENT") {
        environment_name
    } else {
        "default".to_string()
    };

    info!("Using Environment: {}", environment_name);

    // Instantiate TDK
    let tdk = TDK::new(
        TDKConfig::builder()
            .with_environment_name(environment_name.clone())
            .build()?,
        None,
    )
    .await?;

    let _shared = tdk.get_shared_state();
    let environment = _shared.environment();
    let atm = tdk.atm.clone().unwrap();

    // Add and activate the admin profile
    let admin_opt = environment.admin_did();
    let tdk_admin = if let Some(admin) = admin_opt {
        tdk.add_profile(admin).await;
        admin
    } else {
        return Err(ATMError::ConfigError(format!(
            "ADMIN not found in Profile: {environment_name}"
        )));
    };
    let atm_admin = atm
        .profile_add(&ATMProfile::from_tdk_profile(&atm, tdk_admin).await?, true)
        .await?;
    info!("Admin profile active");

    // Check if actually admin? (a missing account is an Err under Trust Tasks)
    match atm.trust_tasks().account_get(&atm_admin, None).await {
        Ok(account) => {
            if matches!(
                account.account_type,
                AccountType::Admin | AccountType::RootAdmin
            ) {
                info!("Verified Admin account - OK");
            } else {
                return Err(ATMError::ConfigError(
                    "Admin account is actually not an ADMIN level account!!!".to_string(),
                ));
            }
        }
        Err(e) => {
            return Err(ATMError::ConfigError(
                format!("Error getting ADMIN account: {e}").to_string(),
            ));
        }
    }

    // Add and activate the non-admin profile
    let tdk_mallory = if let Some(mallory) = environment.profiles().get("Mallory") {
        tdk.add_profile(mallory).await;
        mallory
    } else {
        return Err(ATMError::ConfigError(
            format!("Mallory not found in Profile: {environment_name}").to_string(),
        ));
    };
    let atm_mallory = atm
        .profile_add(
            &ATMProfile::from_tdk_profile(&atm, tdk_mallory).await?,
            true,
        )
        .await?;
    info!("Mallory profile active");

    // Check if actually not-admin? (a missing account is an Err under Trust Tasks)
    match atm.trust_tasks().account_get(&atm_mallory, None).await {
        Ok(account) => {
            if !matches!(
                account.account_type,
                AccountType::Admin | AccountType::RootAdmin
            ) {
                info!("Verified Non-Admin account - OK");
            } else {
                return Err(ATMError::ConfigError(
                    "Mallory is an ADMIN level account!!!".to_string(),
                ));
            }
        }
        Err(e) => {
            return Err(ATMError::ConfigError(
                format!("Error getting Mallory account: {e}").to_string(),
            ));
        }
    }

    // Mediator for this demo
    let mediator = environment
        .default_mediator()
        .ok_or_else(|| {
            ATMError::ConfigError(format!(
                "Mediator not found in Environment: {environment_name}"
            ))
        })?
        .to_string();
    let mallory_hash = digest(&atm_mallory.inner.did);

    // Try and do an admin function with Mallory
    info!("Trying to access an admin function with Mallory");
    match atm
        .trust_tasks()
        .account_list(&atm_mallory, None, None, None)
        .await
    {
        Ok(_) => {
            warn!("Mallory was able to access an admin function - NOT OK");
        }
        Err(_) => {
            info!("Mallory was not able to access an admin function - OK");
        }
    }

    // Ask for the escalation outright, in Mallory's own name
    info!("  *************************************************************");
    info!("  Attempting to promote Mallory to admin in Mallory's own name");
    info!("  *************************************************************");
    match atm
        .trust_tasks()
        .account_update(
            &atm_mallory,
            Some(mallory_hash.clone()),
            Some(account::update::v0_1::AccountType::Admin),
            None,
            None,
        )
        .await
    {
        Ok(_) => warn!("The mediator accepted Mallory's self-promotion - NOT OK"),
        Err(e) => info!("The mediator refused Mallory's self-promotion - OK ({e})"),
    }
    check_mallory(&atm, &atm_mallory).await?;

    // Hijack credentials
    info!("Starting hijack of admin credentials...");
    let admin_tokens = match tdk
        .get_shared_state()
        .authentication()
        .authenticated(tdk_admin.did.clone(), mediator.clone())
        .await
    {
        Some(tokens) => tokens,
        None => {
            return Err(ATMError::ConfigError("Admin tokens not found".to_string()));
        }
    };
    info!("Admin tokens hijacked");

    info!("Shutdown Admin profile so there is no conflict with Mallory");
    atm.profile_remove(&atm_admin.inner.alias).await?;

    info!("  *************************************************************");
    info!("  Attempting to hijack anonymously an admin session with Mallory");
    info!("  *************************************************************");
    let bad_msg = promote_to_admin(&mallory_hash, &mediator, None)?;
    info!(
        "Created a messaging/account/update Trust Task promoting Mallory, from no one...\n:{:#?}",
        bad_msg
    );

    info!("Packing message anonymously - don't link it to Mallory");
    let (msg, _) = atm.pack_encrypted(&bad_msg, &mediator, None, None).await?;

    info!("Sending the Trust Task to the mediator on the hijacked admin session");
    http_post(&tdk, &atm_mallory, &msg, &admin_tokens).await;
    check_mallory(&atm, &atm_mallory).await?;

    info!("  *************************************************************");
    info!("  Attempting to hijack an admin session as Mallory");
    info!("  *************************************************************");
    let bad_msg = promote_to_admin(&mallory_hash, &mediator, Some(&atm_mallory.inner.did))?;
    info!(
        "Created a messaging/account/update Trust Task promoting Mallory, from Mallory...\n:{:#?}",
        bad_msg
    );

    info!("Packing message from Mallory");
    let (msg, _) = atm
        .pack_encrypted(
            &bad_msg,
            &mediator,
            Some(atm_mallory.dids()?.0),
            Some(atm_mallory.dids()?.0),
        )
        .await?;

    info!("Sending the Trust Task to the mediator on the hijacked admin session");
    http_post(&tdk, &atm_mallory, &msg, &admin_tokens).await;
    check_mallory(&atm, &atm_mallory).await?;

    info!("  *************************************************************");
    info!("  Attempting to resend an Admin Trust Task using Mallory");
    info!("  *************************************************************");
    let bad_msg = promote_to_admin(&mallory_hash, &mediator, Some(&atm_admin.inner.did))?;
    let msg_id = bad_msg.id.clone();
    info!("Created a messaging/account/update Trust Task promoting Mallory, from the admin...");

    info!("Packing message from Admin");
    let (msg, _) = atm
        .pack_encrypted(
            &bad_msg,
            &mediator,
            Some(atm_admin.dids()?.0),
            Some(atm_admin.dids()?.0),
        )
        .await?;

    info!("Sending the admin's Trust Task to the mediator on Mallory's session");
    match atm
        .send_message(&atm_mallory, &msg, &msg_id, true, false)
        .await
    {
        Ok(_) => {
            info!("Message sent successfully");
        }
        Err(e) => {
            warn!("Error sending message: {}", e);
        }
    }
    check_mallory(&atm, &atm_mallory).await?;

    Ok(())
}

/// A `messaging/account/update` Trust Task promoting `mallory_hash` to admin,
/// wrapped in the DIDComm binding envelope. `issuer` is the DID the document
/// and the envelope claim to come from; `None` leaves both anonymous.
fn promote_to_admin(
    mallory_hash: &str,
    mediator: &str,
    issuer: Option<&str>,
) -> Result<Message, ATMError> {
    let payload: account::update::v0_1::Payload = account::update::v0_1::Payload::builder()
        .did(
            account::update::v0_1::Vid::from_str(mallory_hash)
                .map_err(|e| ATMError::MsgSendError(format!("invalid account identifier: {e}")))?,
        )
        .account_type(Some(account::update::v0_1::AccountType::Admin))
        .try_into()
        .map_err(|e| ATMError::MsgSendError(format!("invalid trust-task payload: {e}")))?;
    let mut task = TrustTask::for_payload(Uuid::new_v4().to_string(), payload);
    task.issuer = issuer.map(str::to_string);
    task.recipient = Some(mediator.to_string());
    task.issued_at = Some(chrono::Utc::now());
    let body = serde_json::to_value(&task)
        .map_err(|e| ATMError::MsgSendError(format!("couldn't serialise Trust Task: {e}")))?;

    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let msg = Message::build(Uuid::new_v4().to_string(), ENVELOPE_TYPE.to_owned(), body)
        .to(mediator.to_owned())
        .created_time(now)
        .expires_time(now + 10);
    Ok(match issuer {
        Some(issuer) => msg.from(issuer.to_owned()),
        None => msg,
    }
    .finalize())
}

/// Confirm Mallory is still not an admin after an attempt.
async fn check_mallory(atm: &ATM, atm_mallory: &Arc<ATMProfile>) -> Result<(), ATMError> {
    // A missing account is an Err under Trust Tasks.
    match atm.trust_tasks().account_get(atm_mallory, None).await {
        Ok(account) => {
            if matches!(
                account.account_type,
                AccountType::Admin | AccountType::RootAdmin
            ) {
                warn!("Mallory is now an ADMIN level account - NOT OK!!!!");
            } else {
                info!("Mallory is still a non admin... Phew....");
            }
            Ok(())
        }
        Err(e) => Err(ATMError::ConfigError(format!(
            "Error getting Mallory account: {e}"
        ))),
    }
}

async fn http_post(
    tdk: &TDK,
    profile: &Arc<ATMProfile>,
    msg: &str,
    admin_tokens: &AuthorizationTokens,
) {
    let response = tdk
        .get_shared_state()
        .client()
        .post([&profile.get_mediator_rest_endpoint().unwrap(), "/inbound"].concat())
        .header("Content-Type", "application/json")
        .header(
            "Authorization",
            format!("Bearer {}", admin_tokens.access_token),
        )
        .body(msg.to_string())
        .send()
        .await
        .expect("HTTP Post failed");

    let response_status = response.status();
    let response_body = response.text().await.expect("Failed to get response body");

    if !response_status.is_success() {
        if response_status.as_u16() == 401 {
            warn!("Permission Denied (401: Unauthorized)");
        } else {
            warn!("HTTP Error: {}\n{}", response_status, response_body);
        }
    }

    info!("response body: {}", response_body);
}

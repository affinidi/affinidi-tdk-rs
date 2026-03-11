use affinidi_did_common::service::Endpoint;
use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use affinidi_messaging_mediator_common::errors::MediatorError;
use affinidi_secrets_resolver::{SecretsResolver, ThreadedSecretsResolver, secrets::Secret};
use aws_config::SdkConfig;
use aws_sdk_secretsmanager;
use aws_sdk_ssm::types::ParameterType;
use base64::prelude::*;
use regex::{Captures, Regex};
use std::{
    env,
    fs::File,
    io::{self, BufRead},
    path::Path,
    sync::Arc,
};
use tracing::info;

use super::processors::ForwardingConfig;

/// Loads the secret data into the Config file.
pub(crate) async fn load_secrets(
    secrets_resolver: &Arc<ThreadedSecretsResolver>,
    secrets: &str,
    aws_config: &SdkConfig,
) -> Result<(), MediatorError> {
    let parts: Vec<&str> = secrets.split("://").collect();
    if parts.len() != 2 {
        return Err(MediatorError::ConfigError(
            12,
            "NA".into(),
            "Invalid `mediator_secrets` format".into(),
        ));
    }
    println!("Loading secrets method({}) path({})", parts[0], parts[1]);
    let content: String = match parts[0] {
        "file" => read_file_lines(parts[1])?.concat(),
        "aws_secrets" => {
            let asm = aws_sdk_secretsmanager::Client::new(aws_config);

            let response = asm
                .get_secret_value()
                .secret_id(parts[1])
                .send()
                .await
                .map_err(|e| {
                    eprintln!("Could not get secret value. {e}");
                    MediatorError::ConfigError(
                        12,
                        "NA".into(),
                        format!("Could not get secret value. {e}"),
                    )
                })?;
            response.secret_string.ok_or_else(|| {
                eprintln!("No secret string found in response");
                MediatorError::ConfigError(
                    12,
                    "NA".into(),
                    "No secret string found in response".into(),
                )
            })?
        }
        _ => {
            return Err(MediatorError::ConfigError(
                12,
                "NA".into(),
                "Invalid `mediator_secrets` format! Expecting file:// or aws_secrets:// ...".into(),
            ));
        }
    };

    let secrets: Vec<Secret> = serde_json::from_str(&content).map_err(|err| {
        eprintln!("Could not parse `mediator_secrets` JSON content. {err}");
        MediatorError::ConfigError(
            12,
            "NA".into(),
            format!("Could not parse `mediator_secrets` JSON content. {err}"),
        )
    })?;

    info!(
        "Loading {} mediator Secret{}",
        secrets.len(),
        if secrets.is_empty() { "" } else { "s" }
    );
    secrets_resolver.insert_vec(&secrets).await;

    Ok(())
}

/// Read the primary configuration file for the mediator
/// Returns a ConfigRaw struct, that still needs to be processed for additional information
/// and conversion to Config struct
pub(crate) fn read_config_file(file_name: &str) -> Result<super::ConfigRaw, MediatorError> {
    // Read configuration file parameters
    println!("Config file({file_name})");
    let raw_config = read_file_lines(file_name)?;

    let config_with_vars = expand_env_vars(&raw_config)?;
    match toml::from_str(&config_with_vars.join("\n")) {
        Ok(config) => Ok(config),
        Err(err) => {
            eprintln!("Could not parse configuration settings. {err:?}");
            Err(MediatorError::ConfigError(
                12,
                "NA".into(),
                format!("Could not parse configuration settings. Reason: {err:?}"),
            ))
        }
    }
}

/// Reads a file and returns a vector of strings, one for each line in the file.
/// It also strips any lines starting with a # (comments)
/// You can join the Vec back into a single string with `.join("\n")`
/// ```ignore
/// let lines = read_file_lines("file.txt")?;
/// let file_contents = lines.join("\n");
/// ```
pub(crate) fn read_file_lines<P>(file_name: P) -> Result<Vec<String>, MediatorError>
where
    P: AsRef<Path>,
{
    let file = File::open(file_name.as_ref()).map_err(|err| {
        eprintln!(
            "Could not open file({}). {}",
            file_name.as_ref().display(),
            err
        );
        MediatorError::ConfigError(
            12,
            "NA".into(),
            format!(
                "Could not open file({}). {}",
                file_name.as_ref().display(),
                err
            ),
        )
    })?;

    let mut lines = Vec::new();
    for line in io::BufReader::new(file).lines().map_while(Result::ok) {
        // Strip comments out
        if !line.starts_with('#') {
            lines.push(line);
        }
    }

    Ok(lines)
}

/// Replaces all strings ${VAR_NAME:default_value}
/// with the corresponding environment variables (e.g. value of ${VAR_NAME})
/// or with `default_value` if the variable is not defined.
pub(crate) fn expand_env_vars(raw_config: &Vec<String>) -> Result<Vec<String>, MediatorError> {
    let re = Regex::new(r"\$\{(?P<env_var>[A-Z_]{1,}[0-9A-Z_]*):(?P<default_value>.*)\}").map_err(
        |e| {
            MediatorError::ConfigError(
                12,
                "NA".into(),
                format!("Couldn't create ENV Regex. Reason: {e}"),
            )
        },
    )?;
    let mut result: Vec<String> = Vec::new();
    for line in raw_config {
        result.push(
            re.replace_all(line, |caps: &Captures| match env::var(&caps["env_var"]) {
                Ok(val) => val,
                Err(_) => (caps["default_value"]).into(),
            })
            .into_owned(),
        );
    }
    Ok(result)
}

/// Converts the mediator_did config to a valid DID depending on source
pub(crate) async fn read_did_config(
    did_config: &str,
    aws_config: &SdkConfig,
    field_name: &str,
) -> Result<String, MediatorError> {
    let parts: Vec<&str> = did_config.split("://").collect();
    if parts.len() != 2 {
        return Err(MediatorError::ConfigError(
            12,
            "NA".into(),
            format!("Invalid `{field_name}` format"),
        ));
    }
    let content: String = match parts[0] {
        "did" => parts[1].to_string(),
        "aws_parameter_store" => aws_parameter_store(parts[1], aws_config).await?,
        _ => {
            return Err(MediatorError::ConfigError(
                12,
                "NA".into(),
                "Invalid mediator_did format! Expecting did:// or aws_parameter_store:// ..."
                    .into(),
            ));
        }
    };

    Ok(content)
}

/// Converts the jwt_authorization_secret config to a valid JWT secret
/// Can take a basic string, or fetch from AWS Secrets Manager
pub(crate) async fn config_jwt_secret(
    jwt_secret: &str,
    aws_config: &SdkConfig,
) -> Result<Vec<u8>, MediatorError> {
    let parts: Vec<&str> = jwt_secret.split("://").collect();
    if parts.len() != 2 {
        return Err(MediatorError::ConfigError(
            12,
            "NA".into(),
            "Invalid `jwt_authorization_secret` format".into(),
        ));
    }
    let content: String = match parts[0] {
        "string" => parts[1].to_string(),
        "aws_secrets" => {
            println!("Loading JWT secret from AWS Secrets Manager");
            let asm = aws_sdk_secretsmanager::Client::new(aws_config);

            let response = asm
                .get_secret_value()
                .secret_id(parts[1])
                .send()
                .await
                .map_err(|e| {
                    eprintln!("Could not get secret value. {e}");
                    MediatorError::ConfigError(
                        12,
                        "NA".into(),
                        format!("Could not get secret value. {e}"),
                    )
                })?;
            response.secret_string.ok_or_else(|| {
                eprintln!("No secret string found in response");
                MediatorError::ConfigError(
                    12,
                    "NA".into(),
                    "No secret string found in response".into(),
                )
            })?
        }
        _ => return Err(MediatorError::ConfigError(
            12,
            "NA".into(),
            "Invalid `jwt_authorization_secret` format! Expecting string:// or aws_secrets:// ..."
                .into(),
        )),
    };

    BASE64_URL_SAFE_NO_PAD.decode(content).map_err(|err| {
        eprintln!("Could not create JWT key pair. {err}");
        MediatorError::ConfigError(
            12,
            "NA".into(),
            format!("Could not create JWT key pair. {err}"),
        )
    })
}

pub(crate) fn get_hostname(host_name: &str) -> Result<String, MediatorError> {
    if host_name.starts_with("hostname://") {
        Ok(hostname::get()
            .map_err(|e| {
                MediatorError::ConfigError(
                    12,
                    "NA".into(),
                    format!("Couldn't get hostname. Reason: {e}"),
                )
            })?
            .into_string()
            .map_err(|e| {
                MediatorError::ConfigError(
                    12,
                    "NA".into(),
                    format!("Couldn't get hostname. Reason: {e:?}"),
                )
            })?)
    } else if host_name.starts_with("string://") {
        Ok(host_name.split_at(9).1.to_string())
    } else {
        Err(MediatorError::ConfigError(
            12,
            "NA".into(),
            "Invalid hostname format!".into(),
        ))
    }
}

pub(crate) async fn aws_parameter_store(
    parameter_name: &str,
    aws_config: &SdkConfig,
) -> Result<String, MediatorError> {
    let ssm = aws_sdk_ssm::Client::new(aws_config);

    let response = ssm
        .get_parameter()
        // .set_name(Some(parts[1].to_string()))
        .set_name(Some(parameter_name.to_string()))
        .send()
        .await
        .map_err(|e| {
            eprintln!("Could not get ({parameter_name:?}) parameter. {e}");
            MediatorError::ConfigError(
                12,
                "NA".into(),
                format!("Could not get ({parameter_name:?}) parameter. {e}"),
            )
        })?;
    let parameter = response.parameter.ok_or_else(|| {
        eprintln!("No parameter string found in response");
        MediatorError::ConfigError(
            12,
            "NA".into(),
            "No parameter string found in response".into(),
        )
    })?;

    if let Some(_type) = parameter.r#type {
        if _type != ParameterType::String {
            return Err(MediatorError::ConfigError(
                12,
                "NA".into(),
                "Expected String parameter type".into(),
            ));
        }
    } else {
        return Err(MediatorError::ConfigError(
            12,
            "NA".into(),
            "Unknown parameter type".into(),
        ));
    }

    parameter.value.ok_or_else(|| {
        eprintln!(
            "Parameter ({:?}) found, but no parameter value found in response",
            parameter.name
        );
        MediatorError::ConfigError(
            12,
            "NA".into(),
            format!(
                "Parameter ({:?}) found, but no parameter value found in response",
                parameter.name
            ),
        )
    })
}

/// Reads document from file or aws_parameter_store
pub(crate) async fn read_document(
    document_path: &str,
    aws_config: &SdkConfig,
) -> Result<String, MediatorError> {
    let parts: Vec<&str> = document_path.split("://").collect();
    if parts.len() != 2 {
        return Err(MediatorError::ConfigError(
            12,
            "NA".into(),
            "Invalid `document_path` format".into(),
        ));
    }
    let content: String = match parts[0] {
        "file" => read_file_lines(parts[1])?.concat(),
        "aws_parameter_store" => aws_parameter_store(parts[1], aws_config).await?,
        _ => {
            return Err(MediatorError::ConfigError(
                12,
                "NA".into(),
                "Invalid document_path format! Expecting file:// or aws_parameter_store:// ..."
                    .into(),
            ));
        }
    };

    Ok(content)
}

/// Creates a set of URI's that can be used to detect if forwarding loopbacks to the mediator could occur
pub(crate) async fn load_forwarding_protection_blocks(
    did_resolver: &DIDCacheClient,
    forwarding_config: &mut ForwardingConfig,
    mediator_did: &str,
    blocked_dids: &str,
) -> Result<(), MediatorError> {
    let mut blocked_dids: Vec<String> = match serde_json::from_str(blocked_dids) {
        Ok(dids) => dids,
        Err(err) => {
            eprintln!("Could not parse blocked_forwarding_dids. Reason: {err}");
            return Err(MediatorError::ConfigError(
                12,
                "NA".into(),
                format!("Could not parse blocked_forwarding_dids. Reason: {err}"),
            ));
        }
    };

    // Add the mediator DID to the blocked list
    blocked_dids.push(mediator_did.into());

    // Iterate through each DID that we need to block
    for did in blocked_dids {
        let doc = did_resolver.resolve(&did).await.map_err(|err| {
            MediatorError::DIDError(
                12,
                "NA".into(),
                did.clone(),
                format!("Couldn't resolve DID. Reason: {err}"),
            )
        })?;

        forwarding_config.blocked_forwarding.insert(did.clone());

        // Add the service endpoints to the forwarding protection list
        for service in doc.doc.service.iter() {
            match &service.service_endpoint {
                Endpoint::Url(uri) => {
                    forwarding_config.blocked_forwarding.insert(uri.to_string());
                }
                Endpoint::Map(map) => {
                    if let Some(endpoints) = map.as_array() {
                        for endpoint in endpoints {
                            if let Some(uri) = endpoint.get("uri") {
                                if let Some(uri) = uri.as_str() {
                                    forwarding_config.blocked_forwarding.insert(uri.into());
                                } else {
                                    eprintln!("WARN: Couldn't parse URI as a string: {uri:#?}");
                                }
                            } else {
                                eprintln!(
                                    "WARN: Service endpoint map does not contain a URI. DID ({did}), Service ({service:#?}), Endpoint ({endpoint:#?})"
                                );
                            }
                        }
                    } else if let Some(uri) = map.get("uri") {
                        if let Some(uri) = uri.as_str() {
                            forwarding_config.blocked_forwarding.insert(uri.into());
                        } else {
                            eprintln!("WARN: Couldn't parse URI as a string: {uri:#?}");
                        }
                    } else {
                        eprintln!(
                            "WARN: Service endpoint map does not contain a URI. DID ({did}), Service ({service:#?}), Endpoint ({map:#?})"
                        );
                    }
                }
            }
        }
    }

    Ok(())
}

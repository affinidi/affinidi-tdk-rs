//! Helper functions to do with the Mediator
use affinidi_tdk::secrets_resolver::secrets::Secret;
use base64::prelude::*;
use console::style;
use regex::{Captures, Regex};
use ring::signature::Ed25519KeyPair;
use serde::Serialize;
use std::{
    env,
    error::Error,
    fs::File,
    io::{self, BufRead, Write},
    path::Path,
};
use toml::Value;

#[derive(Debug, Default, Serialize)]
pub(crate) struct MediatorConfig {
    pub mediator_did: Option<String>,
    pub mediator_secrets: Option<Vec<Secret>>,
    pub admin_did: Option<String>,
    pub admin_secrets: Option<Vec<Secret>>,
    pub jwt_authorization_secret: Option<String>,
}

impl MediatorConfig {
    pub fn create_jwt_secrets(&mut self) -> Result<(), Box<dyn Error>> {
        // Create jwt_authorization_secret
        self.jwt_authorization_secret = Some(
            BASE64_URL_SAFE_NO_PAD
                .encode(Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new()).unwrap()),
        );

        println!(
            "  {} {}",
            style(" JWT Authorization Secret created: ").blue().bold(),
            style(&self.jwt_authorization_secret.as_ref().unwrap()).color256(208)
        );

        Ok(())
    }

    /// Saves a mediator configuration to a file
    pub fn save_config(&self) -> Result<(), Box<dyn Error>> {
        // 1. Write out the mediator secrets file
        if let Some(secrets) = &self.mediator_secrets {
            let mut file = File::create("./affinidi-messaging-mediator/conf/secrets.json")?;
            file.write_all(serde_json::to_string(secrets)?.as_bytes())?;
            file.flush()?;
            println!(
                "  {}{}{}",
                style("Mediator secrets file (").blue(),
                style("./affinidi-messaging-mediator/conf/secrets.json").color256(201),
                style(") written...").blue()
            );
        }

        // 3. Write out changes ot the mediator configuration file
        let config = std::fs::read_to_string("./affinidi-messaging-mediator/conf/mediator.toml")?;
        let mut new_config = String::new();
        let mut change_flag = false;

        let mediator_did_re = Regex::new(r"^mediator_did\s*=").unwrap();
        let admin_did_re = Regex::new(r"^admin_did\s*=").unwrap();
        let jwt_authorization_re = Regex::new(r"^jwt_authorization_secret\s*=").unwrap();
        config.lines().for_each(|line| {
            if mediator_did_re.is_match(line) {
                if let Some(mediator_did) = &self.mediator_did {
                    let new_str = format!(
                        "mediator_did = \"${{MEDIATOR_DID:did://{mediator_did}}}\""
                    );
                    new_config.push_str(&new_str);
                    new_config.push('\n');
                    println!(
                        "  {} {}",
                        style("Line modified:").blue(),
                        style(&new_str).color256(208),
                    );
                    change_flag = true;
                } else {
                    new_config.push_str(line);
                    new_config.push('\n');
                }
            } else if admin_did_re.is_match(line) {
                if let Some(admin_did) = &self.admin_did {
                    let new_str = format!("admin_did = \"${{ADMIN_DID:did://{admin_did}}}\"");
                    new_config.push_str(&new_str);
                    new_config.push('\n');
                    println!(
                        "  {} {}",
                        style("Line modified:").blue(),
                        style(&new_str).color256(208),
                    );
                    change_flag = true;
                } else {
                    new_config.push_str(line);
                    new_config.push('\n');
                }
            } else if jwt_authorization_re.is_match(line) {
                if let Some(jwt_auth) = &self.jwt_authorization_secret {
                    let new_str = format!(
                        "jwt_authorization_secret = \"${{JWT_AUTHORIZATION_SECRET:string://{jwt_auth}}}\""
                    );
                    new_config.push_str(&new_str);
                    new_config.push('\n');
                    println!(
                        "  {} {}",
                        style("Line modified:").blue(),
                        style(&new_str).color256(208),
                    );
                    change_flag = true;
                } else {
                    new_config.push_str(line);
                    new_config.push('\n');
                }
            } else {
                new_config.push_str(line);
                new_config.push('\n');
            }
        });

        if change_flag {
            std::fs::write(
                "./affinidi-messaging-mediator/conf/mediator.toml",
                new_config,
            )?;

            println!(
                "  {}{}{}",
                style("Mediator configuration file (").blue(),
                style("./affinidi-messaging-mediator/conf/mediator.toml").color256(201),
                style(") updated...").blue(),
            );
        } else {
            println!(
                "  {}",
                style("No changes were made to the Mediator Configuration").blue(),
            );
        }

        Ok(())
    }
}

/// Replaces all strings ${VAR_NAME:default_value}
/// with the corresponding environment variables (e.g. value of ${VAR_NAME})
/// or with `default_value` if the variable is not defined.
fn expand_env_vars(raw_config: &Vec<String>) -> Result<Vec<String>, Box<dyn Error>> {
    let re = Regex::new(r"\$\{(?P<env_var>[A-Z_]{1,}[0-9A-Z_]*):(?P<default_value>.*)\}")?;
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

/// Read the primary configuration file for the mediator
/// Returns a ConfigRaw struct, that still needs to be processed for additional information
/// and conversion to Config struct
pub fn read_config_file(file_name: &str) -> Result<Value, Box<dyn Error>> {
    // Read configuration file parameters
    let raw_config = read_file_lines(file_name)?;

    let config_with_vars = expand_env_vars(&raw_config)?;
    Ok(toml::from_str(&config_with_vars.join("\n"))?)
}

/// Reads a file and returns a vector of strings, one for each line in the file.
/// It also strips any lines starting with a # (comments)
/// You can join the Vec back into a single string with `.join("\n")`
/// ```ignore
/// let lines = read_file_lines("file.txt")?;
/// let file_contents = lines.join("\n");
/// ```
fn read_file_lines<P>(file_name: P) -> Result<Vec<String>, Box<dyn Error>>
where
    P: AsRef<Path>,
{
    let file = File::open(file_name.as_ref())?;

    let mut lines = Vec::new();
    for line in io::BufReader::new(file).lines().map_while(Result::ok) {
        // Strip comments out
        if !line.starts_with('#') {
            lines.push(line);
        }
    }

    Ok(lines)
}

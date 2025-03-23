use std::{env, error::Error};

pub mod affinidi_logo;
pub mod did;

/// Returns the path to the top level directory depending on where you are
/// Will change path as required
pub fn check_path() -> Result<bool, Box<dyn Error>> {
    let cwd = std::env::current_dir()?;
    let mut path = String::new();
    let mut found = false;
    cwd.components().rev().for_each(|dir| {
        if dir.as_os_str() == "affinidi-messaging" && !found {
            found = true;
            path.push_str("./");
        } else if !found {
            path.push_str("../");
        }
    });

    if !found {
        return Err("You are not in the affinidi-messaging repository".into());
    }

    env::set_current_dir(&path)?;

    Ok(true)
}

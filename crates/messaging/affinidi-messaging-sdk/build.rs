//! Generates the Trust Task types this SDK speaks (`crate::tasks`) from the
//! versions pinned in `trust-tasks.lock`. Each vendored bundle under
//! `trust-tasks/` is checked against the digest the lock pins before anything
//! is generated. Change a pin with the `trust-tasks` CLI (`trust-tasks add`,
//! `trust-tasks update`), never by hand.

fn main() -> Result<(), trust_tasks_build::Error> {
    trust_tasks_build::Config::new().compile()?;
    Ok(())
}

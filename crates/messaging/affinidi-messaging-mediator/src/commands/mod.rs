//! Operator subcommands on the `mediator` binary.
//!
//! Pre-Phase-I the binary's only mode was "run the server" — `main.rs`
//! called [`crate::server::start`] unconditionally. Phase I introduced
//! an admin-rotation operation that benefits from sharing the same
//! config loader, secret backend, and tracing setup as the server, so
//! we host it inside the same binary rather than shipping a sibling.
//!
//! Each module here exposes a `run(...)` function that does its work
//! and returns. The CLI dispatcher in `main.rs` matches on a clap
//! subcommand enum and calls the right `run`.

pub mod rotate_admin;

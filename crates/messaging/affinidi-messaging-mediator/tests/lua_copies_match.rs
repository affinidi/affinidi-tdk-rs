//! The two copies of `atm-functions.lua` must not drift.
//!
//! There are two in the tree — the crate's `conf/atm-functions.lua`, which is
//! canonical, and `docker/test/conf/atm-functions.lua`, which
//! `docker/test/conf/mediator.toml` points `functions_file` at. They are hand
//! maintained, and a change that updates one and not the other is invisible:
//! the stale copy is still valid Lua, still loads cleanly under `FUNCTION LOAD
//! REPLACE`, and still defines every function by the same name. Only the body
//! differs.
//!
//! That is not hypothetical. 0.28.0 added per-relationship queue accounting
//! (`PEER_Q`) to the canonical copy and not to this one, so every deployment
//! reading the docker/test config had `peer_queue_count` returning 0 and the
//! `limits.queue.peer` gate permanently inert — the headline fix of that
//! release, absent, with nothing failing. It failed safe, because the sender
//! and recipient totals still applied, but "fails safe" and "works" are not the
//! same claim and only one of them was true.
//!
//! A byte comparison is the whole test. It is blunt on purpose: anything
//! cleverer (does it define the same functions? does it load?) passes on
//! exactly the drift that has already happened.

/// Canonical: shipped with the crate, and what `mediator-setup` writes.
const CANONICAL: &str = include_str!("../conf/atm-functions.lua");

/// The copy `docker/test/conf/mediator.toml` points `functions_file` at.
const DOCKER_TEST: &str = include_str!("../../../../docker/test/conf/atm-functions.lua");

#[test]
fn the_docker_test_lua_matches_the_canonical_one() {
    if CANONICAL == DOCKER_TEST {
        return;
    }

    // Report *what* drifted, not just that something did — the whole failure
    // mode here is a difference nobody noticed, so a bare "not equal" would
    // repeat the mistake in a smaller way.
    let canonical: Vec<&str> = CANONICAL.lines().collect();
    let docker: Vec<&str> = DOCKER_TEST.lines().collect();
    let only_in_canonical: Vec<&&str> = canonical.iter().filter(|l| !docker.contains(l)).collect();
    let only_in_docker: Vec<&&str> = docker.iter().filter(|l| !canonical.contains(l)).collect();

    panic!(
        "docker/test/conf/atm-functions.lua has drifted from the crate's conf/atm-functions.lua.\n\
         Copy the crate's copy over it — it is canonical.\n\n\
         Lines only in the canonical copy ({}):\n{}\n\n\
         Lines only in the docker/test copy ({}):\n{}",
        only_in_canonical.len(),
        only_in_canonical
            .iter()
            .map(|l| format!("  + {}", l.trim()))
            .collect::<Vec<_>>()
            .join("\n"),
        only_in_docker.len(),
        only_in_docker
            .iter()
            .map(|l| format!("  - {}", l.trim()))
            .collect::<Vec<_>>()
            .join("\n"),
    );
}

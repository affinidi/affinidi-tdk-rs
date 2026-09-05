#!/usr/bin/env bash
#
# Verify a fuzz crate's committed Cargo.lock still pins every crates.io
# dependency (SEC-3899).
#
# WHY THIS EXISTS RATHER THAN `cargo fetch --locked`
#
# The fuzz crates depend on the crates they fuzz *by path*, and a path package
# still carries a version in Cargo.lock. Repo convention
# (scripts/check-version-bumps.sh) requires bumping a crate's version on any
# source edit, so an ordinary PR to `affinidi-messaging-didcomm` — or to
# `affinidi-crypto`, which the fuzz targets pull in transitively and which does
# not even match this workflow's path filter — moves that version and makes the
# committed lock "stale". A bare `cargo fetch --locked` fails there, loudly and
# for a reason that has nothing to do with supply-chain risk: no unreviewed
# third-party code is being pulled, a local crate simply renumbered itself.
#
# What actually needs pinning is the *registry* graph: the crates.io versions
# and checksums whose build scripts and proc macros this job compiles and runs.
# So: let cargo re-resolve, then require that every crates.io entry is exactly
# as committed. Local path packages are free to move; a new or changed
# crates.io version fails the gate and must be reviewed and committed.
#
# Usage: scripts/check-fuzz-lock.sh <fuzz-crate-dir>

set -euo pipefail

dir="$(cd "${1:?usage: check-fuzz-lock.sh <fuzz-crate-dir>}" && pwd)"
cd "$dir"

if [[ ! -f Cargo.lock ]]; then
  echo "ERROR: $dir/Cargo.lock is missing." >&2
  echo "The fuzz dependency graph must be committed — run 'cargo fetch' here" >&2
  echo "and commit the resulting Cargo.lock." >&2
  exit 1
fi

# Every package block that carries a `source` line came from a registry; a path
# package has none. Emit name/version/source/checksum so a changed checksum is
# caught as well as a changed version.
registry_pins() {
  awk '
    function flush() {
      if (src != "") print name, ver, src, sum
      name = ""; ver = ""; src = ""; sum = ""
    }
    /^\[\[package\]\]/ { flush(); next }
    /^name = /         { name = $0 }
    /^version = /      { ver  = $0 }
    /^source = /       { src  = $0 }
    /^checksum = /     { sum  = $0 }
    END { flush() }
  ' "$1" | sort
}

committed_lock="$(mktemp)"
committed_pins="$(mktemp)"
resolved_pins="$(mktemp)"
# Always put the committed lock back: this is a check, not a mutation. The
# build that follows re-resolves offline (CARGO_NET_OFFLINE=1), which can only
# move the local path packages — everything else is already in the cargo cache.
trap 'cp "$committed_lock" "$dir/Cargo.lock"; rm -f "$committed_lock" "$committed_pins" "$resolved_pins"' EXIT

cp Cargo.lock "$committed_lock"
registry_pins Cargo.lock > "$committed_pins"

# Re-resolve. Cargo keeps every locked version it can, so only entries the
# manifests actually force will move.
cargo fetch

registry_pins Cargo.lock > "$resolved_pins"

if ! diff -u "$committed_pins" "$resolved_pins"; then
  echo >&2
  echo "ERROR: re-resolving $dir changed its crates.io dependencies." >&2
  echo >&2
  echo "The committed fuzz Cargo.lock must fully pin the registry graph: this" >&2
  echo "job compiles and runs third-party build scripts and proc macros, so a" >&2
  echo "newly published version is unreviewed code execution on the runner." >&2
  echo "Review the diff above, then commit the updated $dir/Cargo.lock." >&2
  exit 1
fi

echo "OK: $dir crates.io pins unchanged."

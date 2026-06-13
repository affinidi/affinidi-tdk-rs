#!/usr/bin/env bash
# Verify the Rust toolchain version is consistent across the repo.
#
# `rust-toolchain.toml`'s `channel` is the single source of truth. Bumping it
# used to require hand-editing the same version into Cargo.toml's MSRV and every
# `toolchain:` pin scattered across .github/workflows/* (11 references across 6
# files at the time of writing). Miss one and CI silently builds on a different
# compiler than local dev. This check fails the build with a precise list of the
# stragglers so the bump stays a one-line edit + a green check.
#
# Rules:
#   - every `toolchain: "X"` in .github/workflows/* MUST equal the channel
#   - Cargo.toml's `rust-version` (workspace MSRV) MUST be <= the channel
#
# Portable to macOS bash 3.2 / BSD userland (no mapfile, no `sort -V`, no
# associative arrays).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [ -t 1 ]; then
  RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; YELLOW=$'\033[1;33m'; NC=$'\033[0m'
else
  RED=''; GREEN=''; YELLOW=''; NC=''
fi

extract_quoted() { # $1 = line containing  key: "value"  -> prints value
  printf '%s\n' "$1" | sed -E 's/.*"([^"]+)".*/\1/'
}

# returns 0 if $1 <= $2 (dotted numeric versions), via portable component sort
ver_le() {
  [ "$1" = "$2" ] && return 0
  local lowest
  lowest=$(printf '%s\n%s\n' "$1" "$2" | sort -t. -k1,1n -k2,2n -k3,3n | head -1)
  [ "$lowest" = "$1" ]
}

# --- source of truth -------------------------------------------------------
channel_line=$(grep -E '^[[:space:]]*channel[[:space:]]*=' rust-toolchain.toml | head -1 || true)
if [ -z "$channel_line" ]; then
  echo "${RED}error:${NC} could not find 'channel = ...' in rust-toolchain.toml" >&2
  exit 2
fi
channel=$(extract_quoted "$channel_line")
echo "Source of truth: rust-toolchain.toml channel = ${GREEN}${channel}${NC}"
echo ""

fail=0

# --- workflow toolchain pins ----------------------------------------------
# Matches both the shared-workflow `with: toolchain: "X"` form and the
# dtolnay/rust-toolchain `with: toolchain: "X"` form. The `uses:
# dtolnay/rust-toolchain@master` lines do NOT start with `toolchain:` so they
# are not matched.
while IFS= read -r hit; do
  [ -z "$hit" ] && continue
  file=$(printf '%s\n' "$hit" | cut -d: -f1)
  lineno=$(printf '%s\n' "$hit" | cut -d: -f2)
  content=$(printf '%s\n' "$hit" | cut -d: -f3-)
  ver=$(extract_quoted "$content")
  if [ "$ver" = "$channel" ]; then
    echo "  ${GREEN}ok${NC}   $file:$lineno -> $ver"
  else
    echo "  ${RED}DIFF${NC} $file:$lineno -> ${RED}$ver${NC} (expected $channel)"
    fail=1
  fi
done < <(grep -rnE '^[[:space:]]*toolchain:[[:space:]]*"' .github/workflows/ || true)

# --- workspace MSRV --------------------------------------------------------
rustver_line=$(grep -nE '^[[:space:]]*rust-version[[:space:]]*=' Cargo.toml | head -1 || true)
if [ -n "$rustver_line" ]; then
  rv_no=$(printf '%s\n' "$rustver_line" | cut -d: -f1)
  rv=$(extract_quoted "$rustver_line")
  if [ "$rv" = "$channel" ]; then
    echo "  ${GREEN}ok${NC}   Cargo.toml:$rv_no rust-version -> $rv"
  elif ver_le "$rv" "$channel"; then
    echo "  ${YELLOW}note${NC} Cargo.toml:$rv_no rust-version $rv < channel $channel (MSRV below toolchain, allowed)"
  else
    echo "  ${RED}DIFF${NC} Cargo.toml:$rv_no rust-version ${RED}$rv${NC} > channel $channel (MSRV above toolchain)"
    fail=1
  fi
fi

echo ""
if [ "$fail" -eq 0 ]; then
  echo "${GREEN}Toolchain in sync.${NC}"
else
  echo "${RED}Toolchain OUT OF SYNC.${NC} Update the flagged values to match rust-toolchain.toml's channel ($channel)."
  exit 1
fi

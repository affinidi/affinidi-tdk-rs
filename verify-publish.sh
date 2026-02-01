#!/bin/bash
# Verify all publishable crates can be packaged for crates.io
# This catches version mismatches, checksum conflicts, and missing deps
# that only surface during `cargo publish`

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Cache metadata once
METADATA=$(cargo metadata --format-version 1 --no-deps 2>/dev/null)

# Get all publishable crates in workspace order
CRATES=$(echo "$METADATA" | jq -r '.packages[] | select(.publish == null or .publish == [] or .publish == ["crates.io"]) | .name')

get_local_version() {
  echo "$METADATA" | jq -r ".packages[] | select(.name == \"$1\") | .version"
}

get_remote_version() {
  cargo search "$1" 2>/dev/null | head -1 | sed 's/.*= "\([^"]*\)".*/\1/'
}

show_publish_order() {
  echo -e "${CYAN}=== Publish Order (what needs publishing) ===${NC}"
  echo ""

  local needs_publish=0
  local can_publish=0

  for crate in $CRATES; do
    local_ver=$(get_local_version "$crate")
    remote_ver=$(get_remote_version "$crate")

    if [ "$local_ver" != "$remote_ver" ]; then
      needs_publish=$((needs_publish + 1))
      if cargo package -p "$crate" --allow-dirty >/dev/null 2>&1; then
        echo -e "${GREEN}✓ $crate${NC}: $remote_ver → $local_ver ${GREEN}(can publish now)${NC}"
        can_publish=$((can_publish + 1))
      else
        echo -e "${YELLOW}○ $crate${NC}: $remote_ver → $local_ver ${RED}(blocked)${NC}"
      fi
    fi
  done

  echo ""
  if [ $needs_publish -eq 0 ]; then
    echo -e "${GREEN}All crates are up to date!${NC}"
  else
    echo -e "Need to publish: $needs_publish (${GREEN}$can_publish ready${NC}, ${RED}$((needs_publish - can_publish)) blocked${NC})"
  fi
  echo ""
}

verify_crates() {
  echo -e "${CYAN}=== Verifying Publishable Crates ===${NC}"
  echo ""

  local failed=()
  local passed=()

  for crate in $CRATES; do
    echo -n "Checking $crate... "

    if cargo package -p "$crate" --allow-dirty >/dev/null 2>&1; then
      echo -e "${GREEN}OK${NC}"
      passed+=("$crate")
    else
      echo -e "${RED}FAILED${NC}"
      failed+=("$crate")
    fi
  done

  echo ""
  echo "================================"
  echo -e "${GREEN}Passed: ${#passed[@]}${NC}"
  echo -e "${RED}Failed: ${#failed[@]}${NC}"

  if [ ${#failed[@]} -gt 0 ]; then
    echo ""
    echo "Failed crates:"
    for crate in "${failed[@]}"; do
      echo "  - $crate"
    done
    echo ""
    echo "Run 'cargo package -p <crate> --allow-dirty' for details"
    return 1
  fi

  echo ""
  echo -e "${GREEN}All crates ready to publish!${NC}"
}

# Parse arguments
case "${1:-}" in
--order | -o)
  show_publish_order
  ;;
--verify | -v)
  verify_crates
  ;;
--help | -h)
  echo "Usage: $0 [--order|-o] [--verify|-v] [--help|-h]"
  echo ""
  echo "  --order, -o   Show what needs publishing with status"
  echo "  --verify, -v  Verify all crates can be packaged"
  echo "  --help, -h    Show this help"
  echo ""
  echo "Without arguments, shows order then verifies."
  ;;
*)
  show_publish_order
  verify_crates
  ;;
esac

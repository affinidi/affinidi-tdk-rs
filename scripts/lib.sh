# shellcheck shell=bash
# Shared preamble for the PR guards that attribute changed files to workspace
# crates: check-version-bumps.sh, check-publish-dry-run.sh, check-changelogs.sh.
#
# Source it; do not execute it. Each guard used to carry its own copy of this
# code, and the copies drifted: `is_source` excluded `fuzz/*` in one guard and
# not in another, and a `|| true` fix made in one copy was missing from its
# sibling until it bit (see the note in check-changelogs.sh). One copy means a
# fix lands in every guard at once.
#
# Provides:
#   ROOT                      repo root, symlinks resolved; the caller is cd'ed there
#   RED GREEN YELLOW CYAN NC  colour escapes (empty when stdout is not a tty)
#   guard_require_base REF    exit 2 unless REF resolves
#   guard_load_crates         sets ALL_CRATES / WORKSPACE_CRATES; exit 2 on a bad strip
#   publishable_crates        prints  name<TAB>dir  for publishable crates
#   is_source REL             0 if REL (path relative to a crate dir) is source
#   crate_of PATH             prints  pub<TAB>name<TAB>dir  of PATH's owner
#
# Portable to macOS bash 3.2 / BSD userland.

# `pwd -P` — resolve symlinks. `cargo metadata` always reports fully resolved
# manifest paths, so a plain `pwd` reached through a symlinked checkout (on
# macOS, anything under /tmp) yields a prefix that never matches and every
# path comparison silently misses. See the guard in guard_load_crates.
# BASH_SOURCE[0] is this file, so `..` is the repo root for every caller.
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$ROOT" || exit 2

# shellcheck disable=SC2034 # the colours are used by the sourcing guard
if [ -t 1 ]; then
  RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; YELLOW=$'\033[1;33m'; CYAN=$'\033[0;36m'; NC=$'\033[0m'
else
  RED=''; GREEN=''; YELLOW=''; CYAN=''; NC=''
fi

guard_require_base() { # $1 = base ref
  if ! git rev-parse --verify --quiet "$1" >/dev/null; then
    echo "${RED}error:${NC} base ref '$1' not found. Pass a reachable ref, e.g. origin/main." >&2
    exit 2
  fi
}

# ALL_CRATES: every workspace crate as  pub<TAB>name<TAB>relative-crate-dir
# lines, longest dir first so the most specific crate wins for nested manifests
# (e.g. affinidi-tdk vs affinidi-tdk/common). `pub` is 1 for publishable, 0
# otherwise.
#
# Non-publishable crates are included (not just publishable ones) so a file
# under a nested `publish = false` package (e.g. a tool crate nested inside a
# publishable crate's dir) is attributed to that nested package and skipped —
# rather than bubbling up to the publishable parent and demanding a spurious
# bump or dry-run for source that never reaches crates.io.
#
# WORKSPACE_CRATES holds the same lines in `cargo metadata` order, for callers
# that iterate every crate rather than attributing paths (stable report order).
guard_load_crates() {
  WORKSPACE_CRATES=$(cargo metadata --format-version 1 --no-deps 2>/dev/null \
    | jq -r '.packages[]
        | (if (.publish == null or .publish == ["crates.io"]) then "1" else "0" end) as $pub
        | "\($pub)\t\(.name)\t\(.manifest_path)"' \
    | sed "s|\t$ROOT/|\t|; s|/Cargo.toml\$||")
  ALL_CRATES=$(printf '%s\n' "$WORKSPACE_CRATES" \
    | awk -F'\t' 'NF { print length($3)"\t"$0 }' \
    | sort -rn \
    | cut -f2-)

  # A crate dir that is still absolute means the `$ROOT/` strip above did not
  # take, and every path comparison would then match nothing — the guard
  # passing while checking precisely zero crates. That is the failure mode
  # these guards exist to prevent, so refuse rather than report success.
  # Tested with awk, not `grep -E '(^|\t)/'`: POSIX ERE has no `\t` escape, so
  # GNU grep reads that as a literal `t` and the pattern becomes `(^|t)/` —
  # which matches an innocent `crates/trust/...` and fails the guard on every
  # run. (BSD grep and ugrep do treat it as a tab, so it passes locally and
  # fails in CI.) awk's -F'\t' is a real tab on every awk, and anchoring on the
  # last field is what we actually mean.
  if printf '%s\n' "$ALL_CRATES" | awk -F'\t' 'NF && $NF ~ /^\// { bad = 1 } END { exit !bad }'; then
    echo "${RED}error:${NC} crate paths did not resolve against ROOT ($ROOT)." >&2
    echo "The strip of \`cargo metadata\`'s manifest paths produced absolute dirs, so" >&2
    echo "nothing would be checked. Run this script from the repository itself rather" >&2
    echo "than through a symlink to it." >&2
    exit 2
  fi
}

# name<TAB>dir for publishable crates only, in `cargo metadata` order.
publishable_crates() {
  printf '%s\n' "$WORKSPACE_CRATES" | awk -F'\t' '$1 == "1" { print $2 "\t" $3 }'
}

# Classify a path (relative to a crate dir) as source-or-not. "Source" is
# anything EXCEPT tests/, benches/, examples/, fuzz/, *.md and CHANGELOG* —
# test-/doc-only changes get no bump, per repo convention. fuzz/ holds a
# detached, `publish = false` fuzz crate that never reaches crates.io.
is_source() {
  case "$1" in
    tests/*|*/tests/*) return 1 ;;
    benches/*|*/benches/*) return 1 ;;
    examples/*|*/examples/*) return 1 ;;
    fuzz/*|*/fuzz/*) return 1 ;;
    *.md) return 1 ;;
    CHANGELOG*|*/CHANGELOG*) return 1 ;;
    *) return 0 ;;
  esac
}

# Attribute a changed file to its most-specific crate dir (publishable or not).
crate_of() { # $1 = changed path -> prints "pub<TAB>name<TAB>dir" or nothing
  local path="$1" pub name dir
  while IFS=$'\t' read -r pub name dir; do
    [ -z "$dir" ] && continue
    case "$path" in
      "$dir"/*) printf '%s\t%s\t%s\n' "$pub" "$name" "$dir"; return 0 ;;
    esac
  done <<EOF
$ALL_CRATES
EOF
}

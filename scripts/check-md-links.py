#!/usr/bin/env python3
"""Offline link check for the repository's Markdown.

Fails when a tracked *.md file links to a path that does not exist in the
checkout. Two kinds of link are checked:

  * relative links — `[text](../other-crate/README.md)`, `![img](./x.png)`,
    reference definitions `[id]: ./path`, and `href=`/`src=` in inline HTML;
  * absolute links into THIS repository's main branch —
    `https://github.com/affinidi/affinidi-tdk-rs/(tree|blob)/main/<path>`.
    Crate READMEs are rendered on crates.io, where relative links break, so
    they use this form; it goes stale exactly like a relative link does when
    a directory moves.

Everything else (other hosts, mailto:, pure #anchors) is ignored: this check
needs no network and no build, so it can run in release-guards on every PR.
Fenced code blocks and inline code spans are skipped.

Why it exists: the core/identity/credentials reorganisation and the mediator's
move to its own repository left ~50 relative links and most README badges
pointing at directories that no longer exist (#1063), and nothing noticed.

Usage: python3 scripts/check-md-links.py
"""

import os
import re
import subprocess
import sys
from urllib.parse import unquote

ROOT = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
REPO_URL = re.compile(
    r"^https?://github\.com/affinidi/affinidi-tdk-rs/(?:tree|blob)/main/([^?#]*)"
)
INLINE = re.compile(r"!?\[(?:[^\[\]]|\[[^\]]*\])*\]\(\s*<?([^)\s>]+)>?(?:\s+\"[^\"]*\")?\s*\)")
REFDEF = re.compile(r"^\s{0,3}\[[^\]]+\]:\s*<?(\S+?)>?(?:\s+.*)?$")
HTML = re.compile(r"""(?:href|src)\s*=\s*["']([^"']+)["']""")
FENCE = re.compile(r"^\s{0,3}(```|~~~)")
CODESPAN = re.compile(r"(`+)(?:(?!\1).)+?\1")


def tracked_markdown():
    out = subprocess.run(
        ["git", "ls-files", "-z", "*.md"],
        cwd=ROOT, check=True, capture_output=True,
    ).stdout.decode()
    return [p for p in out.split("\0") if p]


def targets(text):
    in_fence = None
    for lineno, line in enumerate(text.splitlines(), 1):
        m = FENCE.match(line)
        if m:
            if in_fence is None:
                in_fence = m.group(1)
            elif m.group(1) == in_fence:
                in_fence = None
            continue
        if in_fence:
            continue
        line = CODESPAN.sub("", line)
        for rx in (INLINE, HTML):
            for m in rx.finditer(line):
                yield lineno, m.group(1)
        m = REFDEF.match(line)
        if m:
            yield lineno, m.group(1)


def check(md, lineno, target):
    """Return an error string, or None when the link resolves."""
    m = REPO_URL.match(target)
    if m:
        path = m.group(1).rstrip("/")
        full = os.path.join(ROOT, path)
    else:
        if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*:", target) or target.startswith("//"):
            return None  # another scheme / host: not checked offline
        path = target.split("#", 1)[0].split("?", 1)[0]
        if not path:
            return None  # same-page anchor
        if path.startswith("/"):
            full = os.path.join(ROOT, path.lstrip("/"))
        else:
            full = os.path.join(ROOT, os.path.dirname(md), path)
    full = os.path.normpath(unquote(full))
    if os.path.exists(full):
        return None
    return f"{md}:{lineno}: {target}"


def main():
    errors = []
    files = tracked_markdown()
    for md in files:
        with open(os.path.join(ROOT, md), encoding="utf-8") as fh:
            text = fh.read()
        for lineno, target in targets(text):
            err = check(md, lineno, target)
            if err:
                errors.append(err)
    if errors:
        print(f"Broken links ({len(errors)}) in tracked Markdown:")
        for e in errors:
            print(f"  {e}")
        print("\nFix the path. For a crate README (rendered on crates.io) prefer an")
        print("absolute https://github.com/affinidi/affinidi-tdk-rs/tree/main/... link.")
        return 1
    print(f"All repository links in {len(files)} Markdown files resolve.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

## Summary

<!-- What changes and why. Link issues with "Closes #N" (fully fixed) or "Part of #N". -->

## Behaviour changes for consumers

<!--
Services pin these crates loosely, so a change to send / ack / reconnect /
receive semantics is breaking for them even when no signature changes (R3.6).
List each one here AND in the crate's CHANGELOG. Write "None" if there are none.
-->

## Checklist

Merging to `main` publishes every crate whose version changed. CI runs the
same guards (`release-guards.yaml`); running them first saves a round trip.

- [ ] Every publishable crate whose source changed has a **version bump** in its
      `Cargo.toml` (0.x: a minor bump for breaking API or behaviour changes).
      `bash scripts/check-version-bumps.sh origin/main`
- [ ] Each bumped crate's `CHANGELOG.md` has a heading
      **`## [x.y.z] - YYYY-MM-DD`** for the new version (not `Unreleased`),
      with behaviour changes called out.
      `bash scripts/check-changelogs.sh origin/main`
- [ ] Sibling version requirements updated where a bump is breaking.
- [ ] A **new workspace crate** has a `[patch.crates-io]` entry in the root
      `Cargo.toml` and a `CHANGELOG.md`.
      `bash scripts/check-workspace-duplicates.sh`
- [ ] Toolchain / MSRV changes keep workflows and README strings in step.
      `bash scripts/check-toolchain-sync.sh`
- [ ] Markdown links resolve. `python3 scripts/check-md-links.py`
- [ ] `cargo fmt --all`, `cargo clippy -p <crates> --all-targets --all-features -- -D warnings`
      and `cargo test -p <crates>` pass locally.
- [ ] Commits are signed off (`git commit -s`).
- [ ] For `crates/messaging/`: sends still report the real write result, every
      drop/reconnect still publishes connection state, and nothing new acks a
      message before its handler has processed it.

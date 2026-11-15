# Contributing

When contributing to this repository, please first discuss the change you wish to
make by creating a new [GitHub issue](https://github.com/affinidi/affinidi-tdk-rs/issues/new).

## Development requirements

- Rust 1.95.0, 2024 edition. `rust-toolchain.toml` pins the toolchain, so
  `rustup` installs the right one on first build.
- `jq` and `python3` for the guard scripts below.
- Native libraries used by some crates: `libssl-dev` and `libdbus-1-dev` on
  Debian/Ubuntu (the text client also needs `libchafa-dev`).

The mediator, which needs Redis, lives in its own repository:
[affinidi/affinidi-messaging-mediator](https://github.com/affinidi/affinidi-messaging-mediator).

## How a change gets released

**Merging to `main` publishes.** `release.yaml` runs on every push to `main`
and publishes each workspace crate whose version is not yet on crates.io. There
is no separate release step, so every PR has to be releasable as it stands.
That is what the rules below are for.

1. **Source change ⇒ version bump.** If you change anything under a
   publishable crate's directory other than `tests/`, `benches/`, `examples/`,
   `fuzz/`, `*.md` or `CHANGELOG*`, bump that crate's `version` in its
   `Cargo.toml`. Otherwise main holds source that crates.io never gets, and the
   next release of a dependent can fail to build against the stale published
   copy. All crates are 0.x: bump the **minor** for a breaking change to the
   public API *or* to behaviour (see [ADR 0003](docs/adr/0003-public-api-semver-policy.md)),
   the patch otherwise.
2. **Version bump ⇒ changelog entry.** The crate's `CHANGELOG.md` gets a new
   section headed exactly

   ```markdown
   ## [x.y.z] - YYYY-MM-DD
   ```

   newest first, with a one-line summary as its first line. Do not use
   `Unreleased` for a version: merging publishes it.
3. **Call out behaviour changes.** Services pin these crates loosely, so a
   change to send / ack / reconnect / receive semantics is breaking for them
   even when no signature changes. Say so in the changelog and in the PR.
4. **Keep siblings consistent.** When a bump is breaking, update the version
   requirement in the workspace crates that depend on it. A new workspace crate
   needs a `[patch.crates-io]` entry in the root `Cargo.toml` (otherwise cargo
   can build the published copy alongside the local one) and its own
   `CHANGELOG.md`.

## Before you push

These are the build-free guards `release-guards.yaml` runs on every PR:

```bash
bash scripts/check-version-bumps.sh origin/main   # rule 1
bash scripts/check-changelogs.sh origin/main      # rule 2
bash scripts/check-workspace-duplicates.sh        # rule 4: patch table covers every member
bash scripts/check-toolchain-sync.sh              # toolchain pins and MSRV strings agree
python3 scripts/check-md-links.py                 # Markdown links resolve
```

and the build checks for the crates you touched:

```bash
cargo fmt --all
cargo clippy -p <crate> --all-targets --all-features -- -D warnings
cargo test -p <crate> --all-features
```

`publish-dry-run.yaml` additionally runs `cargo publish --dry-run` for each
changed crate (`scripts/check-publish-dry-run.sh`); it catches failures that
only appear when a crate is built alone, with default features, against
crates.io.

## Pull requests

- Use a conventional-commit title naming the crates and new versions, e.g.
  `fix(messaging-sdk)!: … (0.49.0)`. PRs are squash-merged.
- Sign off every commit (`git commit -s`, DCO).
- Fill in the PR template's checklist; it is the list above.
- Changes under `.github/`, `scripts/` and `crates/messaging/` need a code-owner
  review (`.github/CODEOWNERS`).

### Code quality expectations

1. The CI checks pass.
2. New behaviour is covered by tests; integration tests run against real
   components (the in-process fixtures in `affinidi-tdk-test-support` and the
   mediator repository's `affinidi-messaging-test-mediator` need no external
   services).
3. Comments explain *why* — the constraint, the incident, the spec clause —
   rather than restating what the code does.
4. Names are simple and unambiguous.

## Code of Conduct

### Our Pledge

In the interest of fostering an open and welcoming environment, we as
contributors and maintainers pledge to make participation in our project and
our community a harassment-free experience for everyone, regardless of age, body
size, disability, ethnicity, gender identity and expression, level of experience,
nationality, personal appearance, race, religion, or sexual identity and
orientation.

### Our Standards

Examples of behavior that contributes to creating a positive environment
include:

- Using welcoming and inclusive language
- Being respectful of differing viewpoints and experiences
- Gracefully accepting constructive criticism
- Focusing on what is best for the community
- Showing empathy towards other community members
- Keeping code review about logic rather than formatting: `cargo fmt` and
  `clippy` settle style, so propose a lint change instead of repeating a style
  comment.

Examples of unacceptable behavior by participants include:

- The use of sexualized language or imagery and unwelcome sexual attention or
  advances
- Trolling, insulting/derogatory comments, and personal or political attacks
- Public or private harassment
- Publishing others' private information, such as a physical or electronic
  address, without explicit permission
- Other conduct which could reasonably be considered inappropriate in a
  professional setting

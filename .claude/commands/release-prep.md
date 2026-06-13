# Release Prep

Cut a new fuzzd release: finalize CHANGELOG, bump version, update benchmark table,
run the full local CI suite, then tag and push. Supply the version as an argument,
e.g. `/release-prep 0.13.0`.

Versioning rules (from CHANGELOG.md header):
- **MAJOR** = breaking CLI/API change
- **MINOR** = new signals or detection capabilities
- **PATCH** = bug fixes and performance improvements

## Phase 0 — Read current state (parallel)

- `CHANGELOG.md` — [Unreleased] section (everything that will go into this release)
- `Cargo.toml` — current version string
- `bench/README.md` — version table (confirm the new version column is present)
- `README.md` — version references ("Current release: vX.Y.Z", binary download URL line)

## Phase 1 — Validate the version number

Before making any changes, confirm the version is appropriate:
- If any new `Signal` variant was added, or detection rate improved, it must be MINOR or higher
- If any `--flag` was removed or renamed, or `Finding` / `BenchmarkReport` JSON shape changed, it must be MAJOR
- PATCH is only correct when no signal, no CLI, and no API shape changed

If the supplied version seems wrong, say so before continuing.

## Phase 2 — Finalize `CHANGELOG.md`

Promote the [Unreleased] section to the new version:

```markdown
## [X.Y.Z] — YYYY-MM-DD

### Added
...

### Changed
...

### Fixed
...
```

Rules:
- Date is today's date in YYYY-MM-DD format
- Keep the existing [Unreleased] header above the new section, empty (ready for the next cycle)
- Do NOT reorder or rewrite existing entries — only add the version header and date

## Phase 3 — Bump `Cargo.toml`

Update the `version` field:
```toml
version = "X.Y.Z"
```

## Phase 4 — Update `bench/README.md`

Confirm the version table has a column for the new version. If it doesn't, add one.
If detection numbers are unchanged from the previous version, copy them and add a
footnote explaining why (same as the v0.12/v0.13 pattern already in the file).

If detection improved, record the new numbers from the most recent benchmark run.

## Phase 5 — Update `README.md` version references

Search for the current version string in README.md and update it:
- The "Current release: **vX.Y.Z**" line in the Roadmap section
- The "Pre-built binaries ... available from vX.Y.Z" line in Quick Start
- Any other hardcoded version references

## Phase 6 — Run full local CI suite

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
cargo build --release
./target/release/fuzzd benchmark --schema bench/mcptox_representative.json --output json
./target/release/fuzzd benchmark --schema bench/mcptox_actual.json --output json
```

All must be green. Record the benchmark numbers — they go into the PR description.

## Phase 7 — Commit, tag, and push

```bash
git add Cargo.toml Cargo.lock CHANGELOG.md bench/README.md README.md
git commit -m "chore: release vX.Y.Z"
git tag -a vX.Y.Z -m "fuzzd vX.Y.Z"
git push origin main
git push origin vX.Y.Z
```

The `release.yml` workflow triggers on the tag and builds cross-platform binaries
(Linux x86_64, macOS x86_64 + aarch64, Windows x86_64).

## Phase 8 — Verify the release

After pushing the tag, confirm:
- GitHub Actions `release` workflow started and all matrix jobs are green
- The GitHub Release page has the correct binaries attached
- `cargo install --git https://github.com/ksek87/fuzzd` resolves to the new version

## Checklist

- [ ] Version number validated against versioning rules
- [ ] [Unreleased] promoted to `[X.Y.Z] — YYYY-MM-DD` in CHANGELOG.md
- [ ] Empty [Unreleased] section left above for the next cycle
- [ ] `Cargo.toml` version bumped
- [ ] `bench/README.md` version column present with correct numbers
- [ ] `README.md` version references updated
- [ ] `cargo fmt --check` clean
- [ ] `cargo clippy -- -D warnings` clean
- [ ] `cargo test` passes
- [ ] Benchmark: 0 FP on actual dataset, 0 FN on representative fixture
- [ ] Commit, tag, and push complete
- [ ] `release.yml` CI green and binaries attached to GitHub Release

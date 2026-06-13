# Documentation Update

Audit fuzzd's documentation against the current codebase and fix every gap or
stale number you find. Run this after any release or significant feature merge.

## Phase 0 — Extract ground-truth counts (parallel reads)

Read these files to get the canonical numbers before touching any docs:

- `src/fuzzer/mod.rs` — count `Signal` enum variants → total signal count
- `src/fuzzer/description.rs` — count AC needle strings → description pattern count
- `src/fuzzer/response.rs` — count response pattern strings → response pattern count
- `src/fuzzer/payloads.rs` — count injection payload categories and integer boundary values
- `src/fuzzer/description.rs` — scan for multilingual pattern strings (Chinese, Japanese, Korean, Russian, Arabic)
- `src/fuzzer/description.rs` — scan `credential_reference` needles, especially API key prefixes (AKIA, ghp_, sk-ant-, xoxb-, etc.)
- `src/cli/mod.rs` — `AttackModule::all()` → default module set
- `corpus/tool_poisoning/`, `corpus/tool_shadowing/`, `corpus/rug_pull/` — count JSON files per category → corpus record counts
- `CHANGELOG.md` [Unreleased] section — features shipped but not yet reflected in versioned docs
- `src/config.rs` (if present) — platform config paths supported by `auto_detect()`

Record every number you find. These are the facts the docs must match.

## Phase 1 — Audit documentation (parallel reads)

Read these files simultaneously and note every gap or stale value:

- `README.md` — full file
- `bench/README.md` — full file
- `CONTRIBUTING.md` — full file
- `CHANGELOG.md` — [Unreleased] and most recent version section

For each file, flag:

1. **Stale counts** — signal count, AC needle count, response pattern count, injection
   payload category count, corpus record count anywhere in prose or tables
2. **Missing signals** — the signal table in README.md must list all variants from `Signal`
   enum; cross-check against the bench/README.md signal distribution table too
3. **Missing features** — features in CHANGELOG.md [Unreleased] not yet reflected in
   README.md Usage, Quick Start, or roadmap table
4. **Stale architecture diagram** — source files listed in the diagram must match actual
   `src/` tree; module counts (signals, patterns, payload categories) in inline comments
   must match Phase 0 counts
5. **Roadmap status** — features described as "Active" or "Future" that have since shipped
6. **Benchmark version table** — bench/README.md must have a column for every release
   that changed detection or signals; check whether the latest CHANGELOG version is present
7. **CI gate documentation** — CONTRIBUTING.md must reflect all CI jobs that can block a PR
8. **New dependency rows** — if `Cargo.toml` has crates not listed in the README dependency
   table, they belong there

## Phase 2 — Apply fixes

Fix every gap found in Phase 1. Work file by file:

### README.md

- Update all stale counts (detection pass count, AC needle count, signal count in prose
  and the pass descriptions, injection payload categories, corpus record counts)
- Add any missing rows to the signal table (one row per `Signal` variant); use the
  bench/README.md signal table as the authoritative description source
- Update `credential_reference` description to include API key prefix examples if the
  code has them
- Add missing `--from-config`, `--attacks peer`, or other new flags to Quick Start and
  Usage sections
- Update the architecture diagram: add new `src/*.rs` files, fix module counts in inline
  comments
- Mark shipped roadmap items as ✅ Shipped; new active themes as 🔜 Active
- Add new dependency rows if crates are missing from the table

### bench/README.md

- Add a column for the current version to the detection-rate table (copy the previous
  column's numbers if detection is unchanged; note why in the version footnote)
- Update the section header counts (AC patterns, total signals)
- Update the Pass 1 description pattern count
- Update signal table rows where descriptions have changed (e.g. new credential needles)

### CHANGELOG.md

- Add missing entries for features that were implemented but not logged; each entry
  must include the issue/PR number if known
- Do NOT modify the format of existing entries or reorder sections

### CONTRIBUTING.md

- Update the "Before opening a PR" checklist to match the actual CI jobs
- If new CI gates were added, document what each gate checks and what the failure
  threshold is

## Output

After applying all fixes, produce a brief summary:
- Files changed (list)
- Specific gaps fixed (one line each)
- Any gap you skipped and why

Do not create new documentation files. Only update existing ones.

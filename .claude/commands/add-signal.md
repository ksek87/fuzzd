# Add Detection Signal

Add a new detection signal end-to-end: research citation, code changes across all
required sites, benchmark validation, corpus record, and CHANGELOG entry. Supply the
signal name and research basis as arguments, e.g.:
`/add-signal MemoryPoisoning "Chen et al. arXiv:2407.XXXXX"`

## Phase 0 — Read the required context (parallel)

Read these files before writing anything:

- `src/fuzzer/mod.rs` — understand Signal enum, ALL slice, and all impl blocks you must update
- `src/fuzzer/description.rs` — see existing AC needle style and how patterns are grouped
- `src/fuzzer/response.rs` — if the new signal fires on tool *responses*, see existing response patterns
- `src/corpus/schema.rs` — AttackRecord schema for the corpus record you'll add at the end
- `corpus/tool_poisoning/TPA-001.json` — use as template for the new corpus record

## Phase 1 — Decide scope

Before touching code, establish:

1. **Signal name** — PascalCase enum variant (e.g. `MemoryPoisoning`); snake_case string for `as_str()` (e.g. `memory_poisoning`)
2. **FUZZD-NNN ID** — next available number after the last entry in `Signal::ALL`
3. **Severity** — Critical / High / Medium / Low (derive from research classification)
4. **Scanner target** — description AC needle, response AC needle, structural heuristic, or runtime (sequence analyzer / protocol fuzzer)
5. **Research citation** — paper title, arXiv ID or URL, specific finding that motivates the signal

If the signal fires only at runtime (e.g. sequence analyzer or protocol fuzzer output), note
it clearly — it gets an enum variant and all the impl methods, but NO AC needle added to
description.rs or response.rs.

## Phase 2 — Update `src/fuzzer/mod.rs` (7 required sites)

Every site must be updated or the build will fail (clippy -D warnings, exhaustive match).

### 2a. `Signal` enum
Add the new variant with a doc comment explaining what it detects, the research basis,
and any CVE or paper citation. Insert it in logical grouping order, or at the end before
runtime-only signals.

```rust
/// One-sentence description of what this signal detects.
/// Research basis: Author et al., Title (Year) — arxiv:NNNN.NNNNN.
NewSignalName,
```

### 2b. `Signal::ALL`
Append the new variant at the end of the slice (maintaining FUZZD-NNN order):
```rust
Self::NewSignalName,
```

### 2c. `as_str()`
Add a match arm returning the snake_case string:
```rust
Self::NewSignalName => "new_signal_name",
```

### 2d. `rule_id()`
Add a match arm returning the FUZZD-NNN identifier:
```rust
Self::NewSignalName => "FUZZD-NNN",
```

### 2e. `description()`
Add a match arm with a one-sentence description suitable for SARIF `shortDescription`:
```rust
Self::NewSignalName => "One sentence describing the attack this signal detects.",
```

### 2f. `tags()`
Add a match arm returning the OWASP MCP Top 10, OWASP Agentic Top 10 (ASI series),
and CWE tags. Use the closest existing entry as a reference for which tags apply:
```rust
Self::NewSignalName => &["OWASP:MCP-NN", "OWASP:ASINNN", "CWE-NNN"],
```

### 2g. `Display` / `impl fmt::Display`
No change needed — `Display` delegates to `as_str()`, which you already updated.

## Phase 3 — Add AC needles (skip if runtime-only signal)

### If the signal fires on tool *descriptions* (`src/fuzzer/description.rs`):
Add needle strings to the existing `DESCRIPTION_PATTERNS` array (or equivalent). Group
them with similar needles; add a comment citing the research source. Keep needles
lowercase — the scanner lowercases input before matching.

```rust
// NewSignalName — Author et al. (Year)
("needle phrase one", Signal::NewSignalName, Severity::High),
("needle phrase two", Signal::NewSignalName, Severity::High),
```

### If the signal fires on tool *responses* (`src/fuzzer/response.rs`):
Add to the `RESPONSE_PATTERNS` array in the same style.

Run `cargo clippy --all-targets -- -D warnings` after this step. Zero warnings allowed.

## Phase 4 — Benchmark gate

Run the benchmark before and after your changes to confirm:
1. Detection rate does not decrease (no regressions)
2. False positive rate stays at 0 / 20

```bash
cargo build --release
./target/release/fuzzd benchmark --schema bench/mcptox_actual.json --output json
./target/release/fuzzd benchmark --schema bench/mcptox_representative.json --output json
```

Record the before/after numbers. If you introduced a regression, fix the needles before continuing.

If the new signal improves recall on the actual dataset, also update `bench/README.md`:
add the improvement to the v0.13 (or current unreleased) column footnote.

## Phase 5 — Add a corpus record

Add at least one corpus record that exercises the new signal. Use the next available
TPA-NNN (or appropriate category) number.

```bash
fuzzd corpus validate ./corpus/tool_poisoning/TPA-NNN.json
```

The record must have `source` and `source_url` fields citing the research. Severity must
match the signal's severity.

## Phase 6 — CHANGELOG entry

Add an entry to the [Unreleased] → Added section in `CHANGELOG.md`:

```
- **FUZZD-NNN `NewSignalName`** — one sentence description of what it detects.
  Research basis: Author et al., Title (Year) — arxiv:NNNN / URL. Adds N AC needles
  targeting X attack class. Benchmark impact: +N.Npp on actual dataset (#issue).
```

## Phase 7 — Run full CI locally

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
./bench/run.sh
```

All must pass before opening a PR. The CI `benchmark` job enforces zero FP and zero FN
on the representative fixture — any regression blocks the build.

## Checklist

Before opening the PR, confirm:
- [ ] `Signal` enum has new variant with doc comment + research citation
- [ ] `Signal::ALL` slice updated
- [ ] `as_str()` arm added
- [ ] `rule_id()` arm added (FUZZD-NNN)
- [ ] `description()` arm added
- [ ] `tags()` arm added (OWASP + CWE)
- [ ] AC needles added (or noted as runtime-only)
- [ ] `cargo clippy -- -D warnings` clean
- [ ] `cargo test` passes
- [ ] Benchmark before/after recorded, no regression, 0 FP
- [ ] Corpus record added and validated
- [ ] CHANGELOG.md entry added
- [ ] `/docs-update` run to sync README.md signal table and counts

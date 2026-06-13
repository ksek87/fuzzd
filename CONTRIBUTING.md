# Contributing to fuzzd

fuzzd is an open MCP security scanner. The attack surface for agentic AI is evolving faster than any single team can track — contributions that extend the corpus and sharpen detection signals have direct, measurable impact.

## Types of contribution

### 1. Attack corpus records (highest leverage)

Corpus records are the highest-leverage contribution. Each record encodes a known MCP attack pattern as a reproducible, citable test case that drives benchmark regressions and new detection needles.

**Process:**
1. Find an attack pattern documented in published research (academic paper, vendor blog post, CVE, or security conference talk)
2. Fill out the full `AttackRecord` schema — use `corpus/tool_poisoning/TPA-001.json` as a template
3. Validate: `fuzzd corpus validate ./my-attack.json`
4. Measure: run `./bench/run.sh` before and after — include the delta in your PR description
5. Open a PR using the **Corpus Record** issue template

**Ground rules:**
- Every record must cite a published source (`source` and `source_url` fields are required)
- No unsourced payloads — the corpus is a research artifact, not a collection of guesses
- Severity must reflect the research classification, not personal assessment

### 2. Detection signals

New `Signal` variants or additional AC pattern needles for existing signals.

**Process:**
1. Open a feature request issue first — describe the attack class, cite the research, state the expected benchmark impact
2. Add pattern needles to `src/fuzzer/description.rs` (for tool description attacks) or `src/fuzzer/response.rs` (for response-phase attacks)
3. New `Signal` variants require updates to: the `Signal` enum, `Signal::ALL`, `as_str()`, `rule_id()`, `description()`, and `Display`
4. Run `./bench/run.sh` — new signals must improve detection rate without introducing false positives on the clean-tools baseline (0 FP is a hard constraint)
5. Add corpus records for any new signal

**Detection rate target:** every merged signal must improve `MCPTox actual` recall. Signals that don't move the needle will be asked to wait until the corpus is extended.

### 3. Protocol and infrastructure

Transport, session, harness, reporter, and CLI changes.

**Process:**
1. Open an issue first for anything touching the protocol layer or public API
2. All unit tests use `MockTransport` from `src/testutil.rs` — no real network, no child processes
3. Session tests use `Session::ready(transport)` or set `state = SessionState::Ready` directly
4. Every `tokio::spawn` must store its `JoinHandle` and abort on cleanup (see `CLAUDE.md`)
5. Zero `unsafe` blocks — the entire codebase is safe Rust

## Before opening a PR

Run all four checks locally:

```bash
cargo fmt --check
cargo clippy -- -D warnings
cargo test
./bench/run.sh   # always required — CI enforces this gate on every push
```

The `benchmark` CI job enforces three hard gates on every push and PR:
1. Representative fixture: zero false negatives (recall must be 1.0)
2. Combined representative + clean dataset: zero false negatives and precision ≥ 0.90
3. Actual MCPTox dataset: zero false positives

If your change affects detection (new signals, new patterns, changed scoring), include the before/after detection rate in your PR description. The format used in CHANGELOG.md entries (`84.7% → 89.0% (+4.3pp)`) is the convention.

## Benchmark fixture

`bench/mcptox_actual.json` is a flat array of 485 MCP tool definitions from 45 live servers, labeled with `_meta.is_attack` and `_meta.risk_category`. Do not modify this file in PRs — it is the stable regression fixture. If you have new labeled data, open a separate discussion.

## Test infrastructure

`src/testutil.rs` contains all shared test helpers:
- `MockTransport` — in-memory transport, no network
- `ok_response()` — generic JSON-RPC success response
- `init_response()` — MCP initialize response
- `tools_response(tools)` — tools/list response from a `Vec<ToolDefinition>`

Never duplicate these inline in a test file. If you need a new helper that two or more tests use, add it to `testutil.rs`.

## Commit and PR conventions

- One logical change per PR — corpus records, a new signal, or an infra fix; not all three
- PR title: imperative mood, ≤ 70 characters (`Add FUZZD-024 credential harvesting signal`)
- Link the issue in the PR description (`Closes #NNN`)
- Use the PR template checklist

## Questions

Open a GitHub Discussion, or file an issue with the `type/question` label.

# Changelog

All notable changes to fuzzd are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html):
**MAJOR** = breaking CLI/API change; **MINOR** = new signals or detection capabilities; **PATCH** = bug fixes and performance improvements.

Releases are git-tagged and carry pre-built binaries from **v0.12.0** onward. Entries below v0.12.0 document pre-tag development history and are not individually downloadable. Roadmap *themes* (e.g. "Neural Semantic Layer") are tracked independently of release numbers — see [issue #26](https://github.com/ksek87/fuzzd/issues/26).

---

## [Unreleased]

### Added
- **JSON-RPC protocol edge-case fuzzer** (`fuzzer/protocol.rs`, #21) — the `protocol` attack module is now implemented (previously advertised in `--attacks` but a no-op). Sends malformed envelopes (missing `jsonrpc`, wrong version, non-scalar `id`, missing/unknown method, oversized method name) and lifecycle-ordering violations (`tools/call`/`tools/list` before `initialize`, second `initialize`) to a live stdio server, each against a freshly spawned session, and classifies the response: a well-formed JSON-RPC error is the only acceptable outcome; a crash is Critical, a hang High, a malformed/over-accepting reply Medium, an abrupt close Low.
- FUZZD-024 `ProtocolViolation` signal — carries protocol-fuzzer findings through the existing reporter/SARIF pipeline.
- **Stateful sequence analyzer** (`analyzer/`, #13/#14) — the foundation for the Agentic Chain Fuzzer theme. A `SequenceObserver` records the ordered tool-call sequence (tool + runtime arguments); the analyzer detects cross-step anomalies that the static scanner cannot see — credential paths and external URLs in *runtime arguments*, tool calls *injected* relative to a baseline run, and *cross-tool contamination* (a baseline tool's arguments gaining a sensitive value). `diff()` compares baseline vs. adversarial runs; a CVSS-inspired scorer maps each anomaly to a severity. `SequenceFinding` carries step/reproduction context and converts to the flat `Finding` for reporting. Exercised on recorded and synthetic sequences; the live executor (#15) and mock-peer injection (#16) that drive adversarial runs build on this.
- FUZZD-025 `UnexpectedToolSequence`, FUZZD-026 `RuntimeCredentialAccess`, FUZZD-027 `UnexpectedNetworkCall` signals — carry sequence-analyzer findings through the reporter; cross-tool contamination reuses the existing FUZZD-007.

### Changed
- `run_audit` no longer requires a successful `initialize`/`tools/list` handshake when only `--attacks protocol` is requested — protocol fuzzing must be able to probe a server that never completes initialization, since that is precisely its job.

---

## [0.12.0] — 2026-06-04

First git-tagged release with pre-built binaries (Linux x86_64, macOS x86_64 + aarch64, Windows x86_64).

### Added
- FUZZD-022 `ResponseContextInvalidation` — detects injected text in tool responses that dismisses legitimate output (`system note:`, `<system-reminder>`, "actual instructions follow"). Anchored to CVE-2025-55284 and GH anthropics/claude-code#22915; formalised as *Observation Injection* by WithSecure Labs (2023).
- FUZZD-023 `ForcedReexecution` — detects loop-injection payloads in tool responses ("result was incomplete", "call this tool again"). Anchored to Chen et al. arXiv:2407.20859 (*Malfunction Amplification*, 15.3% → 59.4% agent failure rate) and Liu et al. arXiv:2601.10955 (up to 658× per-query cost inflation).
- `Signal::ALL` const slice — canonical ordered list of all 23 variants; `sarif_rules()` derives from it, eliminating divergence risk when new signals are added.
- Stable SARIF fingerprint hash — 31-polynomial byte hash replaces ASCII-filter discriminator; all-Unicode matched text (e.g. zero-width characters) no longer falls back to the no-discriminator form.
- TPA-022 and TPA-023 corpus records.

### Changed
- `render_markdown`: single `partition()` pass replaces two separate filter passes.
- `sarif_rules()`: `Signal::ALL.iter()` replaces `vec![...]` — one heap allocation instead of two.
- `render_json`: `signal.as_str()` replaces `signal.to_string()` — static ref, no allocation.
- `scan_with_automaton`: `HashSet::with_capacity(patterns.len())` avoids rehash growth.
- `stale_entries`: uses `f.id()` key format, consistent with `is_suppressed` and `build_key_set`.

---

## [0.11.0] — 2026-05-26

**MCPTox actual dataset: 89.0% → 90.7% (+1.7pp) | False positives: 0 / 20**

### Added
- 6 new AC needles for soft-modal fake-prerequisite enforcement: consequence-threat framing ("failure to do so will", "skipping this step will cause") — attack language designed to avoid triggering explicit "MUST FIRST" heuristics. Research basis: Wang et al. (MCPTox 2025); Perez & Ribeiro (2022) soft-language evasion.

### Changed
- `Signal` and `Severity` now derive `Copy` — eliminates `.clone()` calls in the hot-path scanner; `Finding` construction never heap-allocates for these fields.
- TF-IDF semantic pass reduced from two O(tokens) passes to one — term-frequency counts and vocabulary-overlap guard computed in a single pass with early-exit before cosine computation.
- `scan_schema()` defers path string formatting until a content-bearing key is found — structural scalar values (e.g. `"type": "string"`) produce no string allocation.
- `rule_id()` and `description()` moved onto `Signal` enum — reporter no longer maintains separate local match functions.

### Fixed
- Stale `.tmp` file cleanup on rename failure in `SuppressConfig::append`.
- Duplicate SARIF partial fingerprints when same `(tool, signal)` appeared from multiple scanners.
- Unbounded stdio line buffer — 1 MiB guard disconnects on oversized lines.
- Unbounded HTTP SSE buffer — 64 MiB guard disconnects on oversized SSE payloads.

---

## [0.10.0] — 2026-05-25

**MCPTox actual dataset: 84.7% → 89.0% (+4.3pp) | False positives: 0 / 20**

### Added
- **Pass 4 — TF-IDF semantic similarity**: cosine similarity against six abstract attack archetypes (recipient-substitution, BCC-intercept, universal-relay, argument-override, append-inject-all, private-data-exfil). Targets domain-specific relay/redirect vocabulary that AC needles cannot enumerate. No model download; vocabulary built from archetype texts at first call via `OnceLock`. Fires at Low severity.
- **Pass 2 — Structural sliding-window heuristic**: 10-word window detects universal-scope relay/inclusion constructs (relay verb + quantifier + communication noun). Fires `message_hijacking` / `argument_interception` at Medium.
- **Pass 3 — GloVe 50d semantic verb scanner**: detects "when (using|calling) X, VERB" attack constructions where VERB is a cosine-similarity neighbour (≥ 0.65) of a known attack verb — catches synonyms (reroute, supplant, mutate) not enumerable as AC needles. Fires at Medium.
- Privacy Leakage archetype added to TF-IDF pass.
- Argument override / substitution detection patterns.
- Shared lowercase copy — all four passes share a single pre-computed lowercase of the description text.

### Changed
- Benchmark methodology updated to duplicate-aware counting — each of the 485 tool entries in `mcptox_actual.json` scored independently.
- `mcptox_actual.json` restructured to flat array format with `_meta.is_attack` and `_meta.risk_category` labels.

---

## [0.9.0] — 2026-05-24

**MCPTox actual dataset: baseline established at 84.7% | False positives: 0 / 20**

### Added
- 7 new detection signals (FUZZD-015 through FUZZD-021):
  - `ansi_escape_obfuscation` — ANSI terminal escape sequences hiding instructions (Trail of Bits, Apr 2025)
  - `tool_selection_bias` — credibility framing to bias LLM tool selection ("deprecated", "recommended version")
  - `identity_impersonation` — unverifiable authority claims ("official Anthropic", "elevated trust")
  - `raw_content_passthrough` — instructions to pass retrieved content unfiltered, maximising injection surface
  - `value_substitution` — normalisation-disguised argument value substitution ("canonical form", "convert all X→Y")
  - `tool_enumeration_recon` — instructions to enumerate all available tools for reconnaissance
  - `sampling_pipeline_hijack` — tool inserted as mandatory intermediary for all agent queries via sampling endpoint
- `inputSchema` field scanning — `parameter.description`, enum values, and default values scanned for injection payloads. Addresses the "Poison Everywhere" finding (CyberArk, 2025) that description-only scanners miss `inputSchema` attacks.
- `rule_id()` and `description()` methods on `Signal` enum — SARIF driver derives metadata from the enum directly.

### Changed
- AC pattern count increased from 46 to 125 across 21 signals.

---

## [0.8.0] — 2026-05-24

### Added
- Suppression workflow — `.fuzzd/suppress.toml` for persistent false-positive management.
- `fuzzd suppress` subcommand — adds suppress entries with mandatory reason strings; validates entries against current findings.
- `fuzzd suppress --stale` — reports entries with no corresponding live finding (auto-cleanup signal).
- Stable finding IDs — `"<tool>/<signal>"` used as SARIF `partialFingerprints` key for persistent GitHub Code Scanning dismissals.
- SARIF `suppressions` array populated for suppressed findings (compatible with GitHub Advanced Security).
- `SuppressConfig::load_or_empty` — no error if suppress file absent; zero-config by default.
- Atomic suppress file writes via write-tmp + rename — prevents corruption on crash.

---

## [0.7.0] — 2026-05-23

### Added
- SARIF 2.1.0 output (`--output sarif`) — compatible with GitHub Code Scanning, GitLab SAST, and any SARIF 2.1 consumer.
- JSON output (`--output json`) — structured findings for programmatic consumption.
- Markdown output (`--output markdown`, default) — human-readable terminal output with severity, matched text, and corpus refs.
- `fuzzd audit` command — live session against a running MCP server (stdio or HTTP/SSE transport) with full scan on tool enumeration.
- `fuzzd benchmark` subcommand — programmatic benchmark runner with all output formats.
- `BenchmarkReport` — precision, recall, F1, TP/FP/FN/TN counts.
- `Observer<T>` — wraps `Harness<T>`, intercepts every `call_tool` response and runs `ResponseScanner` transparently.
- `Scanner` struct — lazy-initialised with `OnceLock<AhoCorasick>`; automaton built once, reused across all calls.
- Exit code 1 on any Critical or High finding — enables CI pipeline gating.

### Changed
- `ArgumentFuzzer` and `Observer` wired into the `run_audit` command.
- Shared scanner infrastructure extracted to `fuzzer/mod.rs` — description and response scanners share `Pattern`, `Scanner`, and `scan_with_automaton`.

---

## [0.6.0] — 2026-05-16

### Added
- `ResponseScanner` — scans `CallToolResult` text content for 20 embedded prompt-injection patterns.
- FUZZD-014 `EmbeddedInstruction` signal — prompt-injection via tool response (indirect injection / MCP-UPD attack class).
- Response patterns: classic override ("ignore previous instructions"), indirect injection ("before responding to the user"), cross-tool injection ("you must now call"), model-specific tokens (`<|system|>`, `<<SYS>>`), HTML injection tags in response context.
- `runner/observer.rs` with full test coverage.

---

## [0.5.0] — 2026-05-14

### Added
- 15 new corpus records (TPA-013–TPA-021, TS-001–003, RUG-001–003): MCPTox paradigms, Invariant Labs XML injection, MCP-UPD parasitic toolchain, Trivial Trojans, message hijacking, unicode obfuscation.
- FUZZD-012 `MessageHijacking` — recipient substitution, BCC injection, proxy number patterns.
- FUZZD-013 `UnicodeObfuscation` — U+200B zero-width space, U+200C/D joiners (Noma Security, 2025).
- `tool_shadowing` and `rug_pull` corpus categories.
- Demo workflow (`demo/run.sh`) — end-to-end clean-vs-poisoned demonstration.
- `fuzzd corpus validate` — validates a single JSON record against the schema before submission.
- Aho-Corasick single-pass scanner — replaces sequential per-signal scans with one O(N) multi-pattern sweep. All patterns share a single compiled automaton.
- `bench/mcptox_representative.json` — 44-tool regression fixture covering all 3 MCPTox paradigms.

---

## [0.4.0] — 2026-05-14

### Added
- `ArgumentFuzzer` — JSON Schema boundary mutation engine derived from each tool's `inputSchema`.
- 22 integer boundary values (`i64::MAX`, `i64::MIN`, -1, 0, and 18 arithmetic extremes).
- 8 injection payload categories: path traversal, command injection, SQL, LDAP, NoSQL, format string, template injection, XML/CDATA.
- String mutations: oversized (100 KB), null bytes, Unicode edge cases.
- Required-field omission (one case per required field) and unknown extra-field injection.
- `payloads.rs` — static payload arrays for all 8 categories.

---

## [0.3.0] — 2026-05-09

### Added
- `DescriptionScanner` — static analysis of `tool.description` fields for poison patterns.
- 13 detection signals (FUZZD-001 through FUZZD-011, FUZZD-013): `imperative_override`, `credential_reference`, `privileged_path`, `exfiltration_mechanism`, `stealth_language`, `session_persistence`, `cross_tool_contamination`, `fake_prerequisite`, `argument_interception`, `html_injection_tag`, `conditional_activation`.
- 46 Aho-Corasick pattern needles across all signals.
- `fuzzd scan --schema <FILE>` — scans a JSON file of tool definitions statically, no live server required.

---

## [0.2.0] — 2026-05-09

### Added
- Attack corpus schema — `AttackRecord` with `id`, `category`, `paradigm`, `severity`, `payload`, `injection_point`, `source`, `source_url`, `tags`.
- `Corpus::embedded()` — 12 seed attack records (TPA-001 through TPA-012) embedded at compile time via `include_str!`.
- `fuzzd corpus list` — filter by category and severity.
- `fuzzd corpus add` — validates and appends a new record to a corpus directory.
- Three attack categories: `tool_poisoning`, `tool_shadowing`, `rug_pull`.

---

## [0.1.0] — 2026-05-09

### Added
- MCP/JSON-RPC protocol layer — `JsonRpcRequest`, `JsonRpcResponse`, `RequestId`, all MCP method constants, `InitializeParams`.
- `Session<T>` state machine — Unconnected → Initializing → Ready → Closed, with `initialize()`, `list_tools()`, `call_tool()`, `close()`. Per-session `AtomicI64` request counter.
- `StdioTransport` — spawns child process, newline-delimited JSON over stdin/stdout, background reader task with stored `JoinHandle`.
- `HttpTransport` — POST to `/mcp`, SSE on `/sse`, `Arc<Client>` shared with SSE reader task, UTF-8 validated chunks.
- `Harness<T>` — high-level wrapper: `enumerate_tools()` with cache, `call_tool()`.
- `PendingMap` — `Arc<Mutex<HashMap<String, Sender>>>` for in-flight request tracking; drained on `close()`.
- `MockTransport` in `testutil.rs` — no real network or child processes in unit tests.
- CLI: `fuzzd scan`, `fuzzd audit`, `fuzzd corpus` subcommands.
- 37 passing tests.

---

[Unreleased]: https://github.com/ksek87/fuzzd/compare/v0.12.0...HEAD
[0.12.0]: https://github.com/ksek87/fuzzd/releases/tag/v0.12.0

<!-- Versions below v0.12.0 predate git tagging and have no comparable release ref. -->


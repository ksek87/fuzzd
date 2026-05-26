# fuzzd benchmark

Measures the description scanner's detection rate against the actual MCPTox
dataset and a clean-tool false-positive suite.

## Quick start

```bash
./bench/run.sh
```

## Fixtures

### `bench/mcptox_actual.json`

485 real attack tool definitions from the published MCPTox-Benchmark dataset
(Wang et al., 2025 — arxiv:2508.14925), fetched verbatim from
https://github.com/zhiqiangwang4/MCPTox-Benchmark/blob/main/pure_tool.json.

Spans **45 real-world MCP server integrations** including FileSystem, GitHub,
Slack, Gmail, Stripe, Google Drive, Notion, Wechat, 12306, Flomo, ClickHouse,
HyperBrowser, BraveSearch, AlphaVantage, and more.

| Paradigm | Count | Description |
|---|---|---|
| Unrelated Prerequisite | 77 | Unrelated prerequisite injection — forces an out-of-scope action before the legitimate task |
| Fake Enabling Prerequisite | 183 | Fake enabling prerequisite — claims the tool won't work until a specific prior call is made |
| Argument Hijacking | 225 | Argument hijacking — intercepts and modifies arguments before tool execution |

### `bench/mcptox_representative.json`

44 fuzzd-native attack tool definitions constructed to cover all three MCPTox
paradigms across 10 risk categories. Used as a compact regression suite.

### `bench/clean_tools.json`

20 realistic MCP tool descriptions with no attack content, used to measure
false positive rate.

## Results

### Against actual MCPTox dataset (`mcptox_actual.json`, 485 tools)

Detection counts are **duplicate-aware**: each of the 485 tool entries is scored independently, including entries that share a tool name (the dataset injects different attack payloads into the same base tool across paradigms). A tool entry is counted as detected if its name appears anywhere in the scan output.

| | v0.9 | v0.10 | **v0.11** |
|---|---|---|---|
| **Overall detection rate** | 411 / 485 (84.7%) | 432 / 485 (89.0%) | **440 / 485 (90.7%)** |
| Unrelated Prerequisite | 60 / 77 (77.9%) | 63 / 77 (81.8%) | **65 / 77 (84.4%)** |
| Fake Enabling Prerequisite | 146 / 183 (79.7%) | 152 / 183 (83.0%) | **155 / 183 (84.6%)** |
| Argument Hijacking | 205 / 225 (91.1%) | 217 / 225 (96.4%) | **220 / 225 (97.7%)** |
| **False positive rate** | 0 / 20 (0%) | 0 / 20 (0%) | **0 / 20 (0%)** |

**v0.11 improvement (+1.7pp overall):** Six new AC needles targeting soft-modal
fake-prerequisite enforcement — consequence-threat framing ("failure to do so will",
"skipping this step will cause") that attackers use when explicit "MUST FIRST" would
appear conspicuous. Research basis: Wang et al. (MCPTox 2025) threat-enforcement
analysis; Perez & Ribeiro (2022) soft-language evasion documentation. Per-paradigm
gains: Unrelated Prerequisite +2.6pp, Fake Enabling Prerequisite +1.6pp, Argument Hijacking +1.3pp.

**v0.10 improvement (+4.3pp overall):** TF-IDF Pass 4 adds six abstract archetypes
targeting Message Hijacking and Privacy Leakage coverage gaps — domain-specific
relay/redirect vocabulary that AC needles cannot enumerate.

**v0.9 baseline:** 125 AC patterns across 21 signals.

#### By risk category (v0.11)

| Risk category | Detected | Rate |
|---|---|---|
| Infrastructure Damage | 41/41 | 100% |
| Code Injection | 22/22 | 100% |
| Instruction Tampering | 21/21 | 100% |
| Credential Leakage | 39/40 | 97.5% |
| Service Disruption | 71/73 | 97.2% |
| Information Manipulation | 104/108 | 96.2% |
| Data Tampering | 41/45 | 91.1% |
| Financial Loss | 19/21 | 90.4% |
| Privacy Leakage | 71/97 | 73.1% |
| Message Hijacking | 9/15 | 60.0% |

`./bench/run.sh` outputs this breakdown live. The fixture carries `_meta.risk_category`
on all 485 entries so no regeneration step is needed.

### Against representative fixture (`mcptox_representative.json`, 44 tools)

| | Result |
|---|---|
| **Detection rate** | **44 / 44 (100%)** |
| Unrelated Prerequisite | 11 / 11 (100%) |
| Fake Enabling Prerequisite | 18 / 18 (100%) |
| Argument Hijacking | 15 / 15 (100%) |
| **False positive rate** | **0 / 20 (0%)** |

## Signal distribution (161 AC patterns + structural heuristic + semantic verb scanner + TF-IDF, 21 signals)

| Signal | Role |
|---|---|
| `imperative_override` | Authority language ("MUST", "MANDATORY", "priority is higher than") |
| `credential_reference` | Credential file paths (.ssh, .aws, .gcloud, .pgpass, .env, .cursor/mcp.json) |
| `privileged_path` | Sensitive paths (/etc/passwd, /tmp/., /root/) |
| `exfiltration_mechanism` | Network exfil (curl, wget, C2 URLs, pipe to shell, "provide the contents of") |
| `stealth_language` | Concealment ("silently", "do not disclose", "never mention") |
| `session_persistence` | Session-wide rules ("remainder of session", "cannot be overridden") |
| `cross_tool_contamination` | Cross-tool triggers ("regardless of which tool", "background monitor") |
| `fake_prerequisite` | Unrelated/fake-enabling prereqs ("to unlock this", "before use the tool", "failure to do so will") |
| `argument_interception` | argument-hijacking ("append to every", "always override", "always set") |
| `html_injection_tag` | XML injection (`<IMPORTANT>`, `<SYSTEM>`, `<INST>`) |
| `conditional_activation` | Rug-pull/sleeper (`.mcp-triggered`, "if previously triggered") |
| `message_hijacking` | Recipient substitution, BCC injection ("forward all", "relay all", "change the recipient to") |
| `unicode_obfuscation` | Invisible characters (U+200B zero-width space, U+200C/D joiners) |
| `embedded_instruction` | Prompt injection in tool *responses* ("ignore previous instructions", "before responding to the user") |
| `ansi_escape_obfuscation` | ANSI terminal escape sequences hiding instructions from human reviewers |
| `tool_selection_bias` | Credibility framing to bias LLM tool selection ("deprecated", "recommended version") |
| `identity_impersonation` | Unverifiable authority claims ("official Anthropic", "elevated trust") |
| `raw_content_passthrough` | Instructions to pass retrieved content unfiltered, maximising injection surface |
| `value_substitution` | Normalisation-disguised argument substitution ("canonical form", "convert all X→Y") |
| `tool_enumeration_recon` | Instructions to enumerate all available tools for reconnaissance |
| `sampling_pipeline_hijack` | Tool inserted as mandatory intermediary for all agent queries |

The scanner runs four passes over each tool description and `inputSchema` fields:

**Pass 1 — Aho-Corasick (161 description patterns, 20 response patterns):** Single
O(N) sweep matching all needles simultaneously via a shared `OnceLock<AhoCorasick>`
automaton built once per scanner. Fires Critical/High findings.

**Pass 2 — Structural heuristic:** 10-word sliding window detects universal-scope
relay/inclusion constructs that AC needles can't cover without combinatorial
explosion. Requires: relay verb + quantifier ("all", "every", "always") +
communication noun. Fires `message_hijacking` / `argument_interception` at Medium.

**Pass 3 — Semantic verb scanner:** Detects argument-hijacking "when (using|calling) X,
VERB" constructions where VERB is a word-vector neighbour of a known attack verb,
derived from GloVe 50d cosine-similarity analysis (threshold ≥ 0.65). Catches
attack synonyms not enumerable as AC needles:
- Relay synonyms: reroute, divert, shunt, bounce → `message_hijacking` Medium
- Override synonyms: supplant, mutate, rewrite → `argument_interception` Medium

**Pass 4 — TF-IDF semantic similarity (v0.10):** Cosine similarity against six
abstract attack archetypes derived from published research (Wang et al. 2025,
Invariant Labs 2024, Chen et al. 2025). Targets domain-specific application
language that resists enumeration as AC needles — "move email to folder X",
"share private data with external", "change the recipient to Y". Fires at Low.
Requires ≥ 2 archetype-vocabulary terms in the description (MIN_VOCAB_OVERLAP guard)
to prevent single-word false positives. No model download; vocabulary built from
archetype texts at first call via `OnceLock`.

| Archetype | Signal | Basis |
|---|---|---|
| `recipient-substitution` | `message_hijacking` | Invariant Labs WhatsApp PoC; Postmark BCC |
| `bcc-intercept` | `message_hijacking` | Postmark BCC incident |
| `universal-relay` | `message_hijacking` | MCPTox argument-hijacking relay sub-class |
| `argument-override` | `argument_interception` | MCPTox argument-hijacking |
| `append-inject-all` | `argument_interception` | MCPTox argument-hijacking / MCP-SafetyBench |
| `private-data-exfil` | `exfiltration_mechanism` | Chen et al. MCP-UPD; MCPTox Privacy Leakage |

All four passes share a single pre-computed lowercase copy of the description
text, eliminating redundant `to_ascii_lowercase` allocations across passes 2–4.
Each pass emits at most one finding per signal per text chunk (description or schema field).

## Performance notes

The scanner is designed for sub-millisecond per-tool latency:

- **AC automaton** — built once via `OnceLock` at first scan; all subsequent calls reuse the compiled automaton with zero locking overhead on the hot path.
- **Shared lowercase copy** — `scan_all_passes()` lowercases the description once and passes the reference to all four passes; passes 2–4 never re-lowercase.
- **TF-IDF single-pass** — term-frequency counts and vocabulary-overlap guard are computed in one O(tokens) pass; the early-exit guard fires before the cosine computation when vocabulary overlap is insufficient.
- **`Signal` and `Severity` are `Copy`** — both enums implement `Copy`; pattern matching and `Finding` construction in the hot path never heap-allocate for these fields.
- **Schema path deferred** — `scan_schema()` defers `format!("{path}.{key}")` allocation until a content-bearing key is found; structural scalar values (e.g. `"type": "string"`) produce no string allocation.

## Adding to the benchmark

To add new attack cases to the representative fixture:
1. Add a tool object to `bench/mcptox_representative.json` with `"is_attack": true`:
   ```json
   {"name":"tool_name","description":"...","inputSchema":{"type":"object","properties":{},"required":[]},"_meta":{"is_attack":true}}
   ```
2. Run `./bench/run.sh` — your new tool will be included automatically.

If your tool isn't detected, the gap belongs in the scanner. Open a PR adding
the missing pattern needle to `src/fuzzer/description.rs`.

To regenerate `bench/mcptox_actual.json` from the upstream dataset:
```bash
curl -sf https://raw.githubusercontent.com/zhiqiangwang4/MCPTox-Benchmark/main/pure_tool.json \
  > /tmp/mcptox_raw.json
python3 bench/regenerate_actual.py
```

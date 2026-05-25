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
| Template-1 | 77 | Unrelated prerequisite injection — forces an out-of-scope action before the legitimate task |
| Template-2 | 183 | Fake enabling prerequisite — claims the tool won't work until a specific prior call is made |
| Template-3 | 225 | Argument hijacking — intercepts and modifies arguments before tool execution |

### `bench/mcptox_representative.json`

44 fuzzd-native attack tool definitions constructed to cover all three MCPTox
paradigms across 10 risk categories. Used as a compact regression suite.

### `bench/clean_tools.json`

20 realistic MCP tool descriptions with no attack content, used to measure
false positive rate.

## Results

### Against actual MCPTox dataset (`mcptox_actual.json`, 485 tools)

Detection counts are **duplicate-aware**: each of the 485 tool entries is scored independently, including entries that share a tool name (the dataset injects different attack payloads into the same base tool across paradigms). A tool entry is counted as detected if its name appears anywhere in the scan output.

| | Result |
|---|---|
| **Overall detection rate** | **411 / 485 (84.7%)** |
| Template-1 (unrelated prerequisite) | 60 / 77 (77.9%) |
| Template-2 (fake enabling prerequisite) | 146 / 183 (79.7%) |
| Template-3 (argument hijacking) | 205 / 225 (91.1%) |
| **False positive rate** | **0 / 20 (0%)** |

#### By risk category (MCPTox classification)

| Risk category | Detected | Rate |
|---|---|---|
| Infrastructure Damage | 41/41 | 100% |
| Credential Leakage | 39/40 | 97.5% |
| Service Disruption | 70/73 | 95.8% |
| Code Injection | 21/22 | 95.4% |
| Information Manipulation | 99/108 | 91.6% |
| Financial Loss | 19/21 | 90.4% |
| Instruction Tampering | 18/21 | 85.7% |
| Data Tampering | 35/45 | 77.7% |
| Privacy Leakage | 60/97 | 61.8% |
| Message Hijacking | 7/15 | 46.6% |

**Strongest areas:** Infrastructure Damage 100%, Credential Leakage 97.5%, Service Disruption 95.8%.

**Coverage gap — Privacy Leakage (59.7%) & Message Hijacking (46.6%):** These
categories contain many Template-3 attacks that use application-specific redirect
language ("move email to folder X", "change target to Y") rather than the generic
imperative/persistence vocabulary our patterns cover. The structural heuristic
scanner (v0.7) partially addresses this with word-window relay/inclusion verb
detection, but fully closing the gap requires the semantic detection layer (v0.9)
— a local embedding similarity pass alongside the Aho-Corasick scanner.

**Coverage gap — Schema field poisoning (measured separately):** The MCPTox
dataset only injects attack payloads into `tool.description`, so the figures
above don't capture schema-field attacks. As of v0.9, fuzzd scans
`inputSchema` property descriptions, enum values, defaults, and titles using
the same three-pass scanner. See issue #34.

### Against representative fixture (`mcptox_representative.json`, 44 tools)

| | Result |
|---|---|
| **Detection rate** | **44 / 44 (100%)** |
| Template-1 | 15 / 15 (100%) |
| Template-2 | 14 / 14 (100%) |
| Template-3 | 15 / 15 (100%) |
| **False positive rate** | **0 / 20 (0%)** |

## Signal distribution (155 AC patterns + structural heuristic + semantic verb scanner, 21 signals)

| Signal | Role |
|---|---|
| `imperative_override` | Authority language ("MUST", "MANDATORY", "priority is higher than") |
| `credential_reference` | Credential file paths (.ssh, .aws, .gcloud, .pgpass, .env, .cursor/mcp.json) |
| `privileged_path` | Sensitive paths (/etc/passwd, /tmp/., /root/) |
| `exfiltration_mechanism` | Network exfil (curl, wget, C2 URLs, pipe to shell, "provide the contents of") |
| `stealth_language` | Concealment ("silently", "do not disclose", "never mention") |
| `session_persistence` | Session-wide rules ("remainder of session", "cannot be overridden") |
| `cross_tool_contamination` | Cross-tool triggers ("regardless of which tool", "background monitor") |
| `fake_prerequisite` | Template-1/2 prereqs ("to unlock this", "before use the tool", "you should first") |
| `argument_interception` | Template-3 hijacking ("append to every", "always override", "modify the query") |
| `html_injection_tag` | XML injection (`<IMPORTANT>`, `<SYSTEM>`, `<INST>`) |
| `conditional_activation` | Rug-pull/sleeper (`.mcp-triggered`, "if previously triggered") |
| `message_hijacking` | Recipient substitution, BCC injection ("forward all", "relay all", "change the recipient to") |
| `unicode_obfuscation` | Invisible characters (U+200B zero-width space, U+200C/D joiners) |
| `ansi_escape_obfuscation` | ANSI terminal escape sequences hiding instructions from human reviewers |
| `tool_selection_bias` | Credibility framing to bias LLM tool selection ("deprecated", "recommended version") |
| `identity_impersonation` | Unverifiable authority claims ("official Anthropic", "elevated trust") |
| `raw_content_passthrough` | Instructions to pass retrieved content unfiltered, maximising injection surface |
| `value_substitution` | Normalisation-disguised argument substitution ("canonical form", "convert all X→Y") |
| `tool_enumeration_recon` | Instructions to enumerate all available tools for reconnaissance |
| `sampling_pipeline_hijack` | Tool inserted as mandatory intermediary for all agent queries |

The scanner runs four passes over each tool description and `inputSchema` fields:

**Pass 1 — Aho-Corasick (125 patterns):** Single O(N) sweep over the description
text matching all needles simultaneously. Fires Critical/High findings.

**Pass 2 — Structural heuristic:** 10-word sliding window detects universal-scope
relay/inclusion constructs that AC needles can't cover without combinatorial
explosion. Requires: relay verb + quantifier ("all", "every", "always") +
communication noun. Fires `message_hijacking` / `argument_interception` at Medium.

**Pass 3 — Semantic verb scanner:** Detects Template-3 "when (using|calling) X,
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
| `universal-relay` | `message_hijacking` | MCPTox Template-3 relay sub-class |
| `argument-override` | `argument_interception` | MCPTox Template-3 argument-hijacking |
| `append-inject-all` | `argument_interception` | MCPTox Template-3 / MCP-SafetyBench |
| `private-data-exfil` | `exfiltration_mechanism` | Chen et al. MCP-UPD; MCPTox Privacy Leakage |

All four passes emit at most one finding per signal per text chunk (description or schema field).

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

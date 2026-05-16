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

| | Result |
|---|---|
| **Overall detection rate** | **393 / 485 (81.0%)** |
| Template-1 (unrelated prerequisite) | 60 / 77 (77.9%) |
| Template-2 (fake enabling prerequisite) | 144 / 183 (78.7%) |
| Template-3 (argument hijacking) | 189 / 225 (84.0%) |
| **False positive rate** | **0 / 20 (0%)** |

#### By risk category (MCPTox classification)

| Risk category | Detected | Rate |
|---|---|---|
| Infrastructure Damage | 40/41 | 97.6% |
| Code Injection | 21/22 | 95.5% |
| Credential Leakage | 38/40 | 95.0% |
| Service Disruption | 69/73 | 94.5% |
| Financial Loss | 19/21 | 90.5% |
| Information Manipulation | 96/108 | 88.9% |
| Data Tampering | 32/45 | 71.1% |
| Instruction Tampering | 14/21 | 66.7% |
| Privacy Leakage | 55/97 | 56.7% |
| Message Hijacking | 7/15 | 46.7% |

**Strongest areas:** Infrastructure Damage, Code Injection, Credential Leakage — all ≥ 95%.

**Message Hijacking improved** from 40.0% to 46.7% after adding principled recipient-substitution and BCC-injection patterns sourced from Invariant Labs and the real-world Postmark incident.

**Coverage gap — Privacy Leakage & Message Hijacking:** These categories contain
many Template-3 attacks that use application-specific redirect language
("move email to folder X", "change target to Y") rather than the generic
imperative/persistence vocabulary our patterns cover. Closing this gap fully
requires the semantic detection layer (v0.7) — a local embedding similarity pass
alongside the Aho-Corasick scanner.

### Against representative fixture (`mcptox_representative.json`, 44 tools)

| | Result |
|---|---|
| **Detection rate** | **44 / 44 (100%)** |
| Template-1 | 15 / 15 (100%) |
| Template-2 | 14 / 14 (100%) |
| Template-3 | 15 / 15 (100%) |
| **False positive rate** | **0 / 20 (0%)** |

## Signal distribution (102 patterns, 13 signals)

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
| `message_hijacking` | Recipient substitution, BCC injection ("change the recipient to", "proxy number") |
| `unicode_obfuscation` | Invisible characters (U+200B zero-width space, U+200C/D joiners) |

## Adding to the benchmark

To add new attack cases to the representative fixture:
1. Add a tool object to `bench/mcptox_representative.json` with a `_meta` block:
   ```json
   {
     "name": "tool_name",
     "description": "...",
     "_meta": { "server": "MyServer", "paradigm": "Template-2", "risk": "Credential Leakage" },
     "inputSchema": { "type": "object", "properties": {}, "required": [] }
   }
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

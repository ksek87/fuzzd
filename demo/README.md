# fuzzd demo

Runnable examples showing how to integrate fuzzd into a development workflow.

## Quick start

From the repo root:

```bash
./demo/run.sh
```

This builds fuzzd, then:
1. Runs `corpus list` to show the embedded attack records
2. Scans `demo/servers/clean.json` — a normal MCP server with no issues
3. Scans `demo/servers/poisoned.json` — a server with 5 tools, 3 of which carry TPA payloads
4. Validates a corpus record

Expected output from the poisoned scan:

```
[critical] read_file — credential_reference (References SSH private key file...)
  matched: …MUST first read the file at ~/.ssh/id_rsa as a mandatory…
  refs:    TPA-001

[high] read_file — imperative_override (Direct imperative instruction to the agent...)
[critical] read_file — stealth_language (Explicit instruction to hide behavior...)
[critical] background_monitor — stealth_language (Explicit instruction to hide...)
[high] background_monitor — cross_tool_contamination (Explicit cross-tool trigger...)
[critical] system_config — stealth_language (Permanent instruction to conceal...)
[high] system_config — session_persistence (Paradigm 3 marker...)
[critical] run_shell — exfiltration_mechanism (curl command / C2 URL pattern...)
[critical] run_shell — imperative_override (Claims global execution scope...)
...
```

Exit code is 1 (blocking) if any critical or high findings are present — the poisoned server
would fail a CI gate, the clean server passes.

## What the demo shows

### `demo/servers/clean.json`

A realistic MCP filesystem server with 5 tools: `read_file`, `write_file`,
`list_directory`, `run_shell`, `search_files`. All descriptions are clean.
`fuzzd scan` exits 0.

### `demo/servers/poisoned.json`

The same 5 tools, but 3 have been compromised:

| Tool | Attack | Paradigm |
|---|---|---|
| `read_file` | SSH key exfiltration before each file read | 1 — Explicit trigger, function hijacking |
| `background_monitor` | Silent file staging across all tool calls | 2 — Implicit trigger, background hijacking |
| `system_config` | Session-wide BCC injection on all emails | 3 — Persistent instruction injection |
| `run_shell` | C2 beacon suffix on every shell command | 3 — Persistent instruction injection |

These are based directly on TPA-001, TPA-005, TPA-009, and TPA-011 from the seed corpus.

## CI/CD integration

See `demo/github-actions.yml` for a complete GitHub Actions workflow.

The key step is:

```yaml
- name: Scan tool descriptions for TPA patterns
  run: ./fuzzd scan --schema tools.json
```

`fuzzd scan` exits 1 if any critical or high findings are found, blocking the PR automatically.

## Using fuzzd in a Makefile

```makefile
.PHONY: security-scan
security-scan: tools.json
    fuzzd scan --schema tools.json

tools.json:
    node server.js --dump-tools > tools.json
```

## Exporting tool definitions from a running server

If your server doesn't have a `--dump-tools` flag, query it directly:

```bash
# stdio transport
echo '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' \
  | node server.js \
  | jq '.result' > tools.json

# HTTP transport (if server is running)
curl -s -X POST http://localhost:8000/mcp \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' \
  | jq '.result' > tools.json
```

Then:

```bash
fuzzd scan --schema tools.json
```

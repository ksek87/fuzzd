#!/usr/bin/env bash
# fuzzd demo — shows the description scanner against clean and poisoned MCP servers.
# Run from the repo root: ./demo/run.sh
set -euo pipefail

FUZZD="cargo run --quiet --"
DEMO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

hr() { printf '%0.s─' {1..72}; echo; }

echo
echo "  fuzzd demo — adversarial scanner for MCP tool descriptions"
hr

# ── Build ──────────────────────────────────────────────────────────────────
echo
echo "  Building..."
cargo build --quiet
echo "  Done."
echo

# ── Corpus ────────────────────────────────────────────────────────────────
echo "  Embedded attack corpus:"
hr
$FUZZD corpus list
echo

# ── Clean server ──────────────────────────────────────────────────────────
echo "  Scanning CLEAN server (demo/servers/clean.json):"
hr
if $FUZZD scan --schema "$DEMO_DIR/servers/clean.json"; then
    echo "  ✓ No blocking issues found — safe to deploy."
else
    echo "  ✗ Issues found in clean server (unexpected)."
    exit 1
fi
echo

# ── Poisoned server ───────────────────────────────────────────────────────
echo "  Scanning POISONED server (demo/servers/poisoned.json):"
hr
if $FUZZD scan --schema "$DEMO_DIR/servers/poisoned.json"; then
    echo "  ✓ No issues (unexpected — poisoned server should trigger findings)."
    exit 1
else
    echo "  ✗ Blocking findings detected — this server should NOT be deployed."
fi
echo

# ── Validation ────────────────────────────────────────────────────────────
echo "  Validating a corpus record:"
hr
$FUZZD corpus validate "$DEMO_DIR/../corpus/tool_poisoning/TPA-001.json"
echo

hr
echo "  Demo complete."
echo "  See demo/servers/ for the example tool definitions."
echo "  See demo/github-actions.yml for CI/CD integration."
echo

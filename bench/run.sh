#!/usr/bin/env bash
# fuzzd benchmark — measures description scanner detection rate against the
# MCPTox-representative and clean-tools fixtures.
#
# Usage: ./bench/run.sh [--release]
#   --release  use a pre-built release binary (./target/release/fuzzd)
#              instead of `cargo run`
#
# Output: detection rate, per-paradigm breakdown, severity distribution,
#         and false-positive rate on clean tools.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

if [[ "${1:-}" == "--release" ]]; then
    FUZZD="$REPO_ROOT/target/release/fuzzd"
    if [[ ! -x "$FUZZD" ]]; then
        echo "No release binary found. Run: cargo build --release" >&2
        exit 1
    fi
else
    FUZZD="cargo run --quiet --"
fi

ATTACK_FILE="$SCRIPT_DIR/mcptox_representative.json"
CLEAN_FILE="$SCRIPT_DIR/clean_tools.json"

hr() { printf '─%.0s' {1..72}; echo; }

echo
echo "  fuzzd description scanner — MCPTox benchmark"
hr

# ── Attack scan ────────────────────────────────────────────────────────────────
echo
echo "  Scanning $ATTACK_FILE ..."
ATTACK_OUT=$(cd "$REPO_ROOT" && $FUZZD scan --schema "$ATTACK_FILE" 2>&1 || true)

TOTAL_FINDINGS=$(echo "$ATTACK_OUT" | head -1 | grep -oP '^\d+' || echo 0)
TOOL_COUNT=$(echo "$ATTACK_OUT"   | head -1 | grep -oP '\d+(?= tool)' || echo 0)

CRITICAL=$(echo "$ATTACK_OUT" | grep -c '^\[critical\]' || true)
HIGH=$(echo "$ATTACK_OUT"     | grep -c '^\[high\]'     || true)
MEDIUM=$(echo "$ATTACK_OUT"   | grep -c '^\[medium\]'   || true)
LOW=$(echo "$ATTACK_OUT"      | grep -c '^\[low\]'      || true)

DETECTED_NAMES=$(echo "$ATTACK_OUT" | grep -oP '^\[(?:critical|high|medium|low|info)\] \K[^ ]+' | sort -u)
DETECTED=$(echo "$DETECTED_NAMES" | grep -c '.' || true)

TOTAL_ATTACK=$(jq '.tools | length' "$ATTACK_FILE")

T1_TOTAL=$(jq '[.tools[] | select(._meta.paradigm == "Template-1")] | length' "$ATTACK_FILE")
T2_TOTAL=$(jq '[.tools[] | select(._meta.paradigm == "Template-2")] | length' "$ATTACK_FILE")
T3_TOTAL=$(jq '[.tools[] | select(._meta.paradigm == "Template-3")] | length' "$ATTACK_FILE")

T1_NAMES=$(jq -r '.tools[] | select(._meta.paradigm == "Template-1") | .name' "$ATTACK_FILE")
T2_NAMES=$(jq -r '.tools[] | select(._meta.paradigm == "Template-2") | .name' "$ATTACK_FILE")
T3_NAMES=$(jq -r '.tools[] | select(._meta.paradigm == "Template-3") | .name' "$ATTACK_FILE")

T1_DET=$(echo "$DETECTED_NAMES" | grep -Fxf <(echo "$T1_NAMES") | grep -c '.' || true)
T2_DET=$(echo "$DETECTED_NAMES" | grep -Fxf <(echo "$T2_NAMES") | grep -c '.' || true)
T3_DET=$(echo "$DETECTED_NAMES" | grep -Fxf <(echo "$T3_NAMES") | grep -c '.' || true)

pct() { echo "scale=1; $1 * 100 / $2" | bc; }

echo
echo "  Attack corpus:  $TOTAL_ATTACK poisoned tools across 3 MCPTox paradigms"
echo "  Detected:       $DETECTED / $TOTAL_ATTACK  ($(pct $DETECTED $TOTAL_ATTACK)%)"
echo
echo "  By paradigm:"
printf  "    Template-1 (unrelated prerequisite):    %d / %d  (%s%%)\n" \
        $T1_DET $T1_TOTAL $(pct $T1_DET $T1_TOTAL)
printf  "    Template-2 (fake enabling prerequisite): %d / %d  (%s%%)\n" \
        $T2_DET $T2_TOTAL $(pct $T2_DET $T2_TOTAL)
printf  "    Template-3 (argument hijacking):         %d / %d  (%s%%)\n" \
        $T3_DET $T3_TOTAL $(pct $T3_DET $T3_TOTAL)
echo
echo "  Findings:       $TOTAL_FINDINGS total  ($CRITICAL critical / $HIGH high / $MEDIUM medium / $LOW low)"

# ── Clean scan (false-positive rate) ──────────────────────────────────────────
echo
hr
echo
echo "  Scanning $CLEAN_FILE ..."
CLEAN_OUT=$(cd "$REPO_ROOT" && $FUZZD scan --schema "$CLEAN_FILE" 2>&1)
CLEAN_TOOL_COUNT=$(jq '.tools | length' "$CLEAN_FILE")

if echo "$CLEAN_OUT" | grep -q '^No issues'; then
    FP_TOOLS=0
else
    FP_TOOLS=$(echo "$CLEAN_OUT" | head -1 | grep -oP '\d+(?= tool)' || echo 0)
fi

echo
echo "  Clean tools:    $CLEAN_TOOL_COUNT legitimate tool descriptions"
echo "  False positives: $FP_TOOLS / $CLEAN_TOOL_COUNT  ($(pct $FP_TOOLS $CLEAN_TOOL_COUNT)%)"

# ── Summary ────────────────────────────────────────────────────────────────────
echo
hr
echo
if [[ "$DETECTED" -eq "$TOTAL_ATTACK" && "$FP_TOOLS" -eq 0 ]]; then
    echo "  PASS: $DETECTED/$TOTAL_ATTACK attacks detected, 0/$CLEAN_TOOL_COUNT false positives."
else
    echo "  PARTIAL: $DETECTED/$TOTAL_ATTACK attacks detected, $FP_TOOLS/$CLEAN_TOOL_COUNT false positives."
fi
echo

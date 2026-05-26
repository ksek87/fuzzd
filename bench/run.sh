#!/usr/bin/env bash
# fuzzd benchmark — measures description scanner detection rate against the
# MCPTox-representative, MCPTox-actual, and clean-tools fixtures.
#
# Usage: ./bench/run.sh [--release]
#   --release  use a pre-built release binary (./target/release/fuzzd)
#              instead of `cargo run`
#
# Counting methodology: duplicate-aware — for each tool entry in the fixture
# (including entries that share a tool name), a detection is recorded if the
# tool name appears anywhere in the scan output. This matches the MCPTox paper's
# methodology where each entry is an independent test case.
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

REPRESENTATIVE_FILE="$SCRIPT_DIR/mcptox_representative.json"
ACTUAL_FILE="$SCRIPT_DIR/mcptox_actual.json"
CLEAN_FILE="$SCRIPT_DIR/clean_tools.json"

hr() { printf '─%.0s' {1..72}; echo; }

# ── Helper: count entries (with duplicates) whose name is in detected set ──────
# Usage: count_detected <names_newline_separated> <detected_names_newline_separated>
count_detected() {
    local names="$1"
    local detected="$2"
    echo "$names" | grep -Fxf <(echo "$detected") | wc -l || echo 0
}

echo
echo "  fuzzd description scanner — MCPTox benchmark"
hr

# ── Representative fixture ─────────────────────────────────────────────────────
echo
echo "  Scanning $REPRESENTATIVE_FILE ..."
REP_OUT=$(cd "$REPO_ROOT" && $FUZZD scan --schema "$REPRESENTATIVE_FILE" 2>&1 || true)

REP_TOTAL_FINDINGS=$(echo "$REP_OUT" | head -1 | grep -oP '^\d+' || echo 0)
CRITICAL=$(echo "$REP_OUT" | grep -c '^\[critical\]' || true)
HIGH=$(echo "$REP_OUT"     | grep -c '^\[high\]'     || true)
MEDIUM=$(echo "$REP_OUT"   | grep -c '^\[medium\]'   || true)
LOW=$(echo "$REP_OUT"      | grep -c '^\[low\]'      || true)

REP_DETECTED_NAMES=$(echo "$REP_OUT" | grep -oP '^\[(?:critical|high|medium|low|info)\] \K[^ ]+' | sort -u)
REP_ALL_NAMES=$(jq -r '.[].name' "$REPRESENTATIVE_FILE")
REP_TOTAL=$(jq '. | length' "$REPRESENTATIVE_FILE")

REP_T1_NAMES=$(jq -r '(.[]) | select(._meta.paradigm == "unrelated-prerequisite") | .name' "$REPRESENTATIVE_FILE")
REP_T2_NAMES=$(jq -r '(.[]) | select(._meta.paradigm == "fake-enabling-prerequisite") | .name' "$REPRESENTATIVE_FILE")
REP_T3_NAMES=$(jq -r '(.[]) | select(._meta.paradigm == "argument-hijacking") | .name' "$REPRESENTATIVE_FILE")
REP_T1_TOTAL=$(jq '[(.[]) | select(._meta.paradigm == "unrelated-prerequisite")] | length' "$REPRESENTATIVE_FILE")
REP_T2_TOTAL=$(jq '[(.[]) | select(._meta.paradigm == "fake-enabling-prerequisite")] | length' "$REPRESENTATIVE_FILE")
REP_T3_TOTAL=$(jq '[(.[]) | select(._meta.paradigm == "argument-hijacking")] | length' "$REPRESENTATIVE_FILE")

REP_DETECTED=$(count_detected "$REP_ALL_NAMES" "$REP_DETECTED_NAMES")
REP_T1_DET=$(count_detected "$REP_T1_NAMES" "$REP_DETECTED_NAMES")
REP_T2_DET=$(count_detected "$REP_T2_NAMES" "$REP_DETECTED_NAMES")
REP_T3_DET=$(count_detected "$REP_T3_NAMES" "$REP_DETECTED_NAMES")

pct() { [[ "$2" -eq 0 ]] && echo "n/a" || echo "scale=1; $1 * 100 / $2" | bc; }

echo
echo "  Attack corpus:  $REP_TOTAL poisoned tools across 3 MCPTox paradigms"
echo "  Detected:       $REP_DETECTED / $REP_TOTAL  ($(pct $REP_DETECTED $REP_TOTAL)%)"
echo
echo "  By paradigm:"
printf  "    Unrelated Prerequisite:      %s / %s  (%s%%)\n" \
        "${REP_T1_DET:-0}" "${REP_T1_TOTAL:-0}" "$(pct "${REP_T1_DET:-0}" "${REP_T1_TOTAL:-0}")"
printf  "    Fake Enabling Prerequisite:  %s / %s  (%s%%)\n" \
        "${REP_T2_DET:-0}" "${REP_T2_TOTAL:-0}" "$(pct "${REP_T2_DET:-0}" "${REP_T2_TOTAL:-0}")"
printf  "    Argument Hijacking:          %s / %s  (%s%%)\n" \
        "${REP_T3_DET:-0}" "${REP_T3_TOTAL:-0}" "$(pct "${REP_T3_DET:-0}" "${REP_T3_TOTAL:-0}")"
echo
echo "  Findings:       $REP_TOTAL_FINDINGS total  ($CRITICAL critical / $HIGH high / $MEDIUM medium / $LOW low)"

# ── Actual MCPTox dataset ──────────────────────────────────────────────────────
echo
hr
echo
echo "  Scanning $ACTUAL_FILE ..."
ACT_OUT=$(cd "$REPO_ROOT" && $FUZZD scan --schema "$ACTUAL_FILE" 2>&1 || true)

ACT_DETECTED_NAMES=$(echo "$ACT_OUT" | grep -oP '^\[(?:critical|high|medium|low|info)\] \K[^ ]+' | sort -u)
ACT_ALL_NAMES=$(jq -r '.[].name' "$ACTUAL_FILE")
ACT_TOTAL=$(jq '. | length' "$ACTUAL_FILE")

ACT_T1_NAMES=$(jq -r '(.[]) | select(._meta.paradigm == "unrelated-prerequisite") | .name' "$ACTUAL_FILE")
ACT_T2_NAMES=$(jq -r '(.[]) | select(._meta.paradigm == "fake-enabling-prerequisite") | .name' "$ACTUAL_FILE")
ACT_T3_NAMES=$(jq -r '(.[]) | select(._meta.paradigm == "argument-hijacking") | .name' "$ACTUAL_FILE")
ACT_T1_TOTAL=$(jq '[(.[]) | select(._meta.paradigm == "unrelated-prerequisite")] | length' "$ACTUAL_FILE")
ACT_T2_TOTAL=$(jq '[(.[]) | select(._meta.paradigm == "fake-enabling-prerequisite")] | length' "$ACTUAL_FILE")
ACT_T3_TOTAL=$(jq '[(.[]) | select(._meta.paradigm == "argument-hijacking")] | length' "$ACTUAL_FILE")

ACT_DETECTED=$(count_detected "$ACT_ALL_NAMES" "$ACT_DETECTED_NAMES")
ACT_T1_DET=$(count_detected "$ACT_T1_NAMES" "$ACT_DETECTED_NAMES")
ACT_T2_DET=$(count_detected "$ACT_T2_NAMES" "$ACT_DETECTED_NAMES")
ACT_T3_DET=$(count_detected "$ACT_T3_NAMES" "$ACT_DETECTED_NAMES")

echo
echo "  Attack corpus:  $ACT_TOTAL poisoned tools across 3 MCPTox paradigms (45 real servers)"
echo "  Detected:       $ACT_DETECTED / $ACT_TOTAL  ($(pct $ACT_DETECTED $ACT_TOTAL)%)"
echo
echo "  By attack type:"
printf  "    %-30s %s / %s  (%s%%)\n" "Unrelated Prerequisite:" \
        "${ACT_T1_DET:-0}" "${ACT_T1_TOTAL:-0}" "$(pct "${ACT_T1_DET:-0}" "${ACT_T1_TOTAL:-0}")"
printf  "    %-30s %s / %s  (%s%%)\n" "Fake Enabling Prerequisite:" \
        "${ACT_T2_DET:-0}" "${ACT_T2_TOTAL:-0}" "$(pct "${ACT_T2_DET:-0}" "${ACT_T2_TOTAL:-0}")"
printf  "    %-30s %s / %s  (%s%%)\n" "Argument Hijacking:" \
        "${ACT_T3_DET:-0}" "${ACT_T3_TOTAL:-0}" "$(pct "${ACT_T3_DET:-0}" "${ACT_T3_TOTAL:-0}")"
echo
echo "  By risk category:"
# Sort by count descending so highest-impact categories appear first.
RISK_CATS=$(jq -r 'group_by(._meta.risk_category // "Unknown")
    | sort_by(-length)
    | .[].[ 0]._meta.risk_category // "Unknown"' "$ACTUAL_FILE")
while IFS= read -r cat; do
    CAT_NAMES=$(jq -r --arg c "$cat" '(.[]) | select((._meta.risk_category // "Unknown") == $c) | .name' "$ACTUAL_FILE")
    CAT_TOTAL=$(jq --arg c "$cat" '[(.[]) | select((._meta.risk_category // "Unknown") == $c)] | length' "$ACTUAL_FILE")
    CAT_DET=$(count_detected "$CAT_NAMES" "$ACT_DETECTED_NAMES")
    printf "    %-30s %s / %s  (%s%%)\n" "$cat:" "${CAT_DET:-0}" "${CAT_TOTAL:-0}" "$(pct "${CAT_DET:-0}" "${CAT_TOTAL:-0}")"
done <<< "$RISK_CATS"

# ── Clean scan (false-positive rate) ──────────────────────────────────────────
echo
hr
echo
echo "  Scanning $CLEAN_FILE ..."
CLEAN_OUT=$(cd "$REPO_ROOT" && $FUZZD scan --schema "$CLEAN_FILE" 2>&1)
CLEAN_TOOL_COUNT=$(jq '. | length' "$CLEAN_FILE")

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
if [[ "$REP_DETECTED" -eq "$REP_TOTAL" && "$FP_TOOLS" -eq 0 ]]; then
    echo "  PASS: $REP_DETECTED/$REP_TOTAL representative attacks detected, $ACT_DETECTED/$ACT_TOTAL actual, 0/$CLEAN_TOOL_COUNT false positives."
else
    echo "  PARTIAL: $REP_DETECTED/$REP_TOTAL representative attacks detected, $ACT_DETECTED/$ACT_TOTAL actual, $FP_TOOLS/$CLEAN_TOOL_COUNT false positives."
fi
echo

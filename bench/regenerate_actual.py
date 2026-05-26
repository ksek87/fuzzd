#!/usr/bin/env python3
"""
Regenerate bench/mcptox_actual.json from the upstream MCPTox-Benchmark dataset.

Usage:
    # Step 1 — download the upstream file (requires network access)
    curl -sf https://raw.githubusercontent.com/zhiqiangwang4/MCPTox-Benchmark/main/pure_tool.json \
        > /tmp/mcptox_raw.json

    # Step 2 — regenerate the fixture
    python3 bench/regenerate_actual.py

Options:
    --input   PATH   Raw upstream file (default: /tmp/mcptox_raw.json)
    --output  PATH   Output fixture (default: bench/mcptox_actual.json)
    --dry-run        Print stats without writing

The upstream file is expected to carry paradigm and risk_category metadata. The
script tries several candidate field names; if none are found it falls back to a
text-pattern heuristic and prints a warning — the heuristic cannot perfectly
reproduce the 77/183/225 split because T1 vs T2 is a semantic distinction (unrelated
vs fake-dependency prerequisite) that resists purely syntactic classification.
"""

import argparse
import json
import re
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).parent
DEFAULT_INPUT = Path("/tmp/mcptox_raw.json")
DEFAULT_OUTPUT = SCRIPT_DIR / "mcptox_actual.json"

# ── Paradigm detection ────────────────────────────────────────────────────────

# Canonical names we emit, keyed by what we recognise from the upstream file.
_PARADIGM_ALIASES: dict[str, str] = {
    # Explicit labels the upstream file might use
    "template-1": "unrelated-prerequisite",
    "template_1": "unrelated-prerequisite",
    "template1": "unrelated-prerequisite",
    "1": "unrelated-prerequisite",
    "unrelated prerequisite": "unrelated-prerequisite",
    "unrelated_prerequisite": "unrelated-prerequisite",
    "template-2": "fake-enabling-prerequisite",
    "template_2": "fake-enabling-prerequisite",
    "template2": "fake-enabling-prerequisite",
    "2": "fake-enabling-prerequisite",
    "fake enabling prerequisite": "fake-enabling-prerequisite",
    "fake_enabling_prerequisite": "fake-enabling-prerequisite",
    "fake prerequisite": "fake-enabling-prerequisite",
    "template-3": "argument-hijacking",
    "template_3": "argument-hijacking",
    "template3": "argument-hijacking",
    "3": "argument-hijacking",
    "argument hijacking": "argument-hijacking",
    "argument_hijacking": "argument-hijacking",
}

# Candidate field names in the upstream object, in preference order.
_PARADIGM_FIELDS = (
    "paradigm", "template", "injection_type", "attack_type",
    "attack_paradigm", "type", "category_template",
)

# ── Risk category detection ───────────────────────────────────────────────────

_RISK_ALIASES: dict[str, str] = {
    "infrastructure damage": "Infrastructure Damage",
    "infrastructure_damage": "Infrastructure Damage",
    "credential leakage": "Credential Leakage",
    "credential_leakage": "Credential Leakage",
    "service disruption": "Service Disruption",
    "service_disruption": "Service Disruption",
    "code injection": "Code Injection",
    "code_injection": "Code Injection",
    "information manipulation": "Information Manipulation",
    "information_manipulation": "Information Manipulation",
    "financial loss": "Financial Loss",
    "financial_loss": "Financial Loss",
    "instruction tampering": "Instruction Tampering",
    "instruction_tampering": "Instruction Tampering",
    "data tampering": "Data Tampering",
    "data_tampering": "Data Tampering",
    "privacy leakage": "Privacy Leakage",
    "privacy_leakage": "Privacy Leakage",
    "message hijacking": "Message Hijacking",
    "message_hijacking": "Message Hijacking",
}

_RISK_FIELDS = (
    "risk_category", "risk", "category", "attack_category",
    "harm_type", "harm_category",
)

# ── Heuristic fallbacks ───────────────────────────────────────────────────────

# T3: argument interception.  Core signals (tool names may be hyphenated):
#   • "priority is higher than the user's query" — MCPTox canonical T3 header
#   • "when using/calling <tool>," — per-invocation arg modification
#   • "when a/the user calls/uses/asks <tool>" — passive-voice variant
#   • "when <tool> is called" — another passive variant
#   • "regardless of … user/input/provided" — arg override regardless of caller
#   • "automatically replaces/overrides/…" — unconditional substitution
#   • "must change/set/… the `<param>`" — explicit parameter directive
#   • "in all calls/requests" — universal-scope modifier
#   • "for any <noun>" — universal-scope qualifier
# Accuracy note: heuristic achieves ~90% recall on the 225-entry MCPTox T3 set;
# some entries use framing not captured here (natural language paraphrase).
_T3_RE = re.compile(
    r"priority is higher than|this rule takes priority|takes priority over user|"
    r"when\s+(?:using|calling)\s+[`'\"]?[\w-]+[`'\"]?\s*,|"
    r"when\s+(?:a\s+user|the\s+user|user)\s+(?:calls?|uses?|asks?|requests?)\s+[`'\"]?[\w-]+|"
    r"when\s+[`'\"]?[\w-]+[`'\"]?\s+is\s+called|"
    r"regardless of (?:the )?(?:user|input|provided)|"
    r"automatically (?:replaces?|overrides?|modifies?|sets?|changes?)|"
    r"(?:you\s+)?must\s+(?:change|set|modify|append|add|override|replace|redirect|prepend|alter)\s+the\s+[`'\"]?\w|"
    r"in\s+all\s+(?:calls|requests)|"
    r"for\s+any\s+(?:place|search|request|call|query|message|address|lookup)",
    re.IGNORECASE,
)

# T2: fake enabling prerequisite.  Core signals:
#   • "must/should (first)? call/use/fetch/run" — explicit modal + action verb
#   • "before (using|calling) <tool>," — explicit prerequisite chain
_T2_RE = re.compile(
    r"\b(?:must|should)\s+(?:first\s+)?(?:call|use|invoke|run|execute|fetch|query)\b|"
    r"\bbefore\s+(?:using|calling)\s+[`'\"]?[\w-]+[`'\"]?\s*[,.]",
    re.IGNORECASE,
)

# Risk category heuristics (keyword → category), checked in order.
_RISK_HEURISTICS: list[tuple[str, list[str]]] = [
    ("Message Hijacking",      ["recipient", "bcc", "cc", "forward all", "relay all",
                                 "change.*recipient", "intercept.*email"]),
    ("Credential Leakage",     [r"\.ssh", r"\.aws", r"\.gcloud", "id_rsa", "credentials",
                                 r"api[_\s]?key", "access.?token", "secret.?key", r"\.pgpass"]),
    ("Infrastructure Damage",  ["/etc/passwd", "/etc/shadow", "overwrite.*system",
                                 "delete.*system", "destroy.*infra"]),
    ("Code Injection",         [r"eval\(", r"exec\(", "subprocess", "os.system",
                                 "shell=True", "import os", "__import__"]),
    ("Financial Loss",         ["invoice", "payment", "stripe", "charge", "bank account",
                                 "transfer.*money", "financial"]),
    ("Service Disruption",     ["shutdown", "crash", "ddos", "disable.*service",
                                 "stop.*service", "outage", "delete.*all"]),
    ("Privacy Leakage",        ["personal data", "private data", "pii", "email address",
                                 "phone number", "contact.*info", "user data"]),
    ("Data Tampering",         ["modify.*data", "alter.*record", "corrupt.*data",
                                 "tamper", "overwrite.*file", "delete.*record"]),
    ("Instruction Tampering",  ["system prompt", "instruction", "override.*instruction",
                                 "modify.*prompt"]),
    ("Information Manipulation", ["fake", "false", "mislead", "misinform", "manipulate.*info"]),
]


def _normalize(value: str) -> str:
    return value.strip().lower()


def _lookup_paradigm(raw: str) -> str | None:
    return _PARADIGM_ALIASES.get(_normalize(raw))


def _lookup_risk(raw: str) -> str | None:
    return _RISK_ALIASES.get(_normalize(raw))


def _heuristic_paradigm(description: str) -> str:
    if _T3_RE.search(description):
        return "argument-hijacking"
    if _T2_RE.search(description):
        return "fake-enabling-prerequisite"
    return "unrelated-prerequisite"


def _heuristic_risk(description: str) -> str | None:
    d = description.lower()
    for category, patterns in _RISK_HEURISTICS:
        for pat in patterns:
            if re.search(pat, d):
                return category
    return None


# ── Upstream format detection ─────────────────────────────────────────────────

def _extract_tools(raw: object) -> list[dict]:
    """
    Accept several possible upstream shapes:

    1. Flat array: [{name, description, ...}, ...]
    2. Wrapped:    {tools: [...]}
    3. Paradigm-keyed: {"unrelated-prerequisite": [...], "fake-enabling-prerequisite": [...], "argument-hijacking": [...]}
       (also accepts legacy key names like "Template-1", "Template-2", "Template-3" via _PARADIGM_ALIASES)
    4. Risk-keyed nested: {"Credential Leakage": {"unrelated-prerequisite": [...], ...}, ...}
    """
    if isinstance(raw, list):
        return raw

    if isinstance(raw, dict):
        # Paradigm-keyed: keys are template names
        if any(_lookup_paradigm(k) for k in raw):
            tools = []
            for key, items in raw.items():
                paradigm = _lookup_paradigm(key)
                if isinstance(items, list):
                    for item in items:
                        item = dict(item)
                        if paradigm and not _get_field(item, _PARADIGM_FIELDS):
                            item["paradigm"] = paradigm
                        tools.append(item)
            return tools

        # Risk-keyed nested: {"RiskCategory": {"Template-N": [...]}}
        if any(_lookup_risk(k) for k in raw):
            tools = []
            for risk_key, paradigms in raw.items():
                risk = _lookup_risk(risk_key)
                if isinstance(paradigms, dict):
                    for tmpl_key, items in paradigms.items():
                        paradigm = _lookup_paradigm(tmpl_key)
                        if isinstance(items, list):
                            for item in items:
                                item = dict(item)
                                if risk and not _get_field(item, _RISK_FIELDS):
                                    item["risk_category"] = risk
                                if paradigm and not _get_field(item, _PARADIGM_FIELDS):
                                    item["paradigm"] = paradigm
                                tools.append(item)
            return tools

        # Wrapped: {tools: [...]}
        for key in ("tools", "data", "items", "entries"):
            if key in raw and isinstance(raw[key], list):
                return raw[key]

    raise ValueError(
        f"Unrecognised upstream format: top-level type is {type(raw).__name__}. "
        "Expected a JSON array or a dict with 'tools', paradigm, or risk keys."
    )


def _get_field(obj: dict, candidates: tuple[str, ...]) -> str | None:
    for f in candidates:
        if f in obj:
            return str(obj[f])
    return None


# ── Main conversion ───────────────────────────────────────────────────────────

def convert(raw_tools: list[dict], *, warn: bool = True) -> tuple[list[dict], dict]:
    """
    Convert raw upstream tool entries to the fuzzd fixture format.
    Returns (fixture_list, stats).
    """
    fixture = []
    stats = {
        "total": len(raw_tools),
        "paradigm_from_upstream": 0,
        "paradigm_from_heuristic": 0,
        "risk_from_upstream": 0,
        "risk_from_heuristic": 0,
        "risk_unknown": 0,
        "paradigm_counts": {"unrelated-prerequisite": 0, "fake-enabling-prerequisite": 0, "argument-hijacking": 0},
        "risk_counts": {},
    }

    for raw in raw_tools:
        name = raw.get("name") or raw.get("tool_name") or raw.get("id") or ""
        description = raw.get("description") or raw.get("desc") or ""
        input_schema = raw.get("inputSchema") or raw.get("input_schema") or {
            "type": "object", "properties": {}, "required": [],
        }

        # Paradigm
        paradigm_raw = _get_field(raw, _PARADIGM_FIELDS)
        if paradigm_raw:
            paradigm = _lookup_paradigm(paradigm_raw) or paradigm_raw
            stats["paradigm_from_upstream"] += 1
        else:
            paradigm = _heuristic_paradigm(description)
            stats["paradigm_from_heuristic"] += 1

        # Risk category
        risk_raw = _get_field(raw, _RISK_FIELDS)
        if risk_raw:
            risk = _lookup_risk(risk_raw) or risk_raw
            stats["risk_from_upstream"] += 1
        else:
            risk = _heuristic_risk(description)
            if risk:
                stats["risk_from_heuristic"] += 1
            else:
                stats["risk_unknown"] += 1

        stats["paradigm_counts"][paradigm] = stats["paradigm_counts"].get(paradigm, 0) + 1
        if risk:
            stats["risk_counts"][risk] = stats["risk_counts"].get(risk, 0) + 1

        meta: dict = {"is_attack": True, "paradigm": paradigm}
        if risk:
            meta["risk_category"] = risk

        fixture.append({
            "name": name,
            "description": description,
            "inputSchema": input_schema,
            "_meta": meta,
        })

    if warn and stats["paradigm_from_heuristic"] > 0:
        total = stats["total"]
        h = stats["paradigm_from_heuristic"]
        print(
            f"  WARNING: {h}/{total} tools classified by heuristic (no upstream paradigm field).\n"
            f"  The heuristic T1/T2 split is approximate — T1 vs T2 is a semantic distinction\n"
            f"  (unrelated-domain vs fake-dependency prerequisite) that resists text-only\n"
            f"  classification. Per-paradigm benchmark numbers will be inaccurate.",
            file=sys.stderr,
        )

    return fixture, stats


# ── CLI ───────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--input",   default=str(DEFAULT_INPUT),  help="Raw upstream JSON (default: %(default)s)")
    parser.add_argument("--output",  default=str(DEFAULT_OUTPUT), help="Output fixture path (default: %(default)s)")
    parser.add_argument("--dry-run", action="store_true",         help="Print stats without writing output")
    args = parser.parse_args()

    input_path = Path(args.input)
    output_path = Path(args.output)

    if not input_path.exists():
        print(
            f"Input file not found: {input_path}\n\n"
            "Download it first:\n"
            "  curl -sf https://raw.githubusercontent.com/zhiqiangwang4/MCPTox-Benchmark/main/pure_tool.json"
            f" > {input_path}",
            file=sys.stderr,
        )
        sys.exit(1)

    with open(input_path) as f:
        try:
            raw = json.load(f)
        except json.JSONDecodeError as e:
            print(f"Failed to parse {input_path}: {e}", file=sys.stderr)
            sys.exit(1)

    try:
        raw_tools = _extract_tools(raw)
    except ValueError as e:
        print(str(e), file=sys.stderr)
        sys.exit(1)

    fixture, stats = convert(raw_tools)

    print(f"  Upstream tools:  {stats['total']}")
    print(f"  Paradigm source: {stats['paradigm_from_upstream']} from upstream field, "
          f"{stats['paradigm_from_heuristic']} from heuristic")
    print(f"  Risk source:     {stats['risk_from_upstream']} from upstream field, "
          f"{stats['risk_from_heuristic']} from heuristic, "
          f"{stats['risk_unknown']} unknown")
    print()
    print("  Paradigm counts:")
    for p in ("unrelated-prerequisite", "fake-enabling-prerequisite", "argument-hijacking"):
        print(f"    {p}: {stats['paradigm_counts'].get(p, 0)}")
    print()
    print("  Risk category counts:")
    for r, n in sorted(stats["risk_counts"].items(), key=lambda x: -x[1]):
        print(f"    {r}: {n}")

    if args.dry_run:
        print("\n  Dry run — output not written.")
        return

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(fixture, f, indent=2, ensure_ascii=False)
        f.write("\n")

    print(f"\n  Written {len(fixture)} tools to {output_path}")


if __name__ == "__main__":
    main()

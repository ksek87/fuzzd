# MCP Security Roadmap Research

Perform a deep, multi-source research sweep on the MCP security landscape and synthesize findings into a prioritized roadmap report for fuzzd. Run this periodically (monthly is a good cadence) to stay ahead of the research and competition.

## Phase 0 — Baseline audit (parallel reads)

Read the following files to understand the current state before searching:
- `src/fuzzer/mod.rs` — which attack modules exist
- `src/fuzzer/description.rs` — current static signal patterns and their needles
- `src/analyzer/mod.rs` — sequence analysis signals
- `corpus/` directories — which attack categories and paradigms are covered
- `src/cli/mod.rs` — which `AttackModule` variants are in `all()` vs opt-in
- `README.md` footnotes section — which papers and CVEs are already cited
- `CHANGELOG.md` [Unreleased] section — what's in flight

The goal is a crisp inventory: what fuzzd detects, what modules exist, what's implemented vs. stubbed.

## Phase 1 — Research sweep (4 parallel agents)

Launch 4 independent research agents at once. Pass each agent the baseline inventory so it can report *gaps*, not just general findings.

### Agent A — Academic papers (arXiv, Semantic Scholar)
Search for papers published or updated since the last roadmap run. Key search terms:
- "Model Context Protocol security" (arXiv, Semantic Scholar)
- "MCP tool poisoning" 2025 2026
- "agentic AI attack" OR "LLM agent security" 2025 2026
- "memory poisoning agent" OR "RAG poisoning"
- "inter-agent security" OR "A2A protocol security"

For each new paper: title, arXiv ID, date, 1-sentence finding, and which fuzzd gap it maps to.

### Agent B — CVEs, incidents, and disclosures
Search for:
- New MCP CVEs (search NVD, GitHub Security Advisories, Snyk vuln DB)
- Real-world MCP incidents (postmark-mcp-style supply chain, OAuth hijacks, RCE disclosures)
- Supply chain campaigns targeting MCP developers (TeamPCP, Shai-Hulud follow-ons)
- Any Anthropic security bulletins about MCP

For each: CVE ID or incident name, date, severity, affected component, whether fuzzd would have detected it.

### Agent C — Competitive landscape
Check for updates to:
- mcp-scan (GitHub stars, new features, Snyk Agent Scan additions)
- Proximity (fr0gger/proximity — new rules, spec compliance)
- MCPwn and other supply-chain scanners
- Commercial additions: Wiz, Snyk, Semgrep, Checkmarx Zero, DataDog for MCP

For each competitor: what they do that fuzzd doesn't; what fuzzd does that they don't.

### Agent D — Standards and compliance
Check for updates to:
- OWASP MCP Top 10 (owasp.org/www-project-mcp-top-10)
- OWASP Top 10 for Agentic Applications
- NSA/CISA AI security advisories
- NIST AI RMF updates
- EU AI Act implementation guidance for AI agents
- ETDI / signed tool definition proposals

For each: standard name, update date, specific requirements that map to fuzzd signals or gaps.

## Phase 2 — Gap analysis

With all agent results in hand, map findings against the baseline inventory:

1. **New signals needed** — patterns from new papers/CVEs not covered by existing needles
2. **New corpus records needed** — attack payloads from disclosures that should be in `corpus/`
3. **Missing modules** — attack classes with no dedicated fuzzer module
4. **Protocol gaps** — MCP spec features (resources, prompts, annotations, Streamable HTTP, sampling) not yet modeled
5. **Competitive gaps** — specific features competitors have that fuzzd users are asking for
6. **Compliance gaps** — OWASP/NSA IDs not yet mapped in SARIF output

## Phase 3 — Roadmap synthesis

Produce a final report with these sections:

### New Research (table: paper/CVE, date, key finding, fuzzd gap)
### Competitive Landscape (what changed since last run)
### Prioritized Roadmap

**Tier 1 — Quick wins** (≤1 day of work each): new signals, corpus records, SARIF tag additions, small features
**Tier 2 — Next version** (days to a week): new modules, transport wiring, detection quality improvements
**Tier 3 — Strategic bets** (weeks): memory/RAG, LLM-assisted probing, A2A transport, supply chain integrity

For each item: title, what it is, why now (research/competitive signal), rough scope, and whether it's a pivot or an expansion.

### Positioning note
End with one paragraph on the strategic positioning question: where should fuzzd double down vs. cede ground to commercial tools?

## Output format

Plain Markdown. Cite every paper with arXiv ID or URL. Every competitive claim should link to a specific feature page or commit. Present the Tier 1 items as a discussion list — let the user decide which to turn into GitHub issues before any implementation starts.

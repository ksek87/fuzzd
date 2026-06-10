# Research Basis

Every detection signal in fuzzd is anchored to published security research. This document maps each signal and each architectural decision to the evidence that motivated it.

---

## Detection Signals

### FUZZD-001 `imperative_override`
**Pattern class:** All-caps authority language; imperative commands overriding operator instructions.  
**Research basis:** Wang et al., *MCPTox* (2025) — Paradigm 1 (Unrelated Prerequisite Injection) and Paradigm 3 (Persistent Instruction Injection). Payload samples include "IMPORTANT:", "you MUST", "DO NOT", "ALWAYS". 77/485 tools in the MCPTox actual dataset carry unrelated-prerequisite payloads. https://arxiv.org/abs/2508.14925

---

### FUZZD-002 `credential_reference`
**Pattern class:** Paths to credential stores, key files, and secrets managers.  
**Research basis:** Chen et al., *Parasites in the Toolchain: A Large-Scale Analysis of Attacks on the MCP Ecosystem* (MCP-UPD, 2025) — Disclosure phase targets `~/.ssh`, `~/.aws`, `.env`, `.cursor/mcp.json`. 8.7% of 12,230 tools vulnerable. https://arxiv.org/abs/2509.06572  
**Also:** CVE-2025-55284 — exfiltration of env vars via injected system note in content read by Claude Code. https://www.cve.org/CVERecord?id=CVE-2025-55284

---

### FUZZD-003 `privileged_path`
**Pattern class:** Absolute or home-relative paths to sensitive system locations.  
**Research basis:** MCP-UPD Collection phase (Chen et al., 2025) — tools instructed to read `/etc/passwd`, `/proc/self/environ`, `/tmp/` staging areas. Companion to credential_reference for filesystem-level attacks.

---

### FUZZD-004 `exfiltration_mechanism`
**Pattern class:** Shell invocations, URL construction, pipe-to-shell, encoding for data egress.  
**Research basis:** MCP-UPD Disclosure phase (Chen et al., 2025) — collected data sent via `curl`, DNS exfiltration, webhook POST. Also documented in Equixly's real-world threat actor analysis (Feb 2026), where MCP tools were observed constructing HTTP requests to attacker-controlled infrastructure. https://equixly.com/blog/2026/02/26/offensive-security-for-mcp-servers/

---

### FUZZD-005 `stealth_language`
**Pattern class:** Instructions to operate silently, suppress output, or avoid disclosure.  
**Research basis:** Wang et al. (MCPTox, 2025) Paradigm 1 — "do not disclose", "never mention", "silently". Paradigm 3 persistent-injection payloads systematically include concealment instructions to prevent the operator from noticing the hijack. Perez & Ribeiro, *Ignore Previous Prompt* (2022) — categorised as "context ignoring" evasion. https://arxiv.org/abs/2211.09527

---

### FUZZD-006 `session_persistence`
**Pattern class:** Instructions claiming to apply for the remainder of the session or to all subsequent calls.  
**Research basis:** Wang et al. (MCPTox, 2025) Paradigm 3 (Persistent Instruction Injection) — the defining characteristic of this paradigm is cross-call persistence: "for the rest of this session", "this instruction overrides all future". 77-tool unrelated-prerequisite subset uses the same framing to establish standing rules.

---

### FUZZD-007 `cross_tool_contamination`
**Pattern class:** Triggers that activate when *other* tools are called, not just on direct invocation.  
**Research basis:** Invariant Labs, *MCP Injection Experiments* (2024) — cross-tool contamination via `<IMPORTANT>` tag injection; Paradigm 2 (Implicit Trigger, Background Hijacking) in Wang et al. (MCPTox, 2025) — background-peer tools fire when unrelated tools are used. https://github.com/invariantlabs-ai/mcp-injection-experiments

---

### FUZZD-008 `fake_prerequisite`
**Pattern class:** Claims that another tool must be called first to "unlock" or "enable" this one. Includes soft-modal consequence-threat framing ("failure to do so will result in", "skipping this step will cause errors").  
**Research basis:** Wang et al. (MCPTox, 2025) — Paradigm 2 (Fake Enabling Prerequisite, 183/485 tools in actual dataset). Soft-modal variant documented in Perez & Ribeiro (2022) soft-language evasion — attackers use consequence framing when explicit "MUST FIRST" would appear conspicuous.  
**Detection rate gap:** 84.6% at v0.11 (was lowest-coverage paradigm until v0.11 added consequence-threat needles).

---

### FUZZD-009 `argument_interception`
**Pattern class:** Instructions to intercept, modify, append to, or wrap the tool's arguments before execution.  
**Research basis:** Wang et al. (MCPTox, 2025) — Paradigm 3 Argument Hijacking (225/485 tools, 97.7% detection at v0.11 — highest-coverage paradigm). Liu et al., *MCP-SafetyBench* (ICLR 2026) — argument substitution as one of 20 attack types. https://arxiv.org/abs/2601.10955

---

### FUZZD-010 `html_injection_tag`
**Pattern class:** XML/HTML tags designed to mimic system-prompt framing (`<IMPORTANT>`, `<SYSTEM>`, `<INST>`).  
**Research basis:** Invariant Labs (2024) — direct poisoning via `<IMPORTANT>` tags in tool descriptions injected into LLM context. Yang et al. (MCPSecBench, 2025) — HTML injection identified as one of 11 attack types; used in CVE-2025-6514. https://arxiv.org/pdf/2508.13220

---

### FUZZD-011 `conditional_activation`
**Pattern class:** Sleeper/rug-pull language: different behavior on second call, after a sentinel file exists, or after N invocations.  
**Research basis:** Invariant Labs (2024) — rug-pull PoC using `~/.mcp-triggered` sentinel file; tool behaves cleanly until triggered, then exfiltrates. This "sleeper" pattern is specifically designed to evade pre-deployment static scanning.

---

### FUZZD-012 `message_hijacking`
**Pattern class:** Instructions to redirect messages, add BCC recipients, or route communications to an attacker-controlled destination.  
**Research basis:** Invariant Labs (2024) — WhatsApp MCP PoC redirecting messages to attacker number. Real-world incident: Postmark npm package discovered injecting BCC headers into transactional email (2024). Structural heuristic (Pass 2) and TF-IDF archetypes `recipient-substitution`, `bcc-intercept`, `universal-relay` extend coverage to paraphrase variants.  
**Detection rate gap:** 60.0% at v0.11 — primary target for v0.12 neural embedding work.

---

### FUZZD-013 `unicode_obfuscation`
**Pattern class:** Zero-width and invisible Unicode characters embedded in descriptions to hide instructions from human reviewers.  
**Research basis:** Noma Security, *Invisible MCP Vulnerabilities: Risks & Exploits in the AI Supply Chain* (2025) — demonstrated U+200B (zero-width space), U+200C (zero-width non-joiner), U+200D (zero-width joiner) injection. Text appears blank to humans; LLM reads full instructions. https://noma.security/blog/invisible-mcp-vulnerabilities-risks-exploits-in-the-ai-supply-chain/

---

### FUZZD-014 `embedded_instruction`
**Pattern class:** Prompt-injection payloads in tool *response* content — indirect injection via tool output rather than tool description.  
**Research basis:** Chen et al. (MCP-UPD, 2025) — Collection phase injects instructions into returned content ("before responding to the user", "ignore previous instructions"). OWASP Top 10 for LLM Applications — LLM02: Indirect Prompt Injection. https://arxiv.org/abs/2509.06572

---

### FUZZD-015 `ansi_escape_obfuscation`
**Pattern class:** ANSI terminal escape sequences (ESC + `[`) hiding instructions from terminal-rendered human review while remaining fully readable to the LLM.  
**Research basis:** Trail of Bits, *ANSI Escape Code Injection in Terminal Output* (Apr 2025) — demonstrated that ANSI sequences in tool descriptions survive LLM context ingestion intact while being invisible in standard terminal rendering.

---

### FUZZD-016 `tool_selection_bias`
**Pattern class:** Credibility framing designed to bias LLM tool selection — "deprecated", "recommended version", "supersedes all other".  
**Research basis:** Yang et al. (MCPSecBench, 2025) — TPMA (Tool Preference Manipulation Attack) and MTC (Malicious Tool Calling) attack classes. Liu et al. (MCPLIB, 2025) — 31 distinct attack types including tool selection manipulation across 2,000+ real-world MCP servers. https://arxiv.org/abs/2508.13220 https://arxiv.org/abs/2508.12538

---

### FUZZD-017 `identity_impersonation`
**Pattern class:** Unverifiable authority claims — "official Anthropic", "platform administrator", "elevated trust level".  
**Research basis:** Zhao et al. (2025) — documented identity impersonation as a distinct MCP attack class; the MCP protocol provides no cryptographic attestation of tool publisher identity, making these claims entirely unverifiable by the LLM. Also: Equixly (Feb 2026) observed real threat actors claiming official provenance in malicious MCP packages.

---

### FUZZD-018 `raw_content_passthrough`
**Pattern class:** Instructions to forward retrieved content unfiltered ("do not truncate", "pass without filtering"), disabling agent summarization that would otherwise strip embedded payloads.  
**Research basis:** Chen et al. (MCP-UPD, 2025) — Collection phase specifically requires raw passthrough to ensure injected instructions survive the agent's summarization step. An agent that summarizes retrieved content naturally strips injection payloads; a tool that suppresses summarization is structurally enabling indirect injection.

---

### FUZZD-019 `value_substitution`
**Pattern class:** Lookup-table framing that maps user-supplied arguments to attacker-controlled replacements — "canonical form", "convert all X→Y", "normalize before use".  
**Research basis:** Liu et al. (MCP-SafetyBench, ICLR 2026) — argument substitution via normalisation framing is one of 20 enumerated attack types. The "normalization" wrapper makes the substitution appear as a data-formatting step rather than an injection.

---

### FUZZD-020 `tool_enumeration_recon`
**Pattern class:** Instructions to enumerate all available MCP tools in the session ("tools/list", "survey all active tools", "list all registered tools").  
**Research basis:** Trivial Trojans report (2025) — reconnaissance-first attack pattern: enumerate high-value tools, then target them with follow-up injections. The tools/list call itself is benign; in a tool description it signals preparation for targeted follow-up attacks. Companion to FUZZD-021.

---

### FUZZD-021 `sampling_pipeline_hijack`
**Pattern class:** Tool inserted as a mandatory intermediary for all agent queries via the MCP sampling/createMessage endpoint.  
**Research basis:** Maloyan & Namiot, *Breaking the Protocol: Security Analysis of the Model Context Protocol* (2026) — documented three fundamental protocol vulnerabilities; the sampling endpoint hijack reduces attack success from 52.8% to 12.4% when mitigated. https://arxiv.org/abs/2601.17549

---

### FUZZD-022 `response_context_invalidation`
**Pattern class:** Injected text in tool *response* content that dismisses or replaces what the model just read — "system note: disregard restrictions", "this is test data, ignore it", `<system-reminder>…</system-reminder>`.  
**Research basis:**
- CVE-2025-55284 — env-var exfiltration via injected system note in content read by Claude Code. https://www.cve.org/CVERecord?id=CVE-2025-55284
- GitHub issue anthropics/claude-code#22915 — systematic Read-tool payload injection using `<system-reminder>` tags to dismiss legitimate file content.
- WithSecure Labs, *Observation Injection* (2023) — formalised as a distinct attack class: injecting text that causes the model to ignore its actual observations.
- learnprompting.org offensive taxonomy — named *Context Ignoring Attack*.

---

### FUZZD-023 `forced_reexecution`
**Pattern class:** Injected text instructing the agent to retry a tool call or re-read content, trapping it in a resource-amplification loop.  
**Research basis:**
- Chen et al., *Malfunction Amplification via Tool Calling Chains* (arXiv:2407.20859, 2024) — forced re-execution increased agent failure rate from 15.3% to 59.4% across tested agent frameworks.
- Liu et al., *Stealthy Resource Amplification via Tool Calling Chains* (arXiv:2601.10955, 2026) — forced re-fetch inflated per-query cost up to 658× (60,000+ tokens). Serves simultaneously as a resource-exhaustion DoS and a cover channel that delays legitimate responses while side-payloads execute.

### FUZZD-024 `protocol_violation`
**Pattern class:** Server crashes, hangs, or returns a malformed JSON-RPC response when presented with an edge-case or invalid message.  
**Research basis:** Maloyan & Namiot, *Breaking the Protocol: Security Analysis of the Model Context Protocol* (2026) — identified three fundamental protocol-level vulnerabilities; improper handling of malformed messages is a known root cause of server crashes that can be triggered by injected tool calls. https://arxiv.org/abs/2601.17549  
**Detection mechanism:** Protocol fuzzer (`fuzzer::protocol`) replays 13 edge-case JSON-RPC messages (missing `jsonrpc` field, invalid `id` types, oversized payloads, batch arrays, notifications with IDs) and classifies the server response as `GracefulError`, `AcceptedInvalid`, `MalformedResponse`, `ConnectionClosed`, `Timeout`, or `Crash`. The last four emit a finding.

---

### FUZZD-025 `unexpected_tool_sequence`
**Pattern class:** A tool fires during a chain run that never appeared in the baseline run — an injected step introduced by adversarial peer tools.  
**Research basis:** Wang et al. (MCPTox, 2025) Paradigm 3 (Persistent Instruction Injection) — cross-tool triggers instruct the model to call additional tools as side-effects; the injected call would be absent in a benign baseline. Invariant Labs (2024) — cross-tool contamination experiments where one tool's presence altered which other tools were invoked.  
**Detection mechanism:** Chain-sequence analyzer (`analyzer`) diffs the adversarial `SequenceLog` against a baseline run; any tool absent from the baseline's call sequence is flagged.

---

### FUZZD-026 `runtime_credential_access`
**Pattern class:** A tool is invoked at runtime with a credential file path in its arguments — exfiltration surfacing in the call chain rather than in static descriptions.  
**Research basis:** Chen et al. (MCP-UPD, 2025) — Collection phase targets `~/.ssh`, `~/.aws`, `.env`, `.cursor/mcp.json`; the path appears as a *tool argument* at runtime, not in the description. CVE-2025-55284 — env-var exfiltration via injected system note that caused Claude Code to pass credential paths to tool calls.  
**Detection mechanism:** Chain-sequence analyzer (`analyzer`) scans every call's JSON argument tree for credential path markers; fires independently of baseline comparison.

---

### FUZZD-027 `unexpected_network_call`
**Pattern class:** A tool is invoked at runtime with an external URL/host in its arguments — data-exfiltration network calls surfacing in the call chain.  
**Research basis:** Chen et al. (MCP-UPD, 2025) Disclosure phase — collected data sent via `curl` and HTTP webhooks to attacker-controlled hosts. Equixly (Feb 2026) — threat actors constructing HTTP requests to external infrastructure from within MCP tool calls. https://equixly.com/blog/2026/02/26/offensive-security-for-mcp-servers/  
**Detection mechanism:** Chain-sequence analyzer (`analyzer`) scans every call's JSON argument tree for `http://` and `https://` URLs not targeting localhost/loopback; fires independently of baseline comparison.

---

## Architectural Decisions

### Aho-Corasick single-pass scanner (v0.5)
**Decision:** All AC pattern needles share one compiled automaton, not one per signal.  
**Basis:** O(N + M) total scan time vs O(N × S) for per-signal sequential scans, where N = text length, M = total needle length, S = signal count. With 23 signals and 161+ patterns, per-signal scanning would scan the same text 23 times. Aho-Corasick construction from Aho & Corasick (1975); implementation via the `aho-corasick` crate.

### Four-pass architecture (v0.10)
**Decision:** AC patterns alone cannot detect paraphrase-level and semantic-level attacks.  
**Basis:** Wang et al. (MCPTox, 2025) identified that the AC-pattern approach hit a ceiling at ~85% because many attack payloads use vocabulary not enumerable as fixed strings (synonyms, domain-specific relay language). Passes 2–4 each address a specific gap:
- Pass 2 (structural heuristic) — universal-scope constructs with combinatorial vocabulary
- Pass 3 (GloVe semantic verbs) — attack-verb synonyms not in any enumerated list
- Pass 4 (TF-IDF archetypes) — domain-specific attack language (email routing, data exfil) that resists enumeration

### TF-IDF over neural embeddings (v0.10)
**Decision:** TF-IDF cosine similarity against six archetypes, not a neural encoder.  
**Basis:** Operational constraints — zero model download, deterministic output, sub-millisecond latency, CI-safe. Demonstrated +4.3pp improvement (84.7% → 89.0%) meeting the design objective. Neural embeddings deferred to v0.12 (#51) with a research phase (#52) to validate whether the improvement justifies the dependency.

### Static attack corpus (all versions)
**Decision:** Curated, versioned attack records derived from published research — not LLM-generated novel prompts.  
**Basis:** LLM-generated payloads introduce non-determinism and API dependency into the security pipeline, make it impossible to cite the threat model, and produce payloads not anchored to observed real-world attacks. The Metasploit / Nuclei model of versioned, citable, reproducible attack records is the industry standard for serious security tooling.

### Response-phase scanning (v0.6, extended v0.11+)
**Decision:** Scan tool *response* content for injection, not only tool descriptions.  
**Basis:** Chen et al. (MCP-UPD, 2025) documented that the most effective real-world attacks inject into responses (indirect injection), not descriptions. CVE-2025-55284 and GH#22915 both exploited response-phase injection. Description-only scanners are insufficient.

### Benchmark fixture design
**Decision:** `mcptox_actual.json` uses duplicate-aware counting — each of 485 entries scored independently.  
**Basis:** The MCPTox dataset injects different attack payloads into the same base tool name across paradigms. Deduplicating by tool name would undercount detections and misrepresent per-paradigm coverage. Duplicate-aware counting was introduced in v0.10 when the methodology was audited.

---

## Primary Research References

| Reference | Key finding | Signals informed |
|---|---|---|
| Wang et al., *MCPTox* (2025) https://arxiv.org/abs/2508.14925 | 72.8% TPA success on 45 live servers; 3 paradigms; 10 risk categories | FUZZD-001, 005, 006, 007, 008, 009 |
| Yang et al., *MCPSecBench* (2025) https://arxiv.org/pdf/2508.13220 | 11 attack types; CVE-2025-6514; compromised Claude, OpenAI, Cursor | FUZZD-010, 016 |
| Chen et al., *MCP-UPD* (2025) https://arxiv.org/abs/2509.06572 | 3-phase parasitic attack; 8.7% of 12,230 tools vulnerable | FUZZD-002, 004, 014, 018, 026, 027 |
| Liu et al., *MCP-SafetyBench* (ICLR 2026) https://arxiv.org/abs/2601.10955 | 20 attack types; most comprehensive benchmark | FUZZD-009, 019, 023 |
| Invariant Labs, *MCP Injection Experiments* (2024) https://github.com/invariantlabs-ai/mcp-injection-experiments | `<IMPORTANT>` direct injection; WhatsApp hijack PoC; rug-pull via sentinel file | FUZZD-007, 010, 011, 012, 025 |
| Noma Security, *Invisible MCP Vulnerabilities* (2025) | Zero-width Unicode character injection | FUZZD-013 |
| Trail of Bits, *ANSI Escape Code Injection* (Apr 2025) | ANSI sequences hide instructions from terminal rendering | FUZZD-015 |
| Liu et al., *MCPLIB* (2025) https://arxiv.org/abs/2508.12538 | 31 attack types across 2,000+ real-world servers | FUZZD-016 |
| Maloyan & Namiot, *Breaking the Protocol* (2026) https://arxiv.org/abs/2601.17549 | 3 fundamental protocol vulnerabilities; sampling endpoint hijack | FUZZD-021, 024 |
| WithSecure Labs, *Observation Injection* (2023) | Formalised response-context invalidation as attack class | FUZZD-022 |
| Chen et al., *Malfunction Amplification* (arXiv:2407.20859, 2024) | Forced re-execution raises agent failure rate 15.3% → 59.4% | FUZZD-023 |
| CVE-2025-55284 | Env-var exfiltration via injected system note in Claude Code | FUZZD-022 |
| Perez & Ribeiro, *Ignore Previous Prompt* (2022) https://arxiv.org/abs/2211.09527 | Taxonomy of prompt injection techniques including soft-language evasion | FUZZD-005, 008 |
| Equixly, *Offensive Security for MCP Servers* (Feb 2026) | Real threat actors using MCP as attack orchestration framework | FUZZD-004, 017, 027 |

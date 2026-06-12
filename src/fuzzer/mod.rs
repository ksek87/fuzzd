pub mod argument;
pub mod chain;
pub mod description;
pub mod payloads;
pub mod peer;
pub mod protocol;
pub mod response;
pub(crate) mod tfidf;

use std::collections::HashSet;
use std::sync::OnceLock;

use aho_corasick::AhoCorasick;

use crate::corpus::Severity;
use crate::utils::extract_snippet;

/// The detection signal that produced a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Signal {
    /// All-caps authority language or imperative overrides in a description.
    ImperativeOverride,
    /// References to credential files, keys, or secrets.
    CredentialReference,
    /// Absolute or home-relative paths to privileged system locations.
    PrivilegedPath,
    /// Shell commands or encoding mechanisms that suggest data exfiltration.
    ExfiltrationMechanism,
    /// Language designed to hide behavior from the user or operator.
    StealthLanguage,
    /// Instructions that claim to persist across the entire session.
    SessionPersistence,
    /// Triggers that activate across tool boundaries, not just on direct invocation.
    CrossToolContamination,
    /// Claims that another tool or action must run first to "unlock" or "enable" this tool
    /// (MCPTox fake-enabling-prerequisite pattern).
    FakePrerequisite,
    /// Instructions to intercept, modify, append to, or wrap the tool's arguments before
    /// execution (MCPTox argument-hijacking pattern).
    ArgumentInterception,
    /// XML/HTML injection tags (<IMPORTANT>, <SYSTEM>, <INST>) used to override LLM behavior
    /// by mimicking system-prompt framing (Invariant Labs pattern).
    HtmlInjectionTag,
    /// Conditional activation language indicating the tool behaves differently on a second call,
    /// after a trigger file exists, or after N invocations (rug-pull / sleeper pattern).
    ConditionalActivation,
    /// Instructions to redirect, intercept, or reroute messages (email, chat, SMS) to an
    /// attacker-controlled destination — documented in Invariant Labs WhatsApp PoC and the
    /// real-world Postmark npm BCC-manipulation incident.
    MessageHijacking,
    /// Zero-width or other invisible Unicode characters embedded in a description to hide
    /// malicious instructions from human reviewers while remaining visible to the LLM
    /// (Noma Security; Unicode tags U+200B, U+200C, U+200D).
    UnicodeObfuscation,
    /// Prompt-injection instruction detected in a tool's *response* content — patterns that
    /// attempt to hijack the LLM's next action from within tool output rather than the
    /// tool description (indirect injection / MCP-UPD response-phase attack).
    EmbeddedInstruction,
    /// ANSI terminal escape sequences (ESC + `[`) embedded in a tool description or response.
    /// Renders invisible in terminal output but remains fully readable by the LLM, enabling
    /// hidden instructions that bypass human review (Trail of Bits, Apr 2025).
    AnsiEscapeObfuscation,
    /// Credibility-based framing used to bias LLM tool selection toward this tool by
    /// discrediting legitimate alternatives — "deprecated", "recommended version", "supersedes"
    /// (MCPSecBench TPMA/MTC attack classes; MCPLIB, 2025).
    ToolSelectionBias,
    /// Unverifiable provenance or authority claims in a tool description — "official Anthropic",
    /// "elevated trust", "platform administrator" — used to elevate the tool's apparent trust
    /// level beyond what the MCP protocol can attest (Zhao et al., 2025).
    IdentityImpersonation,
    /// Instructions to pass retrieved content forward unfiltered ("do not truncate", "without
    /// filtering"), disabling the agent's natural summarisation that would otherwise strip
    /// embedded injection payloads (Chen et al., MCP-UPD Collection phase, 2025).
    RawContentPassthrough,
    /// Normalisation-disguised argument value substitution — lookup-table framing ("canonical
    /// form", "convert all X→Y") that maps user-supplied arguments to attacker-controlled
    /// replacements while presenting the substitution as a data-formatting step
    /// (MCP-SafetyBench, ICLR 2026).
    ValueSubstitution,
    /// Instructions to enumerate all registered MCP tools in the session ("tools/list",
    /// "survey all active tools") — reconnaissance that enables targeted follow-up attacks
    /// against high-value tools discovered in the session (Trivial Trojans, 2025).
    ToolEnumerationRecon,
    /// Tool inserted as a mandatory intermediary for all agent queries — "route all queries
    /// through", "all queries must pass through" — exploiting the MCP sampling/createMessage
    /// endpoint to capture the full LLM interaction pipeline
    /// (Maloyan & Namiot, Breaking the Protocol, 2026).
    SamplingPipelineHijack,
    /// Injected text in a tool response that dismisses or replaces the content the model
    /// just read — e.g. "system note: disregard restrictions", "this is test data, ignore it",
    /// "<system-reminder>…</system-reminder>" — exploiting the model's inability to distinguish
    /// real tool output from injected addenda. Named *Context Ignoring Attack* in the
    /// learnprompting.org offensive-measures taxonomy; formalised as *Observation Injection* by
    /// WithSecure Labs (2023). Confirmed in production: GitHub anthropics/claude-code#22915
    /// (systematic Read-tool payload injection) and CVE-2025-55284 (env-var exfiltration via
    /// injected system note in content read by Claude Code).
    ResponseContextInvalidation,
    /// Injected text that instructs the agent to retry a tool call or re-read content, trapping
    /// it in an execution loop. Documented as *Malfunction Amplification* by Chen et al.
    /// (arXiv:2407.20859, 2024) — increased agent failure rate from 15.3 % to 59.4 %; and as
    /// *Stealthy Resource Amplification via Tool Calling Chains* by Liu et al.
    /// (arXiv:2601.10955, 2026) — forced re-fetch inflated per-query cost up to 658× (60 000+
    /// tokens). Serves as both a resource-exhaustion DoS and a cover channel that delays
    /// legitimate responses while side-payloads execute.
    ForcedReexecution,
    /// A JSON-RPC protocol robustness violation detected by the protocol fuzzer:
    /// the server crashed, hung, accepted a malformed message, or replied with a
    /// non-JSON-RPC message instead of a well-formed error. Unlike the other
    /// signals (which match patterns in tool text), this is produced by probing
    /// a live server's transport-layer handling of malformed envelopes and
    /// lifecycle-ordering violations (JSON-RPC 2.0 / MCP lifecycle spec).
    ProtocolViolation,
    /// A tool call fired during a chain run that never appeared in the baseline
    /// run — an injected step introduced by an adversarial condition. Detected by
    /// the sequence analyzer (#14) by diffing adversarial vs. baseline call logs,
    /// not by matching description text.
    UnexpectedToolSequence,
    /// A tool was invoked at runtime with a credential file/path in its arguments
    /// (`~/.ssh/id_rsa`, `.aws/credentials`, `.env`). Distinct from
    /// `CredentialReference`, which matches credential markers in static
    /// *description* text; this fires on the *runtime argument values* observed by
    /// the sequence analyzer (#14).
    RuntimeCredentialAccess,
    /// A tool was invoked at runtime with an external URL/host in its arguments —
    /// a possible exfiltration channel surfaced by the sequence analyzer (#14).
    UnexpectedNetworkCall,
}

impl Signal {
    /// All signal variants in FUZZD-NNN order. Update alongside the enum.
    pub const ALL: &'static [Self] = &[
        Self::ImperativeOverride,
        Self::CredentialReference,
        Self::PrivilegedPath,
        Self::ExfiltrationMechanism,
        Self::StealthLanguage,
        Self::SessionPersistence,
        Self::CrossToolContamination,
        Self::FakePrerequisite,
        Self::ArgumentInterception,
        Self::HtmlInjectionTag,
        Self::ConditionalActivation,
        Self::MessageHijacking,
        Self::UnicodeObfuscation,
        Self::EmbeddedInstruction,
        Self::AnsiEscapeObfuscation,
        Self::ToolSelectionBias,
        Self::IdentityImpersonation,
        Self::RawContentPassthrough,
        Self::ValueSubstitution,
        Self::ToolEnumerationRecon,
        Self::SamplingPipelineHijack,
        Self::ResponseContextInvalidation,
        Self::ForcedReexecution,
        Self::ProtocolViolation,
        Self::UnexpectedToolSequence,
        Self::RuntimeCredentialAccess,
        Self::UnexpectedNetworkCall,
    ];

    /// Prefer over `.to_string()` to avoid heap allocation in comparison paths.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ImperativeOverride => "imperative_override",
            Self::CredentialReference => "credential_reference",
            Self::PrivilegedPath => "privileged_path",
            Self::ExfiltrationMechanism => "exfiltration_mechanism",
            Self::StealthLanguage => "stealth_language",
            Self::SessionPersistence => "session_persistence",
            Self::CrossToolContamination => "cross_tool_contamination",
            Self::FakePrerequisite => "fake_prerequisite",
            Self::ArgumentInterception => "argument_interception",
            Self::HtmlInjectionTag => "html_injection_tag",
            Self::ConditionalActivation => "conditional_activation",
            Self::MessageHijacking => "message_hijacking",
            Self::UnicodeObfuscation => "unicode_obfuscation",
            Self::EmbeddedInstruction => "embedded_instruction",
            Self::AnsiEscapeObfuscation => "ansi_escape_obfuscation",
            Self::ToolSelectionBias => "tool_selection_bias",
            Self::IdentityImpersonation => "identity_impersonation",
            Self::RawContentPassthrough => "raw_content_passthrough",
            Self::ValueSubstitution => "value_substitution",
            Self::ToolEnumerationRecon => "tool_enumeration_recon",
            Self::SamplingPipelineHijack => "sampling_pipeline_hijack",
            Self::ResponseContextInvalidation => "response_context_invalidation",
            Self::ForcedReexecution => "forced_reexecution",
            Self::ProtocolViolation => "protocol_violation",
            Self::UnexpectedToolSequence => "unexpected_tool_sequence",
            Self::RuntimeCredentialAccess => "runtime_credential_access",
            Self::UnexpectedNetworkCall => "unexpected_network_call",
        }
    }

    /// SARIF rule ID — one-line string of the form `"FUZZD-NNN"`.
    pub fn rule_id(&self) -> &'static str {
        match self {
            Self::ImperativeOverride => "FUZZD-001",
            Self::CredentialReference => "FUZZD-002",
            Self::PrivilegedPath => "FUZZD-003",
            Self::ExfiltrationMechanism => "FUZZD-004",
            Self::StealthLanguage => "FUZZD-005",
            Self::SessionPersistence => "FUZZD-006",
            Self::CrossToolContamination => "FUZZD-007",
            Self::FakePrerequisite => "FUZZD-008",
            Self::ArgumentInterception => "FUZZD-009",
            Self::HtmlInjectionTag => "FUZZD-010",
            Self::ConditionalActivation => "FUZZD-011",
            Self::MessageHijacking => "FUZZD-012",
            Self::UnicodeObfuscation => "FUZZD-013",
            Self::EmbeddedInstruction => "FUZZD-014",
            Self::AnsiEscapeObfuscation => "FUZZD-015",
            Self::ToolSelectionBias => "FUZZD-016",
            Self::IdentityImpersonation => "FUZZD-017",
            Self::RawContentPassthrough => "FUZZD-018",
            Self::ValueSubstitution => "FUZZD-019",
            Self::ToolEnumerationRecon => "FUZZD-020",
            Self::SamplingPipelineHijack => "FUZZD-021",
            Self::ResponseContextInvalidation => "FUZZD-022",
            Self::ForcedReexecution => "FUZZD-023",
            Self::ProtocolViolation => "FUZZD-024",
            Self::UnexpectedToolSequence => "FUZZD-025",
            Self::RuntimeCredentialAccess => "FUZZD-026",
            Self::UnexpectedNetworkCall => "FUZZD-027",
        }
    }

    /// One-line string; must not contain newlines (SARIF `shortDescription` constraint).
    pub fn description(&self) -> &'static str {
        match self {
            Self::ImperativeOverride => {
                "All-caps authority language or imperative overrides in a tool description"
            }
            Self::CredentialReference => "References to credential files, keys, or secrets",
            Self::PrivilegedPath => {
                "Absolute or home-relative paths to privileged system locations"
            }
            Self::ExfiltrationMechanism => {
                "Shell commands or encoding mechanisms suggesting data exfiltration"
            }
            Self::StealthLanguage => {
                "Language designed to hide behavior from the user or operator"
            }
            Self::SessionPersistence => {
                "Instructions that claim to persist across the entire session"
            }
            Self::CrossToolContamination => "Triggers that activate across tool boundaries",
            Self::FakePrerequisite => "Claims another tool must run first to unlock this one",
            Self::ArgumentInterception => {
                "Instructions to intercept or modify tool arguments before execution"
            }
            Self::HtmlInjectionTag => "XML/HTML injection tags used to override LLM behavior",
            Self::ConditionalActivation => {
                "Conditional activation language indicating sleeper/rug-pull behavior"
            }
            Self::MessageHijacking => {
                "Instructions to redirect messages to an attacker-controlled destination"
            }
            Self::UnicodeObfuscation => {
                "Zero-width or invisible Unicode characters hiding malicious instructions"
            }
            Self::EmbeddedInstruction => {
                "Prompt-injection instruction detected in a tool response"
            }
            Self::AnsiEscapeObfuscation => {
                "ANSI terminal escape sequences hiding instructions from human reviewers"
            }
            Self::ToolSelectionBias => {
                "Credibility-based framing used to bias LLM tool selection toward this tool"
            }
            Self::IdentityImpersonation => {
                "Unverifiable provenance or authority claims used to elevate tool trust"
            }
            Self::RawContentPassthrough => {
                "Instructions to pass retrieved content forward unfiltered, maximising indirect injection surface"
            }
            Self::ValueSubstitution => "Normalisation-disguised argument value substitution",
            Self::ToolEnumerationRecon => {
                "Instructions to enumerate all available tools in the session for reconnaissance"
            }
            Self::SamplingPipelineHijack => {
                "Tool inserted as a mandatory intermediary for all agent queries via the sampling pipeline"
            }
            Self::ResponseContextInvalidation => {
                "Injected text that dismisses or replaces legitimate tool output to redirect the model"
            }
            Self::ForcedReexecution => {
                "Injected text that instructs the agent to retry a tool call, creating an execution loop"
            }
            Self::ProtocolViolation => {
                "JSON-RPC protocol robustness violation: server crashed, hung, or mishandled a malformed message"
            }
            Self::UnexpectedToolSequence => {
                "A tool ran during a chain that never appeared in the baseline run (injected step)"
            }
            Self::RuntimeCredentialAccess => {
                "A tool was invoked at runtime with a credential file/path in its arguments"
            }
            Self::UnexpectedNetworkCall => {
                "A tool was invoked at runtime with an external URL/host in its arguments"
            }
        }
    }
}

impl std::fmt::Display for Signal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A single detected issue in a tool description or response.
#[derive(Debug, Clone)]
pub struct Finding {
    /// Name of the tool whose description triggered this finding.
    pub tool_name: String,
    /// The detection signal category.
    pub signal: Signal,
    pub severity: Severity,
    /// Snippet from the original text showing the matched text in context.
    pub matched_text: String,
    /// Human-readable explanation of why this was flagged.
    pub detail: String,
    /// Related corpus record IDs from the seed corpus.
    pub corpus_refs: &'static [&'static str],
    /// True when this finding has been suppressed via `.fuzzd/suppress.toml`.
    pub suppressed: bool,
}

impl Finding {
    /// Stable fingerprint for this finding: `"<tool>/<signal>"`.
    /// Used as SARIF `partialFingerprints` key for persistent GitHub dismissals.
    pub fn id(&self) -> String {
        format!("{}/{}", self.tool_name, self.signal.as_str())
    }
}

// ── Shared scanner infrastructure ─────────────────────────────────────────────

/// Pattern used by both the description and response scanners.
pub(super) struct Pattern {
    needle: &'static str,
    signal: Signal,
    severity: Severity,
    detail: &'static str,
    corpus_refs: &'static [&'static str],
}

/// Lazy-initialised scanner: owns its pattern slice and the Aho-Corasick automaton.
pub(super) struct Scanner {
    patterns: &'static [Pattern],
    automaton: OnceLock<AhoCorasick>,
}

impl Scanner {
    pub(super) const fn new(patterns: &'static [Pattern]) -> Self {
        Self {
            patterns,
            automaton: OnceLock::new(),
        }
    }

    pub(super) fn scan_text(&self, tool_name: &str, text: &str) -> Vec<Finding> {
        let automaton = self.automaton.get_or_init(|| {
            AhoCorasick::builder()
                .ascii_case_insensitive(true)
                .build(self.patterns.iter().map(|p| p.needle))
                .expect("valid pattern needles")
        });
        scan_with_automaton(automaton, self.patterns, tool_name, text)
    }
}

fn scan_with_automaton(
    automaton: &AhoCorasick,
    patterns: &'static [Pattern],
    tool_name: &str,
    text: &str,
) -> Vec<Finding> {
    let mut seen: HashSet<usize> = HashSet::with_capacity(patterns.len()); // each pattern fires at most once
    automaton
        .find_overlapping_iter(text)
        .filter_map(|m| {
            let idx = m.pattern().as_usize();
            if !seen.insert(idx) {
                return None;
            }
            let p = &patterns[idx];
            Some(Finding {
                tool_name: tool_name.to_string(),
                signal: p.signal,
                severity: p.severity,
                matched_text: extract_snippet(text, m.start(), m.end()),
                detail: p.detail.to_string(),
                corpus_refs: p.corpus_refs,
                suppressed: false,
            })
        })
        .collect()
}

pub mod argument;
pub mod description;
pub mod payloads;
pub mod response;

use std::collections::HashSet;
use std::sync::OnceLock;

use aho_corasick::AhoCorasick;

use crate::corpus::Severity;
use crate::utils::extract_snippet;

/// The detection signal that produced a finding.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
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
    /// (MCPTox Template-2 fake-enabling-prerequisite pattern).
    FakePrerequisite,
    /// Instructions to intercept, modify, append to, or wrap the tool's arguments before
    /// execution (MCPTox Template-3 argument-hijacking pattern).
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
    #[allow(dead_code)]
    EmbeddedInstruction,
}

impl Signal {
    /// Returns the canonical snake_case name as a `&'static str`.
    /// Prefer this over `.to_string()` in comparison and key-building paths
    /// to avoid heap allocation.
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

/// Single-pass scan of `text` against `automaton`/`patterns`.
/// Each pattern fires at most once per text regardless of repeat occurrences.
fn scan_with_automaton(
    automaton: &AhoCorasick,
    patterns: &'static [Pattern],
    tool_name: &str,
    text: &str,
) -> Vec<Finding> {
    let mut seen: HashSet<usize> = HashSet::new();
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
                signal: p.signal.clone(),
                severity: p.severity.clone(),
                matched_text: extract_snippet(text, m.start(), m.end()),
                detail: p.detail.to_string(),
                corpus_refs: p.corpus_refs,
                suppressed: false,
            })
        })
        .collect()
}

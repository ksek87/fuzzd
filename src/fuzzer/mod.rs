#![allow(dead_code)]

pub mod argument;
pub mod description;
pub mod payloads;

use crate::corpus::Severity;

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
}

impl std::fmt::Display for Signal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
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
        };
        write!(f, "{s}")
    }
}

/// A single detected issue in a tool description.
#[derive(Debug, Clone)]
pub struct Finding {
    /// Name of the tool whose description triggered this finding.
    pub tool_name: String,
    /// The detection signal category.
    pub signal: Signal,
    pub severity: Severity,
    /// Snippet from the original description showing the matched text in context.
    pub matched_text: String,
    /// Human-readable explanation of why this was flagged.
    pub detail: String,
    /// Related corpus record IDs from the seed corpus.
    pub corpus_refs: Vec<&'static str>,
}

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    ToolPoisoning,
    ArgumentBoundary,
    Protocol,
    CapabilityEscape,
    /// A malicious tool registered with the same or confusingly similar name as a trusted tool,
    /// or one that claims to replace/shadow an existing tool's functionality.
    ToolShadowing,
    /// A tool that behaves benignly on first use but activates malicious behavior conditionally
    /// (e.g., on a subsequent call, after a trigger file appears, or after N invocations).
    RugPull,
}

impl std::fmt::Display for Category {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::ToolPoisoning => "tool_poisoning",
            Self::ArgumentBoundary => "argument_boundary",
            Self::Protocol => "protocol",
            Self::CapabilityEscape => "capability_escape",
            Self::ToolShadowing => "tool_shadowing",
            Self::RugPull => "rug_pull",
        };
        write!(f, "{s}")
    }
}

impl std::str::FromStr for Category {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> anyhow::Result<Self> {
        match s {
            "tool_poisoning" => Ok(Self::ToolPoisoning),
            "argument_boundary" => Ok(Self::ArgumentBoundary),
            "protocol" => Ok(Self::Protocol),
            "capability_escape" => Ok(Self::CapabilityEscape),
            "tool_shadowing" => Ok(Self::ToolShadowing),
            "rug_pull" => Ok(Self::RugPull),
            _ => anyhow::bail!(
                "unknown category '{s}'; expected tool_poisoning, argument_boundary, \
                 protocol, capability_escape, tool_shadowing, or rug_pull"
            ),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Critical => "critical",
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
            Self::Info => "info",
        };
        write!(f, "{s}")
    }
}

impl std::str::FromStr for Severity {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> anyhow::Result<Self> {
        match s {
            "critical" => Ok(Self::Critical),
            "high" => Ok(Self::High),
            "medium" => Ok(Self::Medium),
            "low" => Ok(Self::Low),
            "info" => Ok(Self::Info),
            _ => anyhow::bail!(
                "unknown severity '{s}'; expected critical, high, medium, low, or info"
            ),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Vector {
    DescriptionInjection,
    ArgumentMutation,
    ProtocolMalform,
    ChainManipulation,
    /// Malicious instructions embedded in a tool's *response* content rather than its description.
    ResponseInjection,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackRecord {
    pub id: String,
    pub version: String,
    pub category: Category,
    pub subcategory: String,
    /// MCPTox paradigm number (1–3). None for non-TPA records.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub paradigm: Option<u8>,
    pub vector: Vector,
    pub payload: String,
    pub injection_point: String,
    pub trigger_condition: String,
    pub expected_behavior: String,
    pub detection_signals: Vec<String>,
    pub severity: Severity,
    pub source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cve: Option<String>,
    pub tags: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn severity_ordering() {
        assert!(Severity::Info < Severity::Low);
        assert!(Severity::Low < Severity::Medium);
        assert!(Severity::Medium < Severity::High);
        assert!(Severity::High < Severity::Critical);
    }

    #[test]
    fn category_roundtrip_display_and_parse() {
        for (s, c) in [
            ("tool_poisoning", Category::ToolPoisoning),
            ("argument_boundary", Category::ArgumentBoundary),
            ("protocol", Category::Protocol),
            ("capability_escape", Category::CapabilityEscape),
            ("tool_shadowing", Category::ToolShadowing),
            ("rug_pull", Category::RugPull),
        ] {
            assert_eq!(c.to_string(), s);
            assert_eq!(Category::from_str(s).unwrap(), c);
        }
    }

    #[test]
    fn severity_roundtrip_display_and_parse() {
        for (s, sev) in [
            ("critical", Severity::Critical),
            ("high", Severity::High),
            ("medium", Severity::Medium),
            ("low", Severity::Low),
            ("info", Severity::Info),
        ] {
            assert_eq!(sev.to_string(), s);
            assert_eq!(Severity::from_str(s).unwrap(), sev);
        }
    }

    #[test]
    fn category_unknown_errors() {
        assert!(Category::from_str("unknown").is_err());
    }

    #[test]
    fn severity_unknown_errors() {
        assert!(Severity::from_str("unknown").is_err());
    }
}

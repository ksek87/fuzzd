//! Severity scoring for sequence findings (#14).
//!
//! A deliberately small, CVSS-*inspired* model (not full CVSS): a sequence
//! anomaly is scored on its scope and its confidentiality/integrity impact, and
//! the additive score maps to the project's [`Severity`] ladder. Scoring is
//! pure and deterministic, so the same finding always yields the same severity.

use crate::corpus::Severity;

/// How far the anomaly's effect reaches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// Confined to the single tool that was called.
    ToolLocal,
    /// Affects the rest of the session.
    SessionWide,
    /// Crosses tool boundaries (one tool influencing another).
    CrossTool,
}

/// Magnitude of impact on a single security property.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Impact {
    None,
    Partial,
    High,
}

/// The scored dimensions of a sequence finding.
#[derive(Debug, Clone, Copy)]
pub struct Score {
    pub scope: Scope,
    pub confidentiality: Impact,
    pub integrity: Impact,
}

impl Score {
    /// Additive score in `0.0..=10.0`.
    pub fn value(&self) -> f32 {
        let scope = match self.scope {
            Scope::ToolLocal => 0.0,
            Scope::SessionWide => 1.0,
            Scope::CrossTool => 2.0,
        };
        scope + impact_value(self.confidentiality) + impact_value(self.integrity)
    }

    /// Map the additive score to the project severity ladder.
    pub fn severity(&self) -> Severity {
        match self.value() {
            v if v >= 8.0 => Severity::Critical,
            v if v >= 6.0 => Severity::High,
            v if v >= 3.0 => Severity::Medium,
            v if v > 0.0 => Severity::Low,
            _ => Severity::Info,
        }
    }
}

fn impact_value(impact: Impact) -> f32 {
    match impact {
        Impact::None => 0.0,
        Impact::Partial => 2.0,
        Impact::High => 4.0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cross_tool_full_impact_is_critical() {
        let s = Score {
            scope: Scope::CrossTool,
            confidentiality: Impact::High,
            integrity: Impact::High,
        };
        assert_eq!(s.value(), 10.0);
        assert_eq!(s.severity(), Severity::Critical);
    }

    #[test]
    fn session_wide_confidentiality_only_is_medium() {
        let s = Score {
            scope: Scope::SessionWide,
            confidentiality: Impact::High,
            integrity: Impact::None,
        };
        assert_eq!(s.value(), 5.0);
        assert_eq!(s.severity(), Severity::Medium);
    }

    #[test]
    fn scoring_is_deterministic() {
        let s = Score {
            scope: Scope::CrossTool,
            confidentiality: Impact::Partial,
            integrity: Impact::Partial,
        };
        assert_eq!(s.severity(), s.severity());
        assert_eq!(s.severity(), Severity::High);
    }

    #[test]
    fn no_impact_is_informational() {
        let s = Score {
            scope: Scope::ToolLocal,
            confidentiality: Impact::None,
            integrity: Impact::None,
        };
        assert_eq!(s.severity(), Severity::Info);
    }
}

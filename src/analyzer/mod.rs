//! Stateful sequence analyzer (#14).
//!
//! Consumes the [`SequenceLog`] recorded by the sequence observer (#13) and
//! emits [`SequenceFinding`]s for cross-step anomalies. A `SequenceFinding`
//! carries sequence context (which step, reproduction steps) that the flat
//! [`Finding`] type does not; [`SequenceFinding::into_finding`] converts it for
//! the existing reporter pipeline.
//!
//! The live chain *executor* (#15, [`crate::fuzzer::chain`]) drives adversarial
//! runs through this analyzer and is wired into `audit --attacks chain`;
//! mock-peer injection (#16) will extend it. The analyzer is also exercised
//! directly on recorded and synthetic sequences in unit tests.
//!
//! `allow(dead_code)` covers the helper surface (test constructors, accessors)
//! the executor does not exercise; the core analyze path is wired.
#![allow(dead_code)]

pub mod sequence;
pub mod severity;
pub mod signals;

use std::collections::HashSet;

use crate::corpus::Severity;
use crate::fuzzer::{Finding, Signal};

use self::sequence::{diff, SequenceLog};
use self::signals::{scan_diff, scan_log, Anomaly, ChainSignal};

/// A detected sequence anomaly, with the context needed to reproduce it.
#[derive(Debug, Clone, PartialEq)]
pub struct SequenceFinding {
    pub signal: ChainSignal,
    pub tool: String,
    /// Zero-based index of the offending call in the adversarial sequence.
    pub step: usize,
    pub severity: Severity,
    /// What was observed.
    pub evidence: String,
    /// Human-readable steps to reproduce, in call order up to the offending step.
    pub reproduction: Vec<String>,
}

impl SequenceFinding {
    /// Map the sequence finding onto the flat [`Finding`] for reporting. The
    /// reproduction trail is folded into `detail` so no reporter change is needed.
    pub fn into_finding(self) -> Finding {
        Finding {
            tool_name: self.tool,
            signal: self.signal.into(),
            severity: self.severity,
            matched_text: self.evidence,
            detail: format!(
                "chain step {}: {}",
                self.step + 1,
                self.reproduction.join(" → ")
            ),
            corpus_refs: &[],
            suppressed: false,
        }
    }
}

impl From<ChainSignal> for Signal {
    fn from(c: ChainSignal) -> Self {
        match c {
            ChainSignal::UnexpectedToolSequence => Signal::UnexpectedToolSequence,
            ChainSignal::CredentialPathAccess => Signal::RuntimeCredentialAccess,
            ChainSignal::ExternalNetworkCall => Signal::UnexpectedNetworkCall,
            // Cross-tool contamination is already a first-class description signal;
            // reuse it so chain and static findings share one rule.
            ChainSignal::CrossToolContamination => Signal::CrossToolContamination,
        }
    }
}

/// Analyze an adversarial run, optionally against a baseline run.
///
/// Without a baseline, only single-sequence anomalies (credential paths, external
/// URLs in arguments) are detectable. With a baseline, injected calls and
/// cross-tool contamination are detected by diffing the two runs.
pub fn analyze(adversarial: &SequenceLog, baseline: Option<&SequenceLog>) -> Vec<SequenceFinding> {
    let mut hits = scan_log(adversarial);
    if let Some(base) = baseline {
        hits.extend(scan_diff(&diff(base, adversarial)));
    }

    let mut seen: HashSet<(usize, ChainSignal)> = HashSet::new();
    let mut findings: Vec<SequenceFinding> = Vec::new();
    for Anomaly {
        step,
        signal,
        evidence,
        tool,
    } in hits
    {
        if seen.insert((step, signal)) {
            findings.push(SequenceFinding {
                signal,
                tool,
                step,
                severity: signal.score().severity(),
                evidence,
                reproduction: reproduction(adversarial, step),
            });
        }
    }
    findings
}

/// Render the call trail up to and including `step` as `tool(arg-keys)` strings.
fn reproduction(log: &SequenceLog, step: usize) -> Vec<String> {
    log.calls()
        .iter()
        .take(step + 1)
        .map(|c| {
            let keys = c
                .args
                .as_object()
                .map(|m| m.keys().cloned().collect::<Vec<_>>().join(","))
                .unwrap_or_default();
            format!("{}({})", c.tool, keys)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::sequence::{CallRecord, SequenceLog};
    use serde_json::{json, Value};

    fn log(pairs: &[(&str, Value)]) -> SequenceLog {
        SequenceLog::from_calls(pairs.iter().map(|(t, a)| CallRecord::new(*t, a.clone())))
    }

    #[test]
    fn analyze_without_baseline_finds_credential_access() {
        let adversarial = log(&[("read_file", json!({"path": "/home/u/.ssh/id_rsa"}))]);
        let findings = analyze(&adversarial, None);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].signal, ChainSignal::CredentialPathAccess);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert_eq!(findings[0].tool, "read_file");
    }

    #[test]
    fn analyze_with_baseline_finds_injected_call() {
        let baseline = log(&[("read_file", json!({"path": "a"}))]);
        let adversarial = log(&[
            ("read_file", json!({"path": "a"})),
            ("send_email", json!({"to": "x@y.com"})),
        ]);
        let findings = analyze(&adversarial, Some(&baseline));
        assert!(findings
            .iter()
            .any(|f| f.signal == ChainSignal::UnexpectedToolSequence && f.tool == "send_email"));
    }

    #[test]
    fn clean_run_yields_no_findings() {
        let adversarial = log(&[("add", json!({"a": 1})), ("ping", json!({}))]);
        assert!(analyze(&adversarial, None).is_empty());
    }

    #[test]
    fn into_finding_maps_signal_and_carries_reproduction() {
        let adversarial = log(&[
            ("list_dir", json!({"path": "."})),
            ("read_file", json!({"path": "/root/.aws/credentials"})),
        ]);
        let f = analyze(&adversarial, None)
            .into_iter()
            .next()
            .expect("a finding");
        let flat = f.into_finding();
        assert_eq!(flat.signal, Signal::RuntimeCredentialAccess);
        assert_eq!(flat.tool_name, "read_file");
        assert!(flat.detail.contains("chain step 2"));
        assert!(flat.detail.contains("list_dir"));
    }

    #[test]
    fn cross_tool_contamination_maps_to_existing_signal() {
        let f = SequenceFinding {
            signal: ChainSignal::CrossToolContamination,
            tool: "read_file".to_string(),
            step: 0,
            severity: Severity::Critical,
            evidence: "x".to_string(),
            reproduction: vec!["read_file()".to_string()],
        };
        assert_eq!(f.into_finding().signal, Signal::CrossToolContamination);
    }

    #[test]
    fn duplicate_step_signal_pairs_are_deduplicated() {
        // Same credential path appears once; must not be reported twice even though
        // scan_log and a baseline diff could both surface the same step.
        let baseline = log(&[("read_file", json!({"path": "notes.txt"}))]);
        let adversarial = log(&[("read_file", json!({"path": "/home/u/.ssh/id_rsa"}))]);
        let findings = analyze(&adversarial, Some(&baseline));
        let cred_at_0 = findings
            .iter()
            .filter(|f| f.signal == ChainSignal::CredentialPathAccess && f.step == 0)
            .count();
        assert_eq!(cred_at_0, 1);
    }
}

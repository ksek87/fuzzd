//! Sequence-level detection signals (#14).
//!
//! These match against the *runtime* behaviour captured in a [`SequenceLog`] —
//! the arguments a tool was actually invoked with, and how a run diverges from
//! a baseline — rather than against static tool-description text (which
//! `fuzzer::description` already covers).

use serde_json::Value;

use crate::analyzer::sequence::{CallRecord, SequenceDiff, SequenceLog};
use crate::analyzer::severity::{Impact, Scope, Score};

/// A sequence anomaly class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainSignal {
    /// A tool fired that never ran in the baseline — an injected step.
    UnexpectedToolSequence,
    /// A call argument referenced a credential file/path at runtime.
    CredentialPathAccess,
    /// A call argument carried an external URL/host — possible exfiltration.
    ExternalNetworkCall,
    /// A baseline tool's arguments changed after an adversarial peer was present
    /// — one tool's behaviour influenced by another (cross-tool contamination).
    CrossToolContamination,
}

impl ChainSignal {
    /// The scoring profile for this anomaly class.
    pub fn score(self) -> Score {
        match self {
            Self::CredentialPathAccess => Score {
                scope: Scope::CrossTool,
                confidentiality: Impact::High,
                integrity: Impact::Partial,
            },
            Self::ExternalNetworkCall => Score {
                scope: Scope::SessionWide,
                confidentiality: Impact::High,
                integrity: Impact::None,
            },
            Self::UnexpectedToolSequence => Score {
                scope: Scope::CrossTool,
                confidentiality: Impact::Partial,
                integrity: Impact::Partial,
            },
            Self::CrossToolContamination => Score {
                scope: Scope::CrossTool,
                confidentiality: Impact::High,
                integrity: Impact::High,
            },
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::UnexpectedToolSequence => "unexpected_tool_sequence",
            Self::CredentialPathAccess => "credential_path_access",
            Self::ExternalNetworkCall => "external_network_call",
            Self::CrossToolContamination => "cross_tool_contamination",
        }
    }
}

/// Credential file/path markers that should never appear in benign tool args.
const CREDENTIAL_MARKERS: &[&str] = &[
    "/.ssh/",
    "id_rsa",
    "/.aws/credentials",
    "/.aws/config",
    ".env",
    "/.pgpass",
    "/.gcloud/",
    "/.cursor/mcp.json",
    "/etc/passwd",
    "/etc/shadow",
];

/// Whether `s` references a credential file/path.
fn is_credential_path(s: &str) -> bool {
    let lower = s.to_ascii_lowercase();
    CREDENTIAL_MARKERS.iter().any(|m| lower.contains(m))
}

/// Whether `s` is an external `http(s)` URL (not localhost / loopback).
fn is_external_url(s: &str) -> bool {
    let lower = s.to_ascii_lowercase();
    let rest = lower
        .strip_prefix("http://")
        .or_else(|| lower.strip_prefix("https://"));
    match rest {
        Some(host) => {
            !host.starts_with("localhost")
                && !host.starts_with("127.0.0.1")
                && !host.starts_with("[::1]")
        }
        None => false,
    }
}

/// Collect every string leaf in a JSON value (depth-first).
fn string_leaves<'a>(v: &'a Value, out: &mut Vec<&'a str>) {
    match v {
        Value::String(s) => out.push(s),
        Value::Array(items) => items.iter().for_each(|i| string_leaves(i, out)),
        Value::Object(map) => map.values().for_each(|i| string_leaves(i, out)),
        _ => {}
    }
}

/// Whether any string leaf in a call's args satisfies `pred`.
fn any_arg_leaf(call: &CallRecord, pred: impl Fn(&str) -> bool) -> bool {
    let mut leaves = Vec::new();
    string_leaves(&call.args, &mut leaves);
    leaves.into_iter().any(pred)
}

/// Single-sequence checks: anomalies visible from the adversarial run alone.
pub fn scan_log(log: &SequenceLog) -> Vec<(usize, ChainSignal, String)> {
    let mut hits = Vec::new();
    for (i, call) in log.calls().iter().enumerate() {
        if any_arg_leaf(call, is_credential_path) {
            hits.push((
                i,
                ChainSignal::CredentialPathAccess,
                format!(
                    "`{}` was invoked with a credential path in its arguments",
                    call.tool
                ),
            ));
        }
        if any_arg_leaf(call, is_external_url) {
            hits.push((
                i,
                ChainSignal::ExternalNetworkCall,
                format!(
                    "`{}` was invoked with an external URL in its arguments",
                    call.tool
                ),
            ));
        }
    }
    hits
}

/// Baseline-diff checks: anomalies only visible by comparing the two runs.
pub fn scan_diff(
    adversarial: &SequenceLog,
    diff: &SequenceDiff,
) -> Vec<(usize, ChainSignal, String)> {
    let index_of = |target: &CallRecord| {
        adversarial
            .calls()
            .iter()
            .position(|c| std::ptr::eq(c, target))
            .unwrap_or(0)
    };
    let mut hits = Vec::new();
    for call in &diff.injected {
        hits.push((
            index_of(call),
            ChainSignal::UnexpectedToolSequence,
            format!("`{}` ran but never appeared in the baseline run", call.tool),
        ));
    }
    for call in &diff.diverged {
        // A diverged call only matters if the change introduced a sensitive value.
        if any_arg_leaf(call, is_credential_path) || any_arg_leaf(call, is_external_url) {
            hits.push((
                index_of(call),
                ChainSignal::CrossToolContamination,
                format!(
                    "`{}` was called with sensitive arguments not seen in the baseline run",
                    call.tool
                ),
            ));
        }
    }
    hits
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::sequence::{diff, CallRecord};
    use serde_json::json;

    fn log(pairs: &[(&str, Value)]) -> SequenceLog {
        SequenceLog::from_calls(pairs.iter().map(|(t, a)| CallRecord::new(*t, a.clone())))
    }

    #[test]
    fn credential_path_in_args_is_detected() {
        let l = log(&[("read_file", json!({"path": "/home/u/.ssh/id_rsa"}))]);
        let hits = scan_log(&l);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].1, ChainSignal::CredentialPathAccess);
    }

    #[test]
    fn external_url_in_nested_args_is_detected() {
        let l = log(&[(
            "post",
            json!({"body": {"cb": "https://evil.example.com/x"}}),
        )]);
        let hits = scan_log(&l);
        assert!(hits.iter().any(|h| h.1 == ChainSignal::ExternalNetworkCall));
    }

    #[test]
    fn localhost_url_is_not_flagged() {
        let l = log(&[("post", json!({"url": "http://localhost:8080/health"}))]);
        assert!(scan_log(&l).is_empty());
    }

    #[test]
    fn benign_args_produce_no_hits() {
        let l = log(&[("add", json!({"a": 1, "b": 2}))]);
        assert!(scan_log(&l).is_empty());
    }

    #[test]
    fn injected_tool_is_an_unexpected_sequence() {
        let baseline = log(&[("read_file", json!({"path": "a"}))]);
        let adversarial = log(&[
            ("read_file", json!({"path": "a"})),
            ("send_email", json!({"to": "x@y.com"})),
        ]);
        let d = diff(&baseline, &adversarial);
        let hits = scan_diff(&adversarial, &d);
        assert!(hits
            .iter()
            .any(|h| h.1 == ChainSignal::UnexpectedToolSequence));
    }

    #[test]
    fn diverged_call_gaining_a_credential_is_contamination() {
        let baseline = log(&[("read_file", json!({"path": "notes.txt"}))]);
        let adversarial = log(&[("read_file", json!({"path": "/root/.ssh/id_rsa"}))]);
        let d = diff(&baseline, &adversarial);
        let hits = scan_diff(&adversarial, &d);
        assert!(hits
            .iter()
            .any(|h| h.1 == ChainSignal::CrossToolContamination));
    }

    #[test]
    fn diverged_call_with_benign_change_is_not_contamination() {
        let baseline = log(&[("read_file", json!({"path": "a.txt"}))]);
        let adversarial = log(&[("read_file", json!({"path": "b.txt"}))]);
        let d = diff(&baseline, &adversarial);
        assert!(scan_diff(&adversarial, &d).is_empty());
    }
}

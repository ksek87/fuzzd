//! Sequence-level detection signals (#14).
//!
//! These match against the *runtime* behaviour captured in a [`SequenceLog`] —
//! the arguments a tool was actually invoked with, and how a run diverges from
//! a baseline — rather than against static tool-description text (which
//! `fuzzer::description` already covers).

use serde_json::Value;

use crate::analyzer::sequence::{SequenceDiff, SequenceLog};
use crate::analyzer::severity::{Impact, Scope, Score};

/// A sequence anomaly class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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
}

/// A detected sequence anomaly, ready for promotion to a [`SequenceFinding`].
pub struct Anomaly {
    pub step: usize,
    pub signal: ChainSignal,
    pub evidence: String,
    pub tool: String,
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

/// Classify a string leaf for both checks in one lowercase pass.
/// Returns `(is_credential_path, is_external_url)`.
fn classify_leaf(s: &str) -> (bool, bool) {
    let lower = s.to_ascii_lowercase();
    let is_cred = CREDENTIAL_MARKERS.iter().any(|m| lower.contains(m));
    let is_url = {
        let rest = lower
            .strip_prefix("http://")
            .or_else(|| lower.strip_prefix("https://"));
        matches!(rest, Some(h)
            if !h.starts_with("localhost")
                && !h.starts_with("127.0.0.1")
                && !h.starts_with("[::1]"))
    };
    (is_cred, is_url)
}

/// Walk a JSON value depth-first, setting `cred`/`url` on first match.
/// Short-circuits once both flags are true.
fn scan_value(val: &Value, cred: &mut bool, url: &mut bool) {
    if *cred && *url {
        return;
    }
    match val {
        Value::String(s) => {
            let (c, u) = classify_leaf(s);
            *cred |= c;
            *url |= u;
        }
        Value::Array(items) => {
            for i in items {
                scan_value(i, cred, url);
                if *cred && *url {
                    return;
                }
            }
        }
        Value::Object(map) => {
            for i in map.values() {
                scan_value(i, cred, url);
                if *cred && *url {
                    return;
                }
            }
        }
        _ => {}
    }
}

/// Scan a call's args for credential paths and external URLs in a single pass.
fn scan_args(val: &Value) -> (bool, bool) {
    let (mut cred, mut url) = (false, false);
    scan_value(val, &mut cred, &mut url);
    (cred, url)
}

/// Single-sequence checks: anomalies visible from the adversarial run alone.
pub fn scan_log(log: &SequenceLog) -> Vec<Anomaly> {
    let mut hits = Vec::new();
    for (i, call) in log.calls().iter().enumerate() {
        let (has_cred, has_url) = scan_args(&call.args);
        if has_cred {
            hits.push(Anomaly {
                step: i,
                signal: ChainSignal::CredentialPathAccess,
                evidence: format!(
                    "`{}` was invoked with a credential path in its arguments",
                    call.tool
                ),
                tool: call.tool.clone(),
            });
        }
        if has_url {
            hits.push(Anomaly {
                step: i,
                signal: ChainSignal::ExternalNetworkCall,
                evidence: format!(
                    "`{}` was invoked with an external URL in its arguments",
                    call.tool
                ),
                tool: call.tool.clone(),
            });
        }
    }
    hits
}

/// Baseline-diff checks: anomalies only visible by comparing the two runs.
pub fn scan_diff(diff: &SequenceDiff) -> Vec<Anomaly> {
    let mut hits = Vec::new();
    for (idx, call) in &diff.injected {
        hits.push(Anomaly {
            step: *idx,
            signal: ChainSignal::UnexpectedToolSequence,
            evidence: format!("`{}` ran but never appeared in the baseline run", call.tool),
            tool: call.tool.clone(),
        });
    }
    for (idx, call) in &diff.diverged {
        let (has_cred, has_url) = scan_args(&call.args);
        if has_cred || has_url {
            hits.push(Anomaly {
                step: *idx,
                signal: ChainSignal::CrossToolContamination,
                evidence: format!(
                    "`{}` was called with sensitive arguments not seen in the baseline run",
                    call.tool
                ),
                tool: call.tool.clone(),
            });
        }
    }
    hits
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::sequence::{diff, CallRecord, SequenceLog};
    use serde_json::json;

    fn log(pairs: &[(&str, Value)]) -> SequenceLog {
        SequenceLog::from_calls(pairs.iter().map(|(t, a)| CallRecord::new(*t, a.clone())))
    }

    #[test]
    fn credential_path_in_args_is_detected() {
        let l = log(&[("read_file", json!({"path": "/home/u/.ssh/id_rsa"}))]);
        let hits = scan_log(&l);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].signal, ChainSignal::CredentialPathAccess);
    }

    #[test]
    fn external_url_in_nested_args_is_detected() {
        let l = log(&[(
            "post",
            json!({"body": {"cb": "https://evil.example.com/x"}}),
        )]);
        let hits = scan_log(&l);
        assert!(hits
            .iter()
            .any(|h| h.signal == ChainSignal::ExternalNetworkCall));
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
        let hits = scan_diff(&d);
        assert!(hits
            .iter()
            .any(|h| h.signal == ChainSignal::UnexpectedToolSequence));
    }

    #[test]
    fn diverged_call_gaining_a_credential_is_contamination() {
        let baseline = log(&[("read_file", json!({"path": "notes.txt"}))]);
        let adversarial = log(&[("read_file", json!({"path": "/root/.ssh/id_rsa"}))]);
        let d = diff(&baseline, &adversarial);
        let hits = scan_diff(&d);
        assert!(hits
            .iter()
            .any(|h| h.signal == ChainSignal::CrossToolContamination));
    }

    #[test]
    fn diverged_call_with_benign_change_is_not_contamination() {
        let baseline = log(&[("read_file", json!({"path": "a.txt"}))]);
        let adversarial = log(&[("read_file", json!({"path": "b.txt"}))]);
        let d = diff(&baseline, &adversarial);
        assert!(scan_diff(&d).is_empty());
    }
}

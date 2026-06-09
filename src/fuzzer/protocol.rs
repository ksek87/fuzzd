//! JSON-RPC 2.0 protocol edge-case fuzzer (#21).
//!
//! Distinct from the argument fuzzer (which fuzzes tool *inputs*): this fuzzes
//! the protocol *envelope* itself. It sends malformed JSON-RPC messages and
//! lifecycle-violating sequences to a live MCP server and classifies how the
//! server responds. Only a well-formed JSON-RPC **error** is acceptable —
//! crashes, hangs, and malformed replies are findings.
//!
//! The send/receive surface is abstracted behind [`RawChannel`] so the driver
//! and classification logic are unit-testable without spawning a child process
//! (per the project's MockTransport convention). [`StdioRawChannel`] is the
//! real implementation; each case runs against a freshly spawned server so
//! lifecycle probes (e.g. `tools/call` before `initialize`) see a clean session.

use std::process::Stdio;
use std::time::Duration;

use anyhow::Result;
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, Lines};
use tokio::process::{Child, ChildStdin, Command};
use tokio::time::timeout;

use crate::corpus::Severity;
use crate::fuzzer::{Finding, Signal};

/// How long to wait for a reply before declaring the server hung.
const REPLY_TIMEOUT: Duration = Duration::from_secs(5);

/// One malformed-message test case.
pub struct ProtocolCase {
    /// Stable identifier, surfaced as the finding's `tool_name`.
    pub label: &'static str,
    /// Well-formed messages to send (and whose replies to drain) before the
    /// probe — used to reach a specific lifecycle state, e.g. a prior
    /// `initialize` so the probe can test a *second* one.
    pub setup: Vec<String>,
    /// The malformed/violating message to send as the probe.
    pub probe: String,
    /// Whether the probe is a request (a reply is expected) or a notification
    /// (silence is the correct behavior, not a hang).
    pub expects_reply: bool,
}

/// The result of reading from the server after a probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplyOutcome {
    /// The server emitted a line.
    Reply(String),
    /// The server's stdout closed. `crashed` is true if it exited non-zero.
    Closed { crashed: bool },
    /// No line arrived within [`REPLY_TIMEOUT`].
    Silent,
}

/// Classification of a server's handling of one malformed message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Classification {
    /// Returned a well-formed JSON-RPC error — the only fully acceptable outcome.
    GracefulError,
    /// Returned a well-formed JSON-RPC *result* to a message it should reject.
    AcceptedInvalid,
    /// Replied with something that is not valid JSON-RPC.
    MalformedResponse,
    /// Closed the connection without replying (tolerable for some inputs).
    ConnectionClosed,
    /// Hung — no reply to a request within the timeout.
    Timeout,
    /// Process exited with a failure status (crash).
    Crash,
}

impl Classification {
    /// Severity of this outcome, or `None` if the server behaved acceptably.
    fn severity(self) -> Option<Severity> {
        match self {
            Self::GracefulError => None,
            Self::ConnectionClosed => Some(Severity::Low),
            Self::AcceptedInvalid | Self::MalformedResponse => Some(Severity::Medium),
            Self::Timeout => Some(Severity::High),
            Self::Crash => Some(Severity::Critical),
        }
    }

    fn explanation(self) -> &'static str {
        match self {
            Self::GracefulError => "returned a well-formed JSON-RPC error",
            Self::AcceptedInvalid => "accepted an invalid message and returned a result",
            Self::MalformedResponse => "replied with a non-JSON-RPC message",
            Self::ConnectionClosed => "closed the connection without a JSON-RPC error",
            Self::Timeout => "hung without replying (possible denial of service)",
            Self::Crash => "exited with a failure status (crash)",
        }
    }
}

/// Classify a server's reply to a probe. Pure — unit-tested directly.
pub fn classify(expects_reply: bool, outcome: &ReplyOutcome) -> Classification {
    match outcome {
        ReplyOutcome::Reply(line) => match serde_json::from_str::<Value>(line) {
            Ok(v) if is_jsonrpc_error(&v) => Classification::GracefulError,
            Ok(v) if is_jsonrpc_result(&v) => Classification::AcceptedInvalid,
            _ => Classification::MalformedResponse,
        },
        ReplyOutcome::Closed { crashed: true } => Classification::Crash,
        ReplyOutcome::Closed { crashed: false } => Classification::ConnectionClosed,
        // Silence is correct for a notification; a hung request is a finding.
        ReplyOutcome::Silent => {
            if expects_reply {
                Classification::Timeout
            } else {
                Classification::GracefulError
            }
        }
    }
}

fn is_jsonrpc_error(v: &Value) -> bool {
    v.get("jsonrpc").is_some() && v.get("error").is_some()
}

fn is_jsonrpc_result(v: &Value) -> bool {
    v.get("jsonrpc").is_some() && v.get("result").is_some()
}

/// Turn a classification into a finding, or `None` if the server was well-behaved.
fn finding_for(case: &ProtocolCase, class: Classification) -> Option<Finding> {
    let severity = class.severity()?;
    Some(Finding {
        tool_name: case.label.to_string(),
        signal: Signal::ProtocolViolation,
        severity,
        matched_text: snippet(&case.probe),
        detail: format!("server {} for `{}`", class.explanation(), case.label),
        corpus_refs: &[],
        suppressed: false,
    })
}

/// First 120 chars of the probe, for the finding's `matched_text`.
fn snippet(probe: &str) -> String {
    const MAX: usize = 120;
    match probe.char_indices().nth(MAX) {
        Some((end, _)) => format!("{}…", &probe[..end]),
        None => probe.to_string(),
    }
}

/// Abstraction over the raw line-level exchange with a server, so the driver is
/// testable without a child process.
#[async_trait::async_trait]
pub trait RawChannel {
    /// Write one line (a newline is appended) to the server.
    async fn send(&mut self, line: &str) -> Result<()>;
    /// Read the next reply, or report closure / silence.
    async fn next_reply(&mut self) -> ReplyOutcome;
}

/// Drive a single case over a channel and classify the result.
///
/// A failed `send` means the server closed its stdin — almost always because it
/// already died — so we read once more to detect the crash rather than aborting
/// the whole run. This keeps one crashing case from discarding every other
/// finding (e.g. a server that dies on the `setup` message of `second_initialize`).
pub async fn run_case(ch: &mut impl RawChannel, case: &ProtocolCase) -> Classification {
    for msg in &case.setup {
        if ch.send(msg).await.is_err() {
            return classify(case.expects_reply, &ch.next_reply().await);
        }
        // Drain the setup reply so it isn't mistaken for the probe's reply.
        let _ = ch.next_reply().await;
    }
    if ch.send(&case.probe).await.is_err() {
        return classify(case.expects_reply, &ch.next_reply().await);
    }
    classify(case.expects_reply, &ch.next_reply().await)
}

/// The catalog of malformed/violating messages. Pure data — unit-tested.
pub fn cases() -> Vec<ProtocolCase> {
    let init = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"fuzzd","version":"0"}}}"#;
    let req = |label, probe: &str| ProtocolCase {
        label,
        setup: Vec::new(),
        probe: probe.to_string(),
        expects_reply: true,
    };
    let notif = |label, probe: &str| ProtocolCase {
        label,
        setup: Vec::new(),
        probe: probe.to_string(),
        expects_reply: false,
    };

    vec![
        // ── Envelope violations ──────────────────────────────────────────────
        req("missing_jsonrpc_field", r#"{"id":1,"method":"tools/list"}"#),
        req(
            "wrong_jsonrpc_version",
            r#"{"jsonrpc":"1.0","id":1,"method":"tools/list"}"#,
        ),
        req(
            "id_as_array",
            r#"{"jsonrpc":"2.0","id":[1,2,3],"method":"tools/list"}"#,
        ),
        req(
            "id_as_object",
            r#"{"jsonrpc":"2.0","id":{"x":1},"method":"tools/list"}"#,
        ),
        req("missing_method", r#"{"jsonrpc":"2.0","id":1,"params":{}}"#),
        req(
            "unknown_method",
            r#"{"jsonrpc":"2.0","id":1,"method":"this/does/not/exist"}"#,
        ),
        req("not_json", "this is not json at all"),
        req("empty_object", "{}"),
        // ── Lifecycle ordering violations ────────────────────────────────────
        req(
            "tools_call_before_initialize",
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x","arguments":{}}}"#,
        ),
        req(
            "tools_list_before_initialize",
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#,
        ),
        ProtocolCase {
            label: "second_initialize",
            setup: vec![init.to_string()],
            probe: init.to_string(),
            expects_reply: true,
        },
        // ── Payload-size violations ──────────────────────────────────────────
        req(
            "oversized_method_name",
            &format!(
                r#"{{"jsonrpc":"2.0","id":1,"method":"{}"}}"#,
                "a".repeat(100_000)
            ),
        ),
        // A notification (no id) — the server must simply not reply, not hang.
        notif(
            "unknown_notification",
            r#"{"jsonrpc":"2.0","method":"notifications/unknown"}"#,
        ),
    ]
}

/// Real channel: a freshly spawned server process speaking line-delimited JSON
/// over stdio. One per case so lifecycle probes start from a clean session.
struct StdioRawChannel {
    child: Child,
    stdin: ChildStdin,
    lines: Lines<BufReader<tokio::process::ChildStdout>>,
}

impl StdioRawChannel {
    fn spawn(cmd: &str) -> Result<Self> {
        let mut parts = cmd.split_whitespace();
        let program = parts
            .next()
            .ok_or_else(|| anyhow::anyhow!("empty command"))?;
        let mut child = Command::new(program)
            .args(parts)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()?;
        let stdin = child.stdin.take().expect("stdin piped");
        let stdout = child.stdout.take().expect("stdout piped");
        Ok(Self {
            child,
            stdin,
            lines: BufReader::new(stdout).lines(),
        })
    }
}

#[async_trait::async_trait]
impl RawChannel for StdioRawChannel {
    async fn send(&mut self, line: &str) -> Result<()> {
        self.stdin.write_all(line.as_bytes()).await?;
        self.stdin.write_all(b"\n").await?;
        self.stdin.flush().await?;
        Ok(())
    }

    async fn next_reply(&mut self) -> ReplyOutcome {
        match timeout(REPLY_TIMEOUT, self.lines.next_line()).await {
            Ok(Ok(Some(line))) => ReplyOutcome::Reply(line),
            // Clean EOF or a read error: inspect the exit status to tell a crash
            // from an orderly close.
            Ok(_) => ReplyOutcome::Closed {
                crashed: self.exited_with_failure().await,
            },
            Err(_) => ReplyOutcome::Silent,
        }
    }
}

impl StdioRawChannel {
    /// Whether the process has exited with a non-zero (or signal) status.
    async fn exited_with_failure(&mut self) -> bool {
        match self.child.wait().await {
            Ok(status) => !status.success(),
            Err(_) => true,
        }
    }
}

/// Run every protocol case against a freshly spawned stdio server and collect findings.
pub async fn fuzz_stdio(cmd: &str) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();
    for case in cases() {
        let mut ch = StdioRawChannel::spawn(cmd)?;
        let class = run_case(&mut ch, &case).await;
        if let Some(f) = finding_for(&case, class) {
            findings.push(f);
        }
    }
    Ok(findings)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── classify: pure decision logic ───────────────────────────────────────

    #[test]
    fn jsonrpc_error_reply_is_graceful() {
        let outcome = ReplyOutcome::Reply(
            r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32600,"message":"Invalid Request"}}"#
                .to_string(),
        );
        assert_eq!(classify(true, &outcome), Classification::GracefulError);
    }

    #[test]
    fn jsonrpc_result_to_invalid_message_is_accepted_invalid() {
        let outcome =
            ReplyOutcome::Reply(r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}"#.to_string());
        assert_eq!(classify(true, &outcome), Classification::AcceptedInvalid);
    }

    #[test]
    fn non_jsonrpc_reply_is_malformed() {
        let outcome = ReplyOutcome::Reply("OK, done!".to_string());
        assert_eq!(classify(true, &outcome), Classification::MalformedResponse);
    }

    #[test]
    fn plain_json_without_jsonrpc_field_is_malformed() {
        let outcome = ReplyOutcome::Reply(r#"{"result":{"tools":[]}}"#.to_string());
        assert_eq!(classify(true, &outcome), Classification::MalformedResponse);
    }

    #[test]
    fn crash_close_is_crash() {
        let outcome = ReplyOutcome::Closed { crashed: true };
        assert_eq!(classify(true, &outcome), Classification::Crash);
    }

    #[test]
    fn clean_close_is_connection_closed() {
        let outcome = ReplyOutcome::Closed { crashed: false };
        assert_eq!(classify(true, &outcome), Classification::ConnectionClosed);
    }

    #[test]
    fn silence_to_a_request_is_timeout() {
        assert_eq!(
            classify(true, &ReplyOutcome::Silent),
            Classification::Timeout
        );
    }

    #[test]
    fn silence_to_a_notification_is_acceptable() {
        assert_eq!(
            classify(false, &ReplyOutcome::Silent),
            Classification::GracefulError
        );
    }

    // ── severity / finding mapping ───────────────────────────────────────────

    #[test]
    fn graceful_outcomes_produce_no_finding() {
        let case = &cases()[0];
        assert!(finding_for(case, Classification::GracefulError).is_none());
    }

    #[test]
    fn crash_is_a_critical_finding() {
        let case = &cases()[0];
        let f = finding_for(case, Classification::Crash).expect("crash is a finding");
        assert_eq!(f.severity, Severity::Critical);
        assert_eq!(f.signal, Signal::ProtocolViolation);
        assert_eq!(f.tool_name, case.label);
    }

    #[test]
    fn timeout_is_a_high_finding() {
        let f = finding_for(&cases()[0], Classification::Timeout).expect("timeout is a finding");
        assert_eq!(f.severity, Severity::High);
    }

    #[test]
    fn connection_closed_is_low_and_non_blocking() {
        let f = finding_for(&cases()[0], Classification::ConnectionClosed).expect("a finding");
        assert_eq!(f.severity, Severity::Low);
        assert!(f.severity < Severity::High, "closure must not gate CI");
    }

    // ── catalog ──────────────────────────────────────────────────────────────

    #[test]
    fn catalog_covers_envelope_and_lifecycle() {
        let labels: Vec<_> = cases().iter().map(|c| c.label).collect();
        assert!(labels.contains(&"missing_jsonrpc_field"));
        assert!(labels.contains(&"tools_call_before_initialize"));
        assert!(labels.contains(&"second_initialize"));
        assert!(labels.contains(&"unknown_notification"));
    }

    #[test]
    fn second_initialize_has_setup() {
        let case = cases()
            .into_iter()
            .find(|c| c.label == "second_initialize")
            .expect("present");
        assert_eq!(
            case.setup.len(),
            1,
            "must initialize once before re-probing"
        );
    }

    #[test]
    fn snippet_truncates_oversized_probes() {
        let case = cases()
            .into_iter()
            .find(|c| c.label == "oversized_method_name")
            .expect("present");
        let f = finding_for(&case, Classification::Crash).expect("a finding");
        assert!(f.matched_text.chars().count() <= 121, "snippet is bounded");
    }

    // ── driver, against a mock channel (no child process) ────────────────────

    struct MockChannel {
        replies: Vec<ReplyOutcome>,
        sent: Vec<String>,
    }

    #[async_trait::async_trait]
    impl RawChannel for MockChannel {
        async fn send(&mut self, line: &str) -> Result<()> {
            self.sent.push(line.to_string());
            Ok(())
        }
        async fn next_reply(&mut self) -> ReplyOutcome {
            if self.replies.is_empty() {
                ReplyOutcome::Silent
            } else {
                self.replies.remove(0)
            }
        }
    }

    #[tokio::test]
    async fn run_case_drains_setup_before_probe() {
        let case = ProtocolCase {
            label: "second_initialize",
            setup: vec!["setup-msg".to_string()],
            probe: "probe-msg".to_string(),
            expects_reply: true,
        };
        let mut ch = MockChannel {
            // First reply consumed by setup, second is the probe's.
            replies: vec![
                ReplyOutcome::Reply(r#"{"jsonrpc":"2.0","id":1,"result":{}}"#.to_string()),
                ReplyOutcome::Reply(
                    r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32600,"message":"already initialized"}}"#
                        .to_string(),
                ),
            ],
            sent: Vec::new(),
        };
        let class = run_case(&mut ch, &case).await;
        assert_eq!(class, Classification::GracefulError);
        assert_eq!(ch.sent, vec!["setup-msg", "probe-msg"]);
    }

    #[tokio::test]
    async fn run_case_flags_a_hung_server() {
        let case = ProtocolCase {
            label: "tools_call_before_initialize",
            setup: Vec::new(),
            probe: "probe".to_string(),
            expects_reply: true,
        };
        let mut ch = MockChannel {
            replies: vec![ReplyOutcome::Silent],
            sent: Vec::new(),
        };
        assert_eq!(run_case(&mut ch, &case).await, Classification::Timeout);
    }

    /// A channel whose `send` always fails (server closed stdin) and whose reads
    /// report a crashed close — models a server that died mid-exchange.
    struct DeadChannel;

    #[async_trait::async_trait]
    impl RawChannel for DeadChannel {
        async fn send(&mut self, _line: &str) -> Result<()> {
            Err(anyhow::anyhow!("broken pipe"))
        }
        async fn next_reply(&mut self) -> ReplyOutcome {
            ReplyOutcome::Closed { crashed: true }
        }
    }

    #[tokio::test]
    async fn send_failure_on_probe_is_classified_not_propagated() {
        let case = ProtocolCase {
            label: "x",
            setup: Vec::new(),
            probe: "p".to_string(),
            expects_reply: true,
        };
        // No panic, no Err — a dead server becomes a Crash finding.
        assert_eq!(
            run_case(&mut DeadChannel, &case).await,
            Classification::Crash
        );
    }

    #[tokio::test]
    async fn crash_during_setup_does_not_abort_the_case() {
        // Regression: a server that dies on the `setup` message of a multi-step
        // case must still be reported as a crash, not abort the whole run.
        let case = ProtocolCase {
            label: "second_initialize",
            setup: vec!["init".to_string()],
            probe: "init".to_string(),
            expects_reply: true,
        };
        assert_eq!(
            run_case(&mut DeadChannel, &case).await,
            Classification::Crash
        );
    }
}

//! Stateful multi-step attack chain executor (#15).
//!
//! Drives a scripted sequence of tool calls (an [`AttackChain`]) against a live
//! server, recording the ordered call log via [`SequenceObserver`], then runs
//! the sequence analyzer (#14) over the result. This surfaces the runtime
//! anomalies a static scan cannot see: credential paths or external URLs that
//! appear in a call's *arguments*, injected calls, and cross-tool contamination
//! relative to an optional benign baseline run.
//!
//! The driver core ([`execute`]) is generic over [`Transport`] and unit-tested
//! with `MockTransport`. [`fuzz_stdio`] is the live entry point: baseline and
//! adversarial steps each run in their own freshly spawned stdio session, so one
//! run never pollutes the other — the same clean-session model the poisoned-peer
//! injection of #16 will build on.

use std::collections::HashSet;
use std::path::Path;

use anyhow::{Context, Result};
use serde::Deserialize;
use serde_json::Value;

use crate::analyzer::analyze;
use crate::analyzer::sequence::{SequenceLog, SequenceObserver};
use crate::fuzzer::Finding;
use crate::protocol::transport::Transport;
use crate::runner::harness::Harness;

/// One step in a chain: invoke `tool` with `args`.
#[derive(Debug, Clone, Deserialize)]
pub struct ChainStep {
    pub tool: String,
    /// Arguments passed to the tool. A `null` (or absent) value sends none.
    #[serde(default)]
    pub args: Value,
}

/// A scripted multi-step attack chain, loadable from JSON.
#[derive(Debug, Clone, Deserialize)]
pub struct AttackChain {
    pub id: String,
    #[serde(default)]
    pub description: String,
    /// The corpus `AttackRecord` this chain exercises, if any (provenance only).
    #[serde(default)]
    pub corpus_record_id: Option<String>,
    /// An optional benign baseline run. When present, the analyzer diffs the
    /// adversarial steps against it to surface injected and diverged calls.
    #[serde(default)]
    pub baseline: Vec<ChainStep>,
    /// The adversarial sequence to execute and analyze.
    pub steps: Vec<ChainStep>,
}

impl AttackChain {
    /// A short provenance prefix for findings: the chain id and, when set, the
    /// corpus `AttackRecord` it exercises.
    fn provenance(&self) -> String {
        match &self.corpus_record_id {
            Some(record) => format!("[chain {} · {}] ", self.id, record),
            None => format!("[chain {}] ", self.id),
        }
    }
}

/// Drive `steps` through a recording observer, skipping any step whose tool is
/// absent from `available` (recorded as a note, never a hard error). Returns the
/// recorded call log and the names of the skipped tools.
pub async fn execute<T: Transport>(
    harness: Harness<T>,
    steps: &[ChainStep],
    available: &HashSet<String>,
) -> Result<(SequenceLog, Vec<String>)> {
    let mut observer = SequenceObserver::new(harness);
    let mut skipped = Vec::new();
    for step in steps {
        if !available.contains(&step.tool) {
            skipped.push(step.tool.clone());
            continue;
        }
        let args = if step.args.is_null() {
            None
        } else {
            Some(step.args.clone())
        };
        // The observer logs the attempt before the call, so a server-side
        // rejection still feeds detection; a failed call must not abort the chain.
        if let Err(e) = observer.call_tool(&step.tool, args).await {
            tracing::debug!(tool = %step.tool, error = %e, "chain step call failed");
        }
    }
    observer.close().await?;
    Ok((observer.into_log(), skipped))
}

/// Run every chain against freshly spawned stdio sessions and collect findings.
/// Baseline and adversarial steps each run in their own clean session.
pub async fn fuzz_stdio(cmd: &str, chains: &[AttackChain]) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();
    for chain in chains {
        if !chain.description.is_empty() {
            tracing::info!(chain = %chain.id, "{}", chain.description);
        }
        let adversarial = run_session(cmd, &chain.steps).await?;
        let baseline = if chain.baseline.is_empty() {
            None
        } else {
            Some(run_session(cmd, &chain.baseline).await?)
        };
        for sf in analyze(&adversarial, baseline.as_ref()) {
            let mut finding = sf.into_finding();
            finding.detail = format!("{}{}", chain.provenance(), finding.detail);
            findings.push(finding);
        }
    }
    Ok(findings)
}

/// Spawn a fresh stdio session, handshake, enumerate tools, and run `steps`.
async fn run_session(cmd: &str, steps: &[ChainStep]) -> Result<SequenceLog> {
    let transport = crate::protocol::transport::stdio::StdioTransport::spawn(cmd).await?;
    let mut harness = Harness::new(transport);
    harness.initialize().await?;
    let available: HashSet<String> = harness
        .enumerate_tools()
        .await?
        .into_iter()
        .map(|t| t.name)
        .collect();
    let (log, skipped) = execute(harness, steps, &available).await?;
    for tool in &skipped {
        eprintln!("warn: chain step skipped — server does not expose tool `{tool}`");
    }
    Ok(log)
}

/// Load chains from a JSON file (a single chain object or an array of chains) or
/// a directory of `*.json` files (one chain each, loaded in sorted name order).
pub fn load_chains(path: &Path) -> Result<Vec<AttackChain>> {
    if path.is_dir() {
        let mut paths: Vec<_> = std::fs::read_dir(path)
            .with_context(|| format!("reading chain dir {}", path.display()))?
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.extension().is_some_and(|x| x == "json"))
            .collect();
        paths.sort();
        let mut chains = Vec::with_capacity(paths.len());
        for p in paths {
            let src =
                std::fs::read_to_string(&p).with_context(|| format!("reading {}", p.display()))?;
            chains.push(
                serde_json::from_str(&src)
                    .with_context(|| format!("parsing chain {}", p.display()))?,
            );
        }
        Ok(chains)
    } else {
        let src =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        serde_json::from_str::<Vec<AttackChain>>(&src)
            .or_else(|_| serde_json::from_str::<AttackChain>(&src).map(|c| vec![c]))
            .with_context(|| format!("parsing chains from {}", path.display()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::signals::ChainSignal;
    use crate::protocol::mcp::JsonRpcResponse;
    use crate::protocol::session::SessionState;
    use crate::testutil::{ok_response, MockTransport};
    use serde_json::json;

    fn available(names: &[&str]) -> HashSet<String> {
        names.iter().map(|s| s.to_string()).collect()
    }

    fn ready(responses: Vec<JsonRpcResponse>) -> Harness<MockTransport> {
        let mut h = Harness::new(MockTransport::new(responses));
        h.session.state = SessionState::Ready;
        h
    }

    fn ok_call() -> JsonRpcResponse {
        ok_response(1, json!({"content": [{"type": "text", "text": "ok"}]}))
    }

    #[tokio::test]
    async fn execute_records_available_calls_and_skips_the_rest() {
        let h = ready(vec![ok_call()]);
        let steps = vec![
            ChainStep {
                tool: "read_file".into(),
                args: json!({"path": "/home/u/.ssh/id_rsa"}),
            },
            ChainStep {
                tool: "ghost".into(),
                args: Value::Null,
            },
        ];
        let (log, skipped) = execute(h, &steps, &available(&["read_file"]))
            .await
            .unwrap();
        assert_eq!(log.calls().len(), 1, "the unavailable tool is not called");
        assert_eq!(log.calls()[0].tool, "read_file");
        assert_eq!(skipped, vec!["ghost".to_string()]);
    }

    #[tokio::test]
    async fn execute_output_feeds_credential_detection() {
        let h = ready(vec![ok_call()]);
        let steps = vec![ChainStep {
            tool: "read_file".into(),
            args: json!({"path": "/root/.aws/credentials"}),
        }];
        let (log, _) = execute(h, &steps, &available(&["read_file"]))
            .await
            .unwrap();
        let findings = analyze(&log, None);
        assert!(findings
            .iter()
            .any(|f| f.tool == "read_file" && f.signal == ChainSignal::CredentialPathAccess));
    }

    #[test]
    fn load_chains_parses_a_single_object_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("c.json");
        std::fs::write(
            &path,
            r#"{"id":"C1","steps":[{"tool":"read_file","args":{"path":"x"}}]}"#,
        )
        .unwrap();
        let chains = load_chains(&path).unwrap();
        assert_eq!(chains.len(), 1);
        assert_eq!(chains[0].id, "C1");
        assert_eq!(chains[0].steps.len(), 1);
    }

    #[test]
    fn load_chains_parses_an_array_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("arr.json");
        std::fs::write(&path, r#"[{"id":"A","steps":[]},{"id":"B","steps":[]}]"#).unwrap();
        assert_eq!(load_chains(&path).unwrap().len(), 2);
    }

    #[test]
    fn load_chains_reads_json_files_in_a_directory() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("one.json"), r#"{"id":"one","steps":[]}"#).unwrap();
        std::fs::write(dir.path().join("two.json"), r#"{"id":"two","steps":[]}"#).unwrap();
        std::fs::write(dir.path().join("ignore.txt"), "not a chain").unwrap();
        let chains = load_chains(dir.path()).unwrap();
        assert_eq!(chains.len(), 2, "only *.json files are loaded");
    }
}

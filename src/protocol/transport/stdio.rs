#![allow(dead_code)]

use std::collections::HashMap;
use std::process::Stdio;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, Command};
use tokio::sync::{oneshot, Mutex};

use crate::protocol::mcp::{JsonRpcRequest, JsonRpcResponse, RequestId};

use super::Transport;

type PendingMap = Arc<Mutex<HashMap<String, oneshot::Sender<JsonRpcResponse>>>>;

pub struct StdioTransport {
    stdin: ChildStdin,
    pending: PendingMap,
    child: Child,
}

impl StdioTransport {
    /// Spawn `cmd` as a child process and communicate over its stdin/stdout.
    pub async fn spawn(cmd: &str) -> Result<Self> {
        let mut args = cmd.split_whitespace();
        let program = args.next().ok_or_else(|| anyhow!("empty command"))?;

        let mut child = Command::new(program)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .with_context(|| format!("failed to spawn '{cmd}'"))?;

        let stdin = child.stdin.take().expect("stdin piped");
        let stdout = child.stdout.take().expect("stdout piped");

        let pending: PendingMap = Arc::new(Mutex::new(HashMap::new()));
        let pending_reader = Arc::clone(&pending);

        tokio::spawn(async move {
            let reader = BufReader::new(stdout);
            let mut lines = reader.lines();
            while let Ok(Some(line)) = lines.next_line().await {
                let line = line.trim().to_string();
                if line.is_empty() {
                    continue;
                }
                if let Ok(resp) = serde_json::from_str::<JsonRpcResponse>(&line) {
                    let key = id_key(resp.id.as_ref());
                    let mut map = pending_reader.lock().await;
                    if let Some(tx) = map.remove(&key) {
                        let _ = tx.send(resp);
                    }
                }
            }
        });

        Ok(Self {
            stdin,
            pending,
            child,
        })
    }

    async fn write_line(&mut self, msg: &JsonRpcRequest) -> Result<()> {
        let mut line = serde_json::to_string(msg)?;
        line.push('\n');
        self.stdin
            .write_all(line.as_bytes())
            .await
            .context("write to child stdin")
    }
}

impl Drop for StdioTransport {
    fn drop(&mut self) {
        let _ = self.child.start_kill();
    }
}

#[async_trait::async_trait]
impl Transport for StdioTransport {
    async fn send(&mut self, request: JsonRpcRequest) -> Result<JsonRpcResponse> {
        let key = id_key(Some(&request.id));
        let (tx, rx) = oneshot::channel();
        self.pending.lock().await.insert(key, tx);
        self.write_line(&request).await?;
        rx.await
            .map_err(|_| anyhow!("child process closed before responding"))
    }

    async fn notify(&mut self, notification: JsonRpcRequest) -> Result<()> {
        self.write_line(&notification).await
    }

    async fn close(&mut self) -> Result<()> {
        self.stdin.shutdown().await.ok();
        Ok(())
    }
}

fn id_key(id: Option<&RequestId>) -> String {
    match id {
        Some(RequestId::Number(n)) => n.to_string(),
        Some(RequestId::String(s)) => s.clone(),
        None => "__notification__".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    #[test]
    fn id_key_number() {
        assert_eq!(id_key(Some(&RequestId::Number(42))), "42");
    }

    #[test]
    fn id_key_string() {
        assert_eq!(id_key(Some(&RequestId::String("abc".into()))), "abc");
    }

    #[test]
    fn id_key_none() {
        assert_eq!(id_key(None), "__notification__");
    }

    #[test]
    fn write_serializes_valid_json() {
        let req = JsonRpcRequest::new(1i64, "ping", None);
        let serialized = serde_json::to_string(&req).unwrap();
        let parsed: Value = serde_json::from_str(&serialized).unwrap();
        assert_eq!(parsed["method"], "ping");
        assert_eq!(parsed["jsonrpc"], "2.0");
    }
}

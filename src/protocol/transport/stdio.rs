use std::process::Stdio;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, Command};
use tokio::sync::Mutex;

use crate::protocol::mcp::{JsonRpcRequest, JsonRpcResponse};
use crate::protocol::transport::{id_key, PendingMap, Transport};

pub struct StdioTransport {
    stdin: ChildStdin,
    pending: PendingMap,
    child: Child,
    reader_task: tokio::task::JoinHandle<()>,
}

impl StdioTransport {
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

        let pending: PendingMap = Arc::new(Mutex::new(Default::default()));
        let pending_reader = Arc::clone(&pending);

        let reader_task = tokio::spawn(async move {
            let mut lines = BufReader::new(stdout).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                let line = line.trim().to_string();
                if line.is_empty() {
                    continue;
                }
                if let Ok(resp) = serde_json::from_str::<JsonRpcResponse>(&line) {
                    let key = id_key(resp.id.as_ref());
                    if let Some(tx) = pending_reader.lock().await.remove(&key) {
                        let _ = tx.send(resp);
                    }
                }
            }
        });

        Ok(Self {
            stdin,
            pending,
            child,
            reader_task,
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
        self.reader_task.abort();
        let _ = self.child.start_kill();
    }
}

#[async_trait::async_trait]
impl Transport for StdioTransport {
    async fn send(&mut self, request: JsonRpcRequest) -> Result<JsonRpcResponse> {
        let key = id_key(Some(&request.id));
        let (tx, rx) = tokio::sync::oneshot::channel();
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
        self.pending.lock().await.clear();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    #[test]
    fn write_serializes_valid_json() {
        let req = JsonRpcRequest::new(1i64, "ping", None);
        let serialized = serde_json::to_string(&req).unwrap();
        let parsed: Value = serde_json::from_str(&serialized).unwrap();
        assert_eq!(parsed["method"], "ping");
        assert_eq!(parsed["jsonrpc"], "2.0");
    }
}

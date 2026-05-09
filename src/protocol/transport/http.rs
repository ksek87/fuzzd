#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use futures_util::StreamExt;
use reqwest::Client;
use tokio::sync::{oneshot, Mutex};

use crate::protocol::mcp::{JsonRpcRequest, JsonRpcResponse, RequestId};

use super::Transport;

type PendingMap = Arc<Mutex<HashMap<String, oneshot::Sender<JsonRpcResponse>>>>;

pub struct HttpTransport {
    client: Arc<Client>,
    mcp_url: String,
    pending: PendingMap,
}

impl HttpTransport {
    /// Connect to a remote MCP server at `base_url`.
    /// Pre-computes endpoint URLs and spawns a background SSE listener.
    pub async fn connect(base_url: impl Into<String>) -> Result<Self> {
        let base_url = base_url.into();
        let mcp_url = format!("{base_url}/mcp");
        let sse_url = format!("{base_url}/sse");

        let client = Arc::new(Client::builder().build().context("build HTTP client")?);
        let pending: PendingMap = Arc::new(Mutex::new(HashMap::new()));

        let sse_client = Arc::clone(&client);
        let sse_pending = Arc::clone(&pending);

        tokio::spawn(async move {
            if let Ok(resp) = sse_client.get(&sse_url).send().await {
                let mut stream = resp.bytes_stream();
                let mut buf = String::new();
                while let Some(Ok(chunk)) = stream.next().await {
                    buf.push_str(&String::from_utf8_lossy(&chunk));
                    while let Some(pos) = buf.find("\n\n") {
                        let event = buf[..pos].to_string();
                        buf = buf[pos + 2..].to_string();
                        for line in event.lines() {
                            if let Some(data) = line.strip_prefix("data:") {
                                if let Ok(resp) =
                                    serde_json::from_str::<JsonRpcResponse>(data.trim())
                                {
                                    let key = id_key(resp.id.as_ref());
                                    let mut map = sse_pending.lock().await;
                                    if let Some(tx) = map.remove(&key) {
                                        let _ = tx.send(resp);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        });

        Ok(Self {
            client,
            mcp_url,
            pending,
        })
    }
}

#[async_trait::async_trait]
impl Transport for HttpTransport {
    async fn send(&mut self, request: JsonRpcRequest) -> Result<JsonRpcResponse> {
        let key = id_key(Some(&request.id));
        let (tx, rx) = oneshot::channel();
        self.pending.lock().await.insert(key, tx);

        self.client
            .post(&self.mcp_url)
            .json(&request)
            .send()
            .await
            .context("HTTP POST to MCP endpoint")?;

        rx.await
            .map_err(|_| anyhow!("SSE stream closed before response arrived"))
    }

    async fn notify(&mut self, notification: JsonRpcRequest) -> Result<()> {
        self.client
            .post(&self.mcp_url)
            .json(&notification)
            .send()
            .await
            .context("HTTP POST notification")?;
        Ok(())
    }

    async fn close(&mut self) -> Result<()> {
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

    #[test]
    fn id_key_variants() {
        assert_eq!(id_key(Some(&RequestId::Number(1))), "1");
        assert_eq!(id_key(Some(&RequestId::String("x".into()))), "x");
        assert_eq!(id_key(None), "__notification__");
    }

    #[test]
    fn endpoints_derived_from_base_url() {
        let base = "http://localhost:8000";
        assert_eq!(format!("{base}/mcp"), "http://localhost:8000/mcp");
        assert_eq!(format!("{base}/sse"), "http://localhost:8000/sse");
    }
}

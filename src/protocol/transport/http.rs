#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use reqwest::Client;
use tokio::sync::{oneshot, Mutex};

use crate::protocol::mcp::{JsonRpcRequest, JsonRpcResponse, RequestId};

use super::Transport;

type PendingMap = Arc<Mutex<HashMap<String, oneshot::Sender<JsonRpcResponse>>>>;

pub struct HttpTransport {
    client: Client,
    base_url: String,
    pending: PendingMap,
}

impl HttpTransport {
    /// Connect to a remote MCP server at `base_url`.
    /// Spawns a background SSE listener that routes responses to pending callers.
    pub async fn connect(base_url: impl Into<String>) -> Result<Self> {
        let base_url = base_url.into();
        let client = Client::builder()
            .build()
            .context("failed to build HTTP client")?;

        let pending: PendingMap = Arc::new(Mutex::new(HashMap::new()));
        let pending_sse = Arc::clone(&pending);
        let sse_client = client.clone();
        let sse_url = format!("{base_url}/sse");

        tokio::spawn(async move {
            if let Ok(resp) = sse_client.get(&sse_url).send().await {
                let mut stream = resp.bytes_stream();
                use futures_util::StreamExt;
                let mut buf = String::new();
                while let Some(Ok(chunk)) = stream.next().await {
                    buf.push_str(&String::from_utf8_lossy(&chunk));
                    // SSE events are separated by \n\n
                    while let Some(pos) = buf.find("\n\n") {
                        let event = buf[..pos].to_string();
                        buf = buf[pos + 2..].to_string();
                        // Extract `data:` lines
                        for line in event.lines() {
                            if let Some(data) = line.strip_prefix("data:") {
                                let data = data.trim();
                                if let Ok(resp) = serde_json::from_str::<JsonRpcResponse>(data) {
                                    let key = request_id_key(resp.id.as_ref());
                                    let mut map = pending_sse.lock().await;
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
            base_url,
            pending,
        })
    }
}

#[async_trait::async_trait]
impl Transport for HttpTransport {
    async fn send(&mut self, request: JsonRpcRequest) -> Result<JsonRpcResponse> {
        let key = request_id_key(Some(&request.id));
        let (tx, rx) = oneshot::channel();
        self.pending.lock().await.insert(key, tx);

        let url = format!("{}/mcp", self.base_url);
        self.client
            .post(&url)
            .json(&request)
            .send()
            .await
            .context("HTTP POST to MCP endpoint")?;

        rx.await
            .map_err(|_| anyhow!("SSE stream closed before response arrived"))
    }

    async fn close(&mut self) -> Result<()> {
        Ok(())
    }
}

fn request_id_key(id: Option<&RequestId>) -> String {
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
    fn request_id_key_variants() {
        assert_eq!(request_id_key(Some(&RequestId::Number(1))), "1");
        assert_eq!(request_id_key(Some(&RequestId::String("x".into()))), "x");
        assert_eq!(request_id_key(None), "__notification__");
    }

    #[test]
    fn base_url_forms_mcp_endpoint() {
        let base = "http://localhost:8000";
        assert_eq!(format!("{base}/mcp"), "http://localhost:8000/mcp");
        assert_eq!(format!("{base}/sse"), "http://localhost:8000/sse");
    }
}

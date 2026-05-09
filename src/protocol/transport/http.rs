#![allow(dead_code)]

use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use futures_util::StreamExt;
use reqwest::Client;

use crate::protocol::mcp::{JsonRpcRequest, JsonRpcResponse};
use crate::protocol::transport::{id_key, PendingMap, Transport};
use crate::utils::{drain_sse_events, sse_data};

pub struct HttpTransport {
    client: Arc<Client>,
    mcp_url: String,
    pending: PendingMap,
}

impl HttpTransport {
    pub async fn connect(base_url: impl Into<String>) -> Result<Self> {
        let base_url = base_url.into();
        let mcp_url = format!("{base_url}/mcp");
        let sse_url = format!("{base_url}/sse");

        let client = Arc::new(Client::builder().build().context("build HTTP client")?);
        let pending: PendingMap = Arc::new(tokio::sync::Mutex::new(Default::default()));

        let sse_client = Arc::clone(&client);
        let sse_pending = Arc::clone(&pending);

        tokio::spawn(async move {
            if let Ok(resp) = sse_client.get(&sse_url).send().await {
                let mut stream = resp.bytes_stream();
                let mut buf = String::new();
                while let Some(Ok(chunk)) = stream.next().await {
                    buf.push_str(&String::from_utf8_lossy(&chunk));
                    // Collect all parsed responses synchronously, then acquire the
                    // lock once per chunk rather than once per response.
                    let mut ready: Vec<(String, JsonRpcResponse)> = Vec::new();
                    drain_sse_events(&mut buf, |event| {
                        for line in event.lines() {
                            if let Some(data) = sse_data(line) {
                                if let Ok(resp) = serde_json::from_str::<JsonRpcResponse>(data) {
                                    ready.push((id_key(resp.id.as_ref()), resp));
                                }
                            }
                        }
                    });
                    if !ready.is_empty() {
                        let mut map = sse_pending.lock().await;
                        for (key, resp) in ready {
                            if let Some(tx) = map.remove(&key) {
                                let _ = tx.send(resp);
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
        let (tx, rx) = tokio::sync::oneshot::channel();
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

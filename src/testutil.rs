//! Shared test utilities. Only compiled in `#[cfg(test)]`.

use std::collections::VecDeque;

use anyhow::{anyhow, Result};
use async_trait::async_trait;

use crate::protocol::mcp::{JsonRpcRequest, JsonRpcResponse};
use crate::protocol::transport::Transport;

/// A deterministic transport that returns pre-programmed responses in order.
/// Notifications are accepted and discarded.
pub struct MockTransport {
    responses: VecDeque<JsonRpcResponse>,
    pub notifications_sent: usize,
}

impl MockTransport {
    pub fn new(responses: Vec<JsonRpcResponse>) -> Self {
        Self {
            responses: responses.into(),
            notifications_sent: 0,
        }
    }
}

#[async_trait]
impl Transport for MockTransport {
    async fn send(&mut self, _req: JsonRpcRequest) -> Result<JsonRpcResponse> {
        self.responses
            .pop_front()
            .ok_or_else(|| anyhow!("MockTransport: no more responses queued"))
    }

    async fn notify(&mut self, _notification: JsonRpcRequest) -> Result<()> {
        self.notifications_sent += 1;
        Ok(())
    }

    async fn close(&mut self) -> Result<()> {
        Ok(())
    }
}

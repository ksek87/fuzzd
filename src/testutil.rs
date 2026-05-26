use std::collections::VecDeque;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use serde_json::{json, Value};

use crate::protocol::mcp::{JsonRpcRequest, JsonRpcResponse, RequestId, ResponseOutcome, ToolDefinition};
use crate::protocol::transport::Transport;

/// Deterministic transport that returns pre-programmed responses in order.
/// Notifications are accepted and counted.
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

/// Build a successful JSON-RPC response wrapping `result`.
pub fn ok_response(id: i64, result: Value) -> JsonRpcResponse {
    JsonRpcResponse {
        jsonrpc: "2.0".into(),
        id: Some(RequestId::Number(id)),
        outcome: ResponseOutcome::Result(result),
    }
}

pub fn init_response() -> JsonRpcResponse {
    ok_response(
        1,
        json!({
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "serverInfo": {"name": "test-server", "version": "0.1"}
        }),
    )
}

pub fn tools_response(tools: Value) -> JsonRpcResponse {
    ok_response(1, json!({ "tools": tools }))
}

/// Build a `ToolDefinition` with the given name and description for use in scanner tests.
pub fn tool(name: &str, description: &str) -> ToolDefinition {
    ToolDefinition {
        name: name.to_string(),
        description: Some(description.to_string()),
        input_schema: json!({"type": "object"}),
    }
}

/// Build a `ToolDefinition` with no description for use in scanner tests.
pub fn tool_no_desc(name: &str) -> ToolDefinition {
    ToolDefinition {
        name: name.to_string(),
        description: None,
        input_schema: json!({"type": "object"}),
    }
}

#![allow(dead_code)]

use anyhow::Result;
use serde_json::Value;

use crate::protocol::mcp::{CallToolResult, ToolDefinition};
use crate::protocol::session::Session;
use crate::protocol::transport::Transport;

/// High-level interface over an MCP session for use by fuzzer modules.
pub struct Harness<T: Transport> {
    pub(crate) session: Session<T>,
}

impl<T: Transport> Harness<T> {
    pub fn new(transport: T) -> Self {
        Self {
            session: Session::new(transport),
        }
    }

    pub async fn initialize(&mut self) -> Result<()> {
        self.session.initialize().await
    }

    /// Returns the tool list, fetching from server on first call.
    /// Subsequent calls return the cached slice without a network round-trip.
    pub async fn enumerate_tools(&mut self) -> Result<Vec<ToolDefinition>> {
        if self.session.tools.is_empty() {
            self.session.list_tools().await
        } else {
            Ok(self.session.tools.clone())
        }
    }

    /// Zero-copy access to the cached tool list. Empty until `enumerate_tools` is called.
    pub fn tools(&self) -> &[ToolDefinition] {
        &self.session.tools
    }

    pub async fn call_tool(&mut self, name: &str, args: Option<Value>) -> Result<CallToolResult> {
        self.session.call_tool(name, args).await
    }

    pub async fn close(&mut self) -> Result<()> {
        self.session.close().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::mcp::{JsonRpcResponse, ResponseOutcome, ToolContent};
    use crate::protocol::session::SessionState;
    use crate::testutil::MockTransport;
    use serde_json::json;

    #[tokio::test]
    async fn enumerate_tools_fetches_from_server() {
        let list_resp = JsonRpcResponse {
            jsonrpc: "2.0".into(),
            id: Some(1i64.into()),
            outcome: ResponseOutcome::Result(json!({
                "tools": [
                    {"name": "read_file", "description": "reads", "inputSchema": {"type": "object"}}
                ]
            })),
        };
        let mut harness = Harness::new(MockTransport::new(vec![list_resp]));
        harness.session.state = SessionState::Ready;

        let tools = harness.enumerate_tools().await.unwrap();
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].name, "read_file");
    }

    #[tokio::test]
    async fn enumerate_tools_uses_cache_on_second_call() {
        let list_resp = JsonRpcResponse {
            jsonrpc: "2.0".into(),
            id: Some(1i64.into()),
            outcome: ResponseOutcome::Result(json!({
                "tools": [{"name": "ping", "inputSchema": {"type": "object"}}]
            })),
        };
        // Only one response queued — second call must use cache, not hit transport
        let mut harness = Harness::new(MockTransport::new(vec![list_resp]));
        harness.session.state = SessionState::Ready;

        let _ = harness.enumerate_tools().await.unwrap();
        let second = harness.enumerate_tools().await.unwrap();
        assert_eq!(second.len(), 1);
    }

    #[tokio::test]
    async fn tools_returns_empty_before_enumerate() {
        let harness = Harness::new(MockTransport::new(vec![]));
        assert!(harness.tools().is_empty());
    }

    #[tokio::test]
    async fn tools_returns_cached_slice_after_enumerate() {
        let list_resp = JsonRpcResponse {
            jsonrpc: "2.0".into(),
            id: Some(1i64.into()),
            outcome: ResponseOutcome::Result(json!({
                "tools": [{"name": "ping", "inputSchema": {"type": "object"}}]
            })),
        };
        let mut harness = Harness::new(MockTransport::new(vec![list_resp]));
        harness.session.state = SessionState::Ready;
        harness.enumerate_tools().await.unwrap();

        assert_eq!(harness.tools().len(), 1);
        assert_eq!(harness.tools()[0].name, "ping");
    }

    #[tokio::test]
    async fn call_tool_returns_content() {
        let tool_resp = JsonRpcResponse {
            jsonrpc: "2.0".into(),
            id: Some(1i64.into()),
            outcome: ResponseOutcome::Result(json!({
                "content": [{"type": "text", "text": "pong"}]
            })),
        };
        let mut harness = Harness::new(MockTransport::new(vec![tool_resp]));
        harness.session.state = SessionState::Ready;

        let result = harness.call_tool("ping", None).await.unwrap();
        match &result.content[0] {
            ToolContent::Text { text } => assert_eq!(text, "pong"),
            _ => panic!("expected text"),
        }
    }

    #[tokio::test]
    async fn initialize_sends_notification() {
        use crate::protocol::mcp::ResponseOutcome;
        let init_resp = JsonRpcResponse {
            jsonrpc: "2.0".into(),
            id: Some(1i64.into()),
            outcome: ResponseOutcome::Result(json!({
                "protocolVersion": "2024-11-05",
                "capabilities": {}
            })),
        };
        let transport = MockTransport::new(vec![init_resp]);
        let mut harness = Harness::new(transport);
        harness.initialize().await.unwrap();

        // Verify the initialized notification was dispatched via notify(), not send()
        assert_eq!(harness.session.transport.notifications_sent, 1);
    }
}

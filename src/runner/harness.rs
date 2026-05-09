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

    /// Initialize the session and return a ready harness.
    pub async fn initialize(&mut self) -> Result<()> {
        self.session.initialize().await
    }

    /// Returns a copy of the tool list, fetching from server if not yet cached.
    pub async fn enumerate_tools(&mut self) -> Result<Vec<ToolDefinition>> {
        if self.session.tools.is_empty() {
            self.session.list_tools().await
        } else {
            Ok(self.session.tools.clone())
        }
    }

    /// Call a tool and return its result.
    pub async fn call_tool(&mut self, name: &str, args: Option<Value>) -> Result<CallToolResult> {
        self.session.call_tool(name, args).await
    }

    /// Return a reference to cached tools (empty if enumerate_tools not yet called).
    pub fn tools(&self) -> &[ToolDefinition] {
        &self.session.tools
    }

    pub async fn close(&mut self) -> Result<()> {
        self.session.close().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::mcp::{JsonRpcResponse, ResponseOutcome, ToolContent};
    use crate::protocol::transport::Transport;
    use async_trait::async_trait;
    use serde_json::json;
    use std::collections::VecDeque;

    struct MockTransport {
        responses: VecDeque<JsonRpcResponse>,
    }

    impl MockTransport {
        fn new(responses: Vec<JsonRpcResponse>) -> Self {
            Self {
                responses: responses.into(),
            }
        }
    }

    #[async_trait]
    impl Transport for MockTransport {
        async fn send(
            &mut self,
            _req: crate::protocol::mcp::JsonRpcRequest,
        ) -> Result<JsonRpcResponse> {
            self.responses
                .pop_front()
                .ok_or_else(|| anyhow::anyhow!("mock: no more responses"))
        }
        async fn close(&mut self) -> Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn enumerate_tools_calls_list_tools() {
        let list_resp = JsonRpcResponse {
            jsonrpc: "2.0".into(),
            id: Some(1i64.into()),
            outcome: ResponseOutcome::Result(json!({
                "tools": [
                    {"name": "read_file", "description": "reads", "inputSchema": {"type": "object"}}
                ]
            })),
        };
        let transport = MockTransport::new(vec![list_resp]);
        let mut harness = Harness::new(transport);
        harness.session.state = crate::protocol::session::SessionState::Ready;

        let tools = harness.enumerate_tools().await.unwrap();
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].name, "read_file");
    }

    #[tokio::test]
    async fn enumerate_tools_uses_cache_on_second_call() {
        // Only one response available — second call must use cache
        let list_resp = JsonRpcResponse {
            jsonrpc: "2.0".into(),
            id: Some(1i64.into()),
            outcome: ResponseOutcome::Result(json!({
                "tools": [{"name": "ping", "inputSchema": {"type": "object"}}]
            })),
        };
        let transport = MockTransport::new(vec![list_resp]);
        let mut harness = Harness::new(transport);
        harness.session.state = crate::protocol::session::SessionState::Ready;

        let _ = harness.enumerate_tools().await.unwrap();
        let second = harness.enumerate_tools().await.unwrap(); // must not hit transport
        assert_eq!(second.len(), 1);
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
        let transport = MockTransport::new(vec![tool_resp]);
        let mut harness = Harness::new(transport);
        harness.session.state = crate::protocol::session::SessionState::Ready;

        let result = harness.call_tool("ping", None).await.unwrap();
        match &result.content[0] {
            ToolContent::Text { text } => assert_eq!(text, "pong"),
            _ => panic!("expected text"),
        }
    }
}

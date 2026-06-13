use anyhow::Result;
use serde_json::Value;

use crate::protocol::mcp::{CallToolResult, PromptDefinition, ResourceDefinition, ToolDefinition};
use crate::protocol::session::Session;
use crate::protocol::transport::Transport;

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

    /// Returns the tool list, fetching from the server on first call then caching.
    pub async fn enumerate_tools(&mut self) -> Result<Vec<ToolDefinition>> {
        if self.session.tools.is_empty() {
            self.session.list_tools().await
        } else {
            Ok(self.session.tools.clone())
        }
    }

    /// Zero-copy access to the cached tool list. Empty until `enumerate_tools` is called.
    #[allow(dead_code)]
    pub fn tools(&self) -> &[ToolDefinition] {
        &self.session.tools
    }

    /// Returns the prompt list, fetching on first call then caching.
    /// Returns an error if the server does not support prompts/list — callers should
    /// handle with `if let Ok(...)` rather than propagating.
    pub async fn enumerate_prompts(&mut self) -> Result<Vec<PromptDefinition>> {
        if self.session.prompts.is_empty() {
            self.session.list_prompts().await
        } else {
            Ok(self.session.prompts.clone())
        }
    }

    /// Returns the resource list, fetching on first call then caching.
    /// Returns an error if the server does not support resources/list — callers should
    /// handle with `if let Ok(...)` rather than propagating.
    pub async fn enumerate_resources(&mut self) -> Result<Vec<ResourceDefinition>> {
        if self.session.resources.is_empty() {
            self.session.list_resources().await
        } else {
            Ok(self.session.resources.clone())
        }
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
    use crate::protocol::mcp::ToolContent;
    use crate::protocol::session::SessionState;
    use crate::testutil::{init_response, ok_response, tools_response, MockTransport};
    use serde_json::json;

    fn ready(responses: Vec<crate::protocol::mcp::JsonRpcResponse>) -> Harness<MockTransport> {
        let mut h = Harness::new(MockTransport::new(responses));
        h.session.state = SessionState::Ready;
        h
    }

    #[tokio::test]
    async fn enumerate_tools_fetches_from_server() {
        let mut h = ready(vec![tools_response(json!([
            {"name": "read_file", "description": "reads", "inputSchema": {"type": "object"}}
        ]))]);
        let tools = h.enumerate_tools().await.unwrap();
        assert_eq!(tools[0].name, "read_file");
    }

    #[tokio::test]
    async fn enumerate_tools_uses_cache_on_second_call() {
        let mut h = ready(vec![tools_response(json!([
            {"name": "ping", "inputSchema": {"type": "object"}}
        ]))]);
        h.enumerate_tools().await.unwrap();
        let second = h.enumerate_tools().await.unwrap(); // must not hit transport
        assert_eq!(second.len(), 1);
    }

    #[tokio::test]
    async fn tools_returns_empty_before_enumerate() {
        assert!(Harness::new(MockTransport::new(vec![])).tools().is_empty());
    }

    #[tokio::test]
    async fn tools_returns_cached_slice_after_enumerate() {
        let mut h = ready(vec![tools_response(json!([
            {"name": "ping", "inputSchema": {"type": "object"}}
        ]))]);
        h.enumerate_tools().await.unwrap();
        assert_eq!(h.tools()[0].name, "ping");
    }

    #[tokio::test]
    async fn call_tool_returns_content() {
        let mut h = ready(vec![ok_response(
            1,
            json!({"content": [{"type":"text","text":"pong"}]}),
        )]);
        let result = h.call_tool("ping", None).await.unwrap();
        match &result.content[0] {
            ToolContent::Text { text } => assert_eq!(text, "pong"),
            _ => panic!("expected text"),
        }
    }

    #[tokio::test]
    async fn initialize_sends_notification() {
        let mut h = Harness::new(MockTransport::new(vec![init_response()]));
        h.initialize().await.unwrap();
        assert_eq!(h.session.transport.notifications_sent, 1);
    }
}

#![allow(dead_code)]

use std::sync::atomic::{AtomicI64, Ordering};

use anyhow::{anyhow, bail, Result};

use crate::protocol::mcp::{
    methods, CallToolParams, CallToolResult, InitializeParams, InitializeResult, JsonRpcRequest,
    ListToolsResult, ResponseOutcome, ToolDefinition,
};
use crate::protocol::transport::Transport;

#[derive(Debug, Clone, PartialEq)]
pub enum SessionState {
    Unconnected,
    Initializing,
    Ready,
    Closed,
}

pub struct Session<T: Transport> {
    pub(crate) transport: T,
    pub(crate) state: SessionState,
    counter: AtomicI64,
    pub server_info: Option<InitializeResult>,
    pub tools: Vec<ToolDefinition>,
}

impl<T: Transport> Session<T> {
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            state: SessionState::Unconnected,
            counter: AtomicI64::new(1),
            server_info: None,
            tools: Vec::new(),
        }
    }

    /// Construct a session already in the Ready state. For use in tests only.
    #[cfg(test)]
    pub(crate) fn ready(transport: T) -> Self {
        Self {
            transport,
            state: SessionState::Ready,
            counter: AtomicI64::new(1),
            server_info: None,
            tools: Vec::new(),
        }
    }

    fn next_id(&self) -> i64 {
        self.counter.fetch_add(1, Ordering::Relaxed)
    }

    /// Drive the initialize → initialized handshake and enumerate tools.
    pub async fn initialize(&mut self) -> Result<()> {
        if self.state != SessionState::Unconnected {
            bail!("session already initialized (state: {:?})", self.state);
        }
        self.state = SessionState::Initializing;

        let params = InitializeParams {
            protocol_version: "2024-11-05".into(),
            capabilities: Default::default(),
            client_info: Default::default(),
        };

        let req = JsonRpcRequest::new(
            self.next_id(),
            methods::INITIALIZE,
            Some(serde_json::to_value(params)?),
        );

        let resp = self.transport.send(req).await?;
        self.server_info = Some(serde_json::from_value::<InitializeResult>(outcome_result(
            resp.outcome,
        )?)?);

        // Notifications have no response — use notify() to avoid blocking on a reply.
        let notif = JsonRpcRequest::new(self.next_id(), methods::INITIALIZED, None);
        self.transport.notify(notif).await?;

        self.state = SessionState::Ready;
        Ok(())
    }

    /// Fetch and cache the server's tool list.
    pub async fn list_tools(&mut self) -> Result<Vec<ToolDefinition>> {
        self.require_ready()?;

        let req = JsonRpcRequest::new(self.next_id(), methods::TOOLS_LIST, None);
        let resp = self.transport.send(req).await?;
        let list: ListToolsResult = serde_json::from_value(outcome_result(resp.outcome)?)?;
        self.tools = list.tools;
        Ok(self.tools.clone())
    }

    /// Call a tool by name with the given arguments.
    pub async fn call_tool(
        &mut self,
        name: &str,
        arguments: Option<serde_json::Value>,
    ) -> Result<CallToolResult> {
        self.require_ready()?;

        let params = CallToolParams {
            name: name.to_string(),
            arguments,
        };
        let req = JsonRpcRequest::new(
            self.next_id(),
            methods::TOOLS_CALL,
            Some(serde_json::to_value(params)?),
        );

        let resp = self.transport.send(req).await?;
        Ok(serde_json::from_value::<CallToolResult>(outcome_result(
            resp.outcome,
        )?)?)
    }

    pub fn state(&self) -> &SessionState {
        &self.state
    }

    pub async fn close(&mut self) -> Result<()> {
        self.transport.close().await?;
        self.state = SessionState::Closed;
        Ok(())
    }

    fn require_ready(&self) -> Result<()> {
        if self.state != SessionState::Ready {
            bail!("session not ready (state: {:?})", self.state);
        }
        Ok(())
    }
}

fn outcome_result(outcome: ResponseOutcome) -> Result<serde_json::Value> {
    match outcome {
        ResponseOutcome::Result(v) => Ok(v),
        ResponseOutcome::Error(e) => Err(anyhow!("server error {}: {}", e.code, e.message)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::mcp::{JsonRpcError, JsonRpcResponse, ResponseOutcome, ToolContent};
    use crate::testutil::{init_response, ok_response, tools_response, MockTransport};
    use serde_json::json;

    #[tokio::test]
    async fn session_starts_unconnected() {
        let session = Session::new(MockTransport::new(vec![]));
        assert_eq!(*session.state(), SessionState::Unconnected);
    }

    #[tokio::test]
    async fn initialize_transitions_to_ready() {
        let mut session = Session::new(MockTransport::new(vec![init_response()]));
        session.initialize().await.unwrap();
        assert_eq!(*session.state(), SessionState::Ready);
    }

    #[tokio::test]
    async fn initialize_twice_errors() {
        let mut session = Session::ready(MockTransport::new(vec![]));
        let err = session.initialize().await.unwrap_err();
        assert!(err.to_string().contains("already initialized"));
    }

    #[tokio::test]
    async fn list_tools_before_ready_errors() {
        let mut session = Session::new(MockTransport::new(vec![]));
        let err = session.list_tools().await.unwrap_err();
        assert!(err.to_string().contains("not ready"));
    }

    #[tokio::test]
    async fn list_tools_returns_definitions() {
        let resp = tools_response(json!([
            {"name": "read_file", "description": "reads a file", "inputSchema": {"type": "object"}}
        ]));
        let mut session = Session::ready(MockTransport::new(vec![resp]));
        let tools = session.list_tools().await.unwrap();
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].name, "read_file");
        assert_eq!(session.tools.len(), 1);
    }

    #[tokio::test]
    async fn call_tool_before_ready_errors() {
        let mut session = Session::new(MockTransport::new(vec![]));
        let err = session.call_tool("foo", None).await.unwrap_err();
        assert!(err.to_string().contains("not ready"));
    }

    #[tokio::test]
    async fn call_tool_returns_result() {
        let resp = ok_response(
            1,
            json!({"content": [{"type": "text", "text": "file contents"}], "isError": false}),
        );
        let mut session = Session::ready(MockTransport::new(vec![resp]));
        let result = session
            .call_tool("read_file", Some(json!({"path": "/tmp/test.txt"})))
            .await
            .unwrap();
        match &result.content[0] {
            ToolContent::Text { text } => assert_eq!(text, "file contents"),
            _ => panic!("expected text"),
        }
    }

    #[tokio::test]
    async fn call_tool_server_error_propagates() {
        let err_resp = JsonRpcResponse {
            jsonrpc: "2.0".into(),
            id: Some(1i64.into()),
            outcome: ResponseOutcome::Error(JsonRpcError {
                code: -32601,
                message: "Method not found".into(),
                data: None,
            }),
        };
        let mut session = Session::ready(MockTransport::new(vec![err_resp]));
        let err = session.call_tool("nonexistent", None).await.unwrap_err();
        assert!(err.to_string().contains("Method not found"));
    }

    #[tokio::test]
    async fn close_transitions_to_closed() {
        let mut session = Session::ready(MockTransport::new(vec![]));
        session.close().await.unwrap();
        assert_eq!(*session.state(), SessionState::Closed);
    }

    #[tokio::test]
    async fn per_session_counter_starts_at_one() {
        let session = Session::new(MockTransport::new(vec![]));
        assert_eq!(session.next_id(), 1);
        assert_eq!(session.next_id(), 2);
    }

    #[tokio::test]
    async fn two_sessions_have_independent_counters() {
        let s1 = Session::new(MockTransport::new(vec![]));
        let s2 = Session::new(MockTransport::new(vec![]));
        assert_eq!(s1.next_id(), 1);
        assert_eq!(s2.next_id(), 1);
    }
}

#![allow(dead_code)]

pub mod http;
pub mod stdio;

use crate::protocol::mcp::{JsonRpcRequest, JsonRpcResponse};
use anyhow::Result;

/// Common interface for MCP transports (stdio and HTTP+SSE).
#[async_trait::async_trait]
pub trait Transport: Send {
    /// Send a request and wait for its response (matched by id).
    async fn send(&mut self, request: JsonRpcRequest) -> Result<JsonRpcResponse>;

    /// Send a notification (no response expected, no id registration).
    async fn notify(&mut self, notification: JsonRpcRequest) -> Result<()>;

    async fn close(&mut self) -> Result<()>;
}

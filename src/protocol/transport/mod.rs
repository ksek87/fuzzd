#![allow(dead_code)]

pub mod http;
pub mod stdio;

use crate::protocol::mcp::{JsonRpcRequest, JsonRpcResponse};
use anyhow::Result;

/// Common interface for MCP transports (stdio and HTTP+SSE).
#[async_trait::async_trait]
pub trait Transport: Send {
    async fn send(&mut self, request: JsonRpcRequest) -> Result<JsonRpcResponse>;
    async fn close(&mut self) -> Result<()>;
}

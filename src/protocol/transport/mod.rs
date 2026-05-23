// Pending CLI wiring in the audit command (v0.3+).
#![allow(dead_code)]

pub mod http;
pub mod stdio;

use crate::protocol::mcp::{JsonRpcRequest, JsonRpcResponse, RequestId};
use anyhow::Result;
use std::collections::HashMap;
use tokio::sync::{oneshot, Mutex};

#[async_trait::async_trait]
pub trait Transport: Send {
    async fn send(&mut self, request: JsonRpcRequest) -> Result<JsonRpcResponse>;
    async fn notify(&mut self, notification: JsonRpcRequest) -> Result<()>;
    async fn close(&mut self) -> Result<()>;
}

// Shared infrastructure used by both stdio and HTTP transports.

pub(crate) type PendingMap =
    std::sync::Arc<Mutex<HashMap<String, oneshot::Sender<JsonRpcResponse>>>>;

pub(crate) fn id_key(id: Option<&RequestId>) -> String {
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
    fn id_key_number() {
        assert_eq!(id_key(Some(&RequestId::Number(42))), "42");
    }

    #[test]
    fn id_key_string() {
        assert_eq!(id_key(Some(&RequestId::String("abc".into()))), "abc");
    }

    #[test]
    fn id_key_none() {
        assert_eq!(id_key(None), "__notification__");
    }
}

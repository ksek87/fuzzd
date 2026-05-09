#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use serde_json::Value;

// JSON-RPC 2.0 envelope types

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub id: RequestId,
    pub method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
}

impl JsonRpcRequest {
    pub fn new(id: impl Into<RequestId>, method: impl Into<String>, params: Option<Value>) -> Self {
        Self {
            jsonrpc: "2.0".into(),
            id: id.into(),
            method: method.into(),
            params,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum RequestId {
    Number(i64),
    String(String),
}

impl From<i64> for RequestId {
    fn from(n: i64) -> Self {
        Self::Number(n)
    }
}

impl From<&str> for RequestId {
    fn from(s: &str) -> Self {
        Self::String(s.to_string())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    pub id: Option<RequestId>,
    #[serde(flatten)]
    pub outcome: ResponseOutcome,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ResponseOutcome {
    Result(Value),
    Error(JsonRpcError),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

impl JsonRpcError {
    pub fn parse_error() -> Self {
        Self {
            code: -32700,
            message: "Parse error".into(),
            data: None,
        }
    }
    pub fn invalid_request() -> Self {
        Self {
            code: -32600,
            message: "Invalid Request".into(),
            data: None,
        }
    }
    pub fn method_not_found() -> Self {
        Self {
            code: -32601,
            message: "Method not found".into(),
            data: None,
        }
    }
    pub fn internal_error() -> Self {
        Self {
            code: -32603,
            message: "Internal error".into(),
            data: None,
        }
    }
}

// MCP-specific types

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct InitializeParams {
    pub protocol_version: String,
    pub capabilities: ClientCapabilities,
    pub client_info: ClientInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct ClientCapabilities {}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ClientInfo {
    pub name: String,
    pub version: String,
}

impl Default for ClientInfo {
    fn default() -> Self {
        Self {
            name: "fuzzd".into(),
            version: env!("CARGO_PKG_VERSION").into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct InitializeResult {
    pub protocol_version: String,
    pub capabilities: ServerCapabilities,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_info: Option<ServerInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct ServerCapabilities {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tools: Option<ToolsCapability>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct ToolsCapability {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub list_changed: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ServerInfo {
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ToolDefinition {
    pub name: String,
    pub description: Option<String>,
    #[serde(rename = "inputSchema")]
    pub input_schema: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ListToolsResult {
    pub tools: Vec<ToolDefinition>,
    #[serde(rename = "nextCursor", skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CallToolParams {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arguments: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CallToolResult {
    pub content: Vec<ToolContent>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_error: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum ToolContent {
    Text { text: String },
    Image { data: String, mime_type: String },
    Resource { resource: Value },
}

// Method name constants
pub mod methods {
    pub const INITIALIZE: &str = "initialize";
    pub const INITIALIZED: &str = "notifications/initialized";
    pub const TOOLS_LIST: &str = "tools/list";
    pub const TOOLS_CALL: &str = "tools/call";
    pub const PING: &str = "ping";
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn request_serializes_with_jsonrpc_field() {
        let req = JsonRpcRequest::new(1i64, "initialize", None);
        let v = serde_json::to_value(&req).unwrap();
        assert_eq!(v["jsonrpc"], "2.0");
        assert_eq!(v["method"], "initialize");
        assert_eq!(v["id"], 1);
        assert!(v.get("params").is_none());
    }

    #[test]
    fn request_with_params_serializes() {
        let req = JsonRpcRequest::new(1i64, "tools/call", Some(json!({"name": "foo"})));
        let v = serde_json::to_value(&req).unwrap();
        assert_eq!(v["params"]["name"], "foo");
    }

    #[test]
    fn response_result_roundtrip() {
        let resp = JsonRpcResponse {
            jsonrpc: "2.0".into(),
            id: Some(RequestId::Number(1)),
            outcome: ResponseOutcome::Result(json!({"protocolVersion": "2024-11-05"})),
        };
        let s = serde_json::to_string(&resp).unwrap();
        let back: JsonRpcResponse = serde_json::from_str(&s).unwrap();
        assert_eq!(resp, back);
    }

    #[test]
    fn response_error_roundtrip() {
        let resp = JsonRpcResponse {
            jsonrpc: "2.0".into(),
            id: Some(RequestId::Number(1)),
            outcome: ResponseOutcome::Error(JsonRpcError::method_not_found()),
        };
        let s = serde_json::to_string(&resp).unwrap();
        let back: JsonRpcResponse = serde_json::from_str(&s).unwrap();
        assert_eq!(resp, back);
    }

    #[test]
    fn tool_definition_deserializes() {
        let json = json!({
            "name": "read_file",
            "description": "Reads a file",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": {"type": "string"}
                },
                "required": ["path"]
            }
        });
        let tool: ToolDefinition = serde_json::from_value(json).unwrap();
        assert_eq!(tool.name, "read_file");
        assert_eq!(tool.description.as_deref(), Some("Reads a file"));
    }

    #[test]
    fn tool_definition_without_description_deserializes() {
        let json = json!({
            "name": "ping",
            "inputSchema": {"type": "object"}
        });
        let tool: ToolDefinition = serde_json::from_value(json).unwrap();
        assert!(tool.description.is_none());
    }

    #[test]
    fn call_tool_result_text_content() {
        let json = json!({
            "content": [{"type": "text", "text": "hello"}],
            "isError": false
        });
        let result: CallToolResult = serde_json::from_value(json).unwrap();
        assert_eq!(result.content.len(), 1);
        match &result.content[0] {
            ToolContent::Text { text } => assert_eq!(text, "hello"),
            _ => panic!("expected text content"),
        }
    }

    #[test]
    fn request_id_string_variant() {
        let req = JsonRpcRequest::new("req-1", "ping", None);
        let v = serde_json::to_value(&req).unwrap();
        assert_eq!(v["id"], "req-1");
    }

    #[test]
    fn json_rpc_error_codes() {
        assert_eq!(JsonRpcError::parse_error().code, -32700);
        assert_eq!(JsonRpcError::invalid_request().code, -32600);
        assert_eq!(JsonRpcError::method_not_found().code, -32601);
        assert_eq!(JsonRpcError::internal_error().code, -32603);
    }
}

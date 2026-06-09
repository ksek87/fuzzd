//! Minimal MCP-over-stdio reference server, used only by the end-to-end
//! integration tests (`tests/audit_stdio.rs`). It is compiled solely when the
//! `test-fixtures` feature is enabled, so it never ships in the release binary.
//!
//! It speaks just enough of the MCP/JSON-RPC handshake for `fuzzd audit
//! --transport stdio` to drive it: `initialize`, `tools/list`, `tools/call`,
//! and `ping`. The tool definitions it advertises are loaded verbatim from a
//! JSON fixture file passed as the first argument, so a single binary serves
//! both the poisoned and the clean tool sets — one source of truth shared with
//! the `scan` tests.
//!
//! Deliberately self-contained (std + serde_json only): a bin-only crate cannot
//! import the parent's internal MCP types, and hand-emitting the four response
//! shapes keeps the fixture honest about wire format.

use std::error::Error;
use std::io::{self, BufRead, Write};

use serde_json::{json, Value};

fn main() {
    if let Err(e) = run() {
        eprintln!("reference_server: {e}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let fixture = std::env::args()
        .nth(1)
        .ok_or("usage: reference_server <tools.json>")?;
    let src = std::fs::read_to_string(&fixture)?;
    // The fixture is a bare JSON array of tool definitions — the same shape the
    // `scan` command accepts — so it is embedded directly under `tools`.
    let tools: Value = serde_json::from_str(&src)?;

    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut out = stdout.lock();

    for line in stdin.lock().lines() {
        let line = line?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let req: Value = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(_) => continue,
        };

        let method = req.get("method").and_then(Value::as_str).unwrap_or("");
        // Notifications (e.g. notifications/initialized) carry no reply.
        if method.starts_with("notifications/") {
            continue;
        }
        let id = req.get("id").cloned().unwrap_or(Value::Null);

        let response = match method {
            "initialize" => ok(
                &id,
                json!({
                    "protocolVersion": "2024-11-05",
                    "capabilities": { "tools": {} },
                    "serverInfo": { "name": "fuzzd-reference-server", "version": "0.0.0" }
                }),
            ),
            "tools/list" => ok(&id, json!({ "tools": tools })),
            "tools/call" => ok(
                &id,
                json!({ "content": [{ "type": "text", "text": "ok" }], "isError": false }),
            ),
            "ping" => ok(&id, json!({})),
            _ => json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": { "code": -32601, "message": "Method not found" }
            }),
        };

        writeln!(out, "{response}")?;
        out.flush()?;
    }

    Ok(())
}

fn ok(id: &Value, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

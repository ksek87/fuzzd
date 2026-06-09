//! End-to-end tests for `fuzzd audit --transport stdio` against a live MCP
//! server. The server is the `reference_server` fixture binary, spawned as a
//! real child process and driven over the full MCP handshake (initialize →
//! tools/list → tools/call). This is the only test layer that exercises the
//! transport + session state machine against a genuine peer process; the unit
//! tests use `MockTransport` in-memory.
//!
//! Gated behind the `test-fixtures` feature so the reference-server binary is
//! built (CI runs `cargo test --all-features`). With the feature off, the whole
//! crate compiles away — local `cargo test` stays green without the fixture.
#![cfg(feature = "test-fixtures")]

mod common;
use common::{fixture, fuzzd};

use serde_json::Value;

/// `--cmd` string that launches the reference server serving the named fixture.
/// `StdioTransport` splits this on whitespace into program + args; the fixture
/// paths contain no spaces.
fn server_serving(fixture_name: &str) -> String {
    format!(
        "{} {}",
        env!("CARGO_BIN_EXE_reference_server"),
        fixture(fixture_name).display()
    )
}

#[test]
fn audit_detects_tool_poisoning_from_a_live_server() {
    let out = fuzzd()
        .args(["audit", "--transport", "stdio", "--cmd"])
        .arg(server_serving("vulnerable_tools.json"))
        .args(["--attacks", "tool_poisoning", "--output", "json"])
        .output()
        .expect("spawn fuzzd");

    assert_eq!(
        out.status.code(),
        Some(1),
        "auditing a server that advertises a poisoned tool must gate with exit 1"
    );
    let report: Value = serde_json::from_slice(&out.stdout).expect("stdout is valid JSON");
    let findings = report["findings"].as_array().expect("findings array");
    assert!(
        findings.iter().any(|f| f["tool"] == "read_notes"),
        "the poisoned tool enumerated over the live transport must be flagged"
    );
}

#[test]
fn audit_clean_server_reports_no_findings() {
    // Runs both the static (tool_poisoning) and dynamic (argument) modules; the
    // argument module drives real tools/call round-trips against the server.
    let out = fuzzd()
        .args(["audit", "--transport", "stdio", "--cmd"])
        .arg(server_serving("clean_tools.json"))
        .args(["--attacks", "tool_poisoning,argument", "--output", "json"])
        .output()
        .expect("spawn fuzzd");

    assert!(
        out.status.success(),
        "a clean server must not gate CI (expected exit 0)"
    );
    let report: Value = serde_json::from_slice(&out.stdout).expect("stdout is valid JSON");
    assert_eq!(
        report["findings"].as_array().expect("findings array").len(),
        0,
        "a clean server must produce zero findings across both attack modules"
    );
}

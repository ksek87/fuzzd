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
fn audit_chain_flags_runtime_credential_access() {
    // Drives a scripted chain through the live server: a benign call followed by
    // one carrying an AWS credential path in its runtime arguments. The chain
    // analyzer must flag it — and Critical severity must gate CI with exit 1.
    let out = fuzzd()
        .args(["audit", "--transport", "stdio", "--cmd"])
        .arg(server_serving("clean_tools.json"))
        .args(["--attacks", "chain", "--chains"])
        .arg(fixture("chain_credential_exfil.json"))
        .args(["--output", "json"])
        .output()
        .expect("spawn fuzzd");

    assert_eq!(
        out.status.code(),
        Some(1),
        "a runtime credential-path access surfaced mid-chain must gate with exit 1"
    );
    let report: Value = serde_json::from_slice(&out.stdout).expect("stdout is valid JSON");
    let findings = report["findings"].as_array().expect("findings array");
    assert!(
        findings
            .iter()
            .any(|f| f["signal"] == "runtime_credential_access"),
        "the credential path in the chain's runtime args must be flagged"
    );
}

#[test]
fn audit_chain_clean_script_reports_no_findings() {
    let out = fuzzd()
        .args(["audit", "--transport", "stdio", "--cmd"])
        .arg(server_serving("clean_tools.json"))
        .args(["--attacks", "chain", "--chains"])
        .arg(fixture("chain_clean.json"))
        .args(["--output", "json"])
        .output()
        .expect("spawn fuzzd");

    assert!(
        out.status.success(),
        "a benign chain must not gate CI (expected exit 0)"
    );
    let report: Value = serde_json::from_slice(&out.stdout).expect("stdout is valid JSON");
    assert_eq!(
        report["findings"].as_array().expect("findings array").len(),
        0,
        "a benign chain must produce zero findings"
    );
}

#[test]
fn audit_peer_injection_surfaces_corpus_tpa_tools() {
    // Runs the peer-injection module against the clean server. The embedded
    // corpus contains TPA records with poisoned payloads; the static scanner
    // and sequence injector must flag at least one, gating CI with exit 1.
    let out = fuzzd()
        .args(["audit", "--transport", "stdio", "--cmd"])
        .arg(server_serving("clean_tools.json"))
        .args(["--attacks", "peer", "--output", "json"])
        .output()
        .expect("spawn fuzzd");

    assert_eq!(
        out.status.code(),
        Some(1),
        "embedded TPA corpus records injected as peer tools must gate CI with exit 1"
    );
    let report: Value = serde_json::from_slice(&out.stdout).expect("stdout is valid JSON");
    let findings = report["findings"].as_array().expect("findings array");
    assert!(
        !findings.is_empty(),
        "at least one peer-injection finding must be reported from the embedded corpus"
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

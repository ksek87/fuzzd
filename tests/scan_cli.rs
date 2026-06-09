//! End-to-end tests for `fuzzd scan`: invoke the real compiled binary against
//! on-disk fixtures and assert on exit codes, finding content, and report
//! validity. These exercise the full CLI → scanner → reporter → process-exit
//! path that unit tests (which stop at `DescriptionScanner::scan`) cannot.

mod common;
use common::{fixture, fuzzd};

use serde_json::Value;

fn run_scan(fixture_name: &str, format: &str) -> std::process::Output {
    fuzzd()
        .args(["scan", "--schema"])
        .arg(fixture(fixture_name))
        .args(["--output", format])
        .output()
        .expect("spawn fuzzd")
}

#[test]
fn scan_clean_fixture_exits_zero_with_no_findings() {
    let out = run_scan("clean_tools.json", "json");
    assert!(
        out.status.success(),
        "a clean tool set must not block CI (expected exit 0)"
    );
    let report: Value = serde_json::from_slice(&out.stdout).expect("stdout is valid JSON");
    assert_eq!(report["tools_scanned"], 2);
    assert_eq!(
        report["findings"].as_array().expect("findings array").len(),
        0,
        "clean tools must produce zero findings (0% false positive)"
    );
}

#[test]
fn scan_poisoned_fixture_exits_nonzero_and_flags_the_tool() {
    let out = run_scan("vulnerable_tools.json", "json");
    assert_eq!(
        out.status.code(),
        Some(1),
        "a High/Critical finding must gate CI with exit code 1"
    );
    let report: Value = serde_json::from_slice(&out.stdout).expect("stdout is valid JSON");
    let findings = report["findings"].as_array().expect("findings array");
    assert!(
        findings.iter().any(|f| f["tool"] == "read_notes"),
        "the poisoned tool must be named in the findings"
    );
    assert!(
        findings.iter().any(|f| f["severity"] == "critical"),
        "the SSH private-key reference must surface as Critical"
    );
}

#[test]
fn scan_emits_complete_valid_sarif_on_the_blocking_path() {
    // The exit-1 path is the one the GitHub Action (#66) relies on: findings
    // must still produce complete, parseable SARIF for Code Scanning upload.
    let out = run_scan("vulnerable_tools.json", "sarif");
    assert_eq!(out.status.code(), Some(1));

    let sarif: Value = serde_json::from_slice(&out.stdout).expect("complete SARIF JSON");
    assert_eq!(sarif["version"], "2.1.0");
    let driver = &sarif["runs"][0]["tool"]["driver"];
    assert_eq!(driver["name"], "fuzzd");
    // Guards the version-credibility fix: driver.version must report the real
    // crate version, never the scaffold's stale 0.1.0.
    assert_eq!(driver["version"], env!("CARGO_PKG_VERSION"));
    assert_ne!(driver["version"], "0.1.0");
    assert!(
        !sarif["runs"][0]["results"]
            .as_array()
            .expect("results array")
            .is_empty(),
        "poisoned tools must yield SARIF results"
    );
}

#[test]
fn scan_clean_fixture_emits_valid_sarif_with_no_results() {
    let out = run_scan("clean_tools.json", "sarif");
    assert!(out.status.success());
    let sarif: Value = serde_json::from_slice(&out.stdout).expect("valid SARIF");
    assert_eq!(sarif["version"], "2.1.0");
    assert_eq!(
        sarif["runs"][0]["results"]
            .as_array()
            .expect("results array")
            .len(),
        0
    );
}

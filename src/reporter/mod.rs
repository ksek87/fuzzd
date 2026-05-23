use std::path::Path;

use anyhow::Result;
use serde_json::json;

use crate::cli::OutputFormat;
use crate::corpus::Severity;
use crate::fuzzer::{Finding, Signal};

pub struct BenchmarkReport {
    pub tools_total: usize,
    pub tp: usize,
    pub fp: usize,
    pub fn_count: usize,
    pub tn: usize,
    pub precision: f64,
    pub recall: f64,
    pub f1: f64,
}

pub fn write_findings(
    findings: &[Finding],
    tools_scanned: usize,
    format: &OutputFormat,
    out: Option<&Path>,
) -> Result<()> {
    let content = match format {
        OutputFormat::Markdown => render_markdown(findings, tools_scanned),
        OutputFormat::Json => render_json(findings, tools_scanned)?,
        OutputFormat::Sarif => render_sarif(findings)?,
    };
    write_output(&content, out)
}

pub fn write_benchmark(
    report: &BenchmarkReport,
    format: &OutputFormat,
    out: Option<&Path>,
) -> Result<()> {
    let content = match format {
        OutputFormat::Markdown => render_benchmark_markdown(report),
        OutputFormat::Json | OutputFormat::Sarif => render_benchmark_json(report)?,
    };
    write_output(&content, out)
}

fn write_output(content: &str, out: Option<&Path>) -> Result<()> {
    match out {
        Some(path) => std::fs::write(path, content).map_err(Into::into),
        None => {
            print!("{content}");
            Ok(())
        }
    }
}

fn render_markdown(findings: &[Finding], tools_scanned: usize) -> String {
    if findings.is_empty() {
        return format!("No issues found in {} tool(s).\n", tools_scanned);
    }
    let mut out = String::new();
    out.push_str(&format!(
        "{} finding(s) in {} tool(s):\n\n",
        findings.len(),
        tools_scanned
    ));
    for f in findings {
        out.push_str(&format!(
            "[{}] {} — {} ({})\n",
            f.severity, f.tool_name, f.signal, f.detail
        ));
        out.push_str(&format!("  matched: {}\n", f.matched_text));
        if !f.corpus_refs.is_empty() {
            out.push_str(&format!("  refs:    {}\n", f.corpus_refs.join(", ")));
        }
        out.push('\n');
    }
    out
}

fn render_json(findings: &[Finding], tools_scanned: usize) -> Result<String> {
    let arr: Vec<_> = findings
        .iter()
        .map(|f| {
            json!({
                "tool": f.tool_name,
                "signal": f.signal.to_string(),
                "severity": f.severity.to_string(),
                "matched": f.matched_text,
                "detail": f.detail,
                "corpus_refs": f.corpus_refs,
            })
        })
        .collect();
    let wrapper = json!({
        "tools_scanned": tools_scanned,
        "findings": arr,
    });
    Ok(serde_json::to_string_pretty(&wrapper)?)
}

fn render_sarif(findings: &[Finding]) -> Result<String> {
    let rules = sarif_rules();
    let results: Vec<_> = findings
        .iter()
        .map(|f| {
            json!({
                "ruleId": signal_rule_id(&f.signal),
                "level": severity_level(&f.severity),
                "message": {"text": format!("{}: {}", f.detail, f.matched_text)},
                "locations": [{
                    "logicalLocations": [{"name": f.tool_name, "kind": "function"}]
                }]
            })
        })
        .collect();

    let sarif = json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "fuzzd",
                    "version": env!("CARGO_PKG_VERSION"),
                    "informationUri": "https://github.com/ksek87/fuzzd",
                    "rules": rules,
                }
            },
            "results": results,
        }]
    });
    Ok(serde_json::to_string_pretty(&sarif)?)
}

fn render_benchmark_markdown(report: &BenchmarkReport) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "Benchmark results ({} tools):\n\n",
        report.tools_total
    ));
    out.push_str(&format!("  True positives:  {}\n", report.tp));
    out.push_str(&format!("  False positives: {}\n", report.fp));
    out.push_str(&format!("  False negatives: {}\n", report.fn_count));
    out.push_str(&format!("  True negatives:  {}\n\n", report.tn));
    out.push_str(&format!("  Precision: {:.3}\n", report.precision));
    out.push_str(&format!("  Recall:    {:.3}\n", report.recall));
    out.push_str(&format!("  F1:        {:.3}\n", report.f1));
    out
}

fn render_benchmark_json(report: &BenchmarkReport) -> Result<String> {
    let obj = json!({
        "tools_total": report.tools_total,
        "tp": report.tp,
        "fp": report.fp,
        "fn": report.fn_count,
        "tn": report.tn,
        "precision": report.precision,
        "recall": report.recall,
        "f1": report.f1,
    });
    Ok(serde_json::to_string_pretty(&obj)?)
}

fn severity_level(sev: &Severity) -> &'static str {
    match sev {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low => "note",
        Severity::Info => "none",
    }
}

fn signal_rule_id(signal: &Signal) -> &'static str {
    match signal {
        Signal::ImperativeOverride => "FUZZD-001",
        Signal::CredentialReference => "FUZZD-002",
        Signal::PrivilegedPath => "FUZZD-003",
        Signal::ExfiltrationMechanism => "FUZZD-004",
        Signal::StealthLanguage => "FUZZD-005",
        Signal::SessionPersistence => "FUZZD-006",
        Signal::CrossToolContamination => "FUZZD-007",
        Signal::FakePrerequisite => "FUZZD-008",
        Signal::ArgumentInterception => "FUZZD-009",
        Signal::HtmlInjectionTag => "FUZZD-010",
        Signal::ConditionalActivation => "FUZZD-011",
        Signal::MessageHijacking => "FUZZD-012",
        Signal::UnicodeObfuscation => "FUZZD-013",
        Signal::EmbeddedInstruction => "FUZZD-014",
    }
}

fn signal_description(signal: &Signal) -> &'static str {
    match signal {
        Signal::ImperativeOverride => {
            "All-caps authority language or imperative overrides in a tool description"
        }
        Signal::CredentialReference => "References to credential files, keys, or secrets",
        Signal::PrivilegedPath => "Absolute or home-relative paths to privileged system locations",
        Signal::ExfiltrationMechanism => {
            "Shell commands or encoding mechanisms suggesting data exfiltration"
        }
        Signal::StealthLanguage => "Language designed to hide behavior from the user or operator",
        Signal::SessionPersistence => {
            "Instructions that claim to persist across the entire session"
        }
        Signal::CrossToolContamination => "Triggers that activate across tool boundaries",
        Signal::FakePrerequisite => "Claims another tool must run first to unlock this one",
        Signal::ArgumentInterception => {
            "Instructions to intercept or modify tool arguments before execution"
        }
        Signal::HtmlInjectionTag => "XML/HTML injection tags used to override LLM behavior",
        Signal::ConditionalActivation => {
            "Conditional activation language indicating sleeper/rug-pull behavior"
        }
        Signal::MessageHijacking => {
            "Instructions to redirect messages to an attacker-controlled destination"
        }
        Signal::UnicodeObfuscation => {
            "Zero-width or invisible Unicode characters hiding malicious instructions"
        }
        Signal::EmbeddedInstruction => "Prompt-injection instruction detected in a tool response",
    }
}

fn sarif_rules() -> Vec<serde_json::Value> {
    use Signal::*;
    vec![
        ImperativeOverride,
        CredentialReference,
        PrivilegedPath,
        ExfiltrationMechanism,
        StealthLanguage,
        SessionPersistence,
        CrossToolContamination,
        FakePrerequisite,
        ArgumentInterception,
        HtmlInjectionTag,
        ConditionalActivation,
        MessageHijacking,
        UnicodeObfuscation,
        EmbeddedInstruction,
    ]
    .iter()
    .map(|s| {
        json!({
            "id": signal_rule_id(s),
            "name": format!("{s:?}"),
            "shortDescription": {"text": signal_description(s)},
            "defaultConfiguration": {"level": "error"},
            "helpUri": "https://github.com/ksek87/fuzzd",
        })
    })
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fuzzer::Signal;

    fn finding(tool: &str, signal: Signal, severity: Severity) -> Finding {
        Finding {
            tool_name: tool.to_string(),
            signal,
            severity,
            matched_text: "matched snippet".to_string(),
            detail: "test detail".to_string(),
            corpus_refs: &["TPA-001"],
        }
    }

    #[test]
    fn markdown_no_findings() {
        let out = render_markdown(&[], 3);
        assert!(out.contains("No issues found in 3 tool(s)"));
    }

    #[test]
    fn markdown_with_findings() {
        let findings = vec![finding(
            "evil_tool",
            Signal::ImperativeOverride,
            Severity::High,
        )];
        let out = render_markdown(&findings, 2);
        assert!(out.contains("1 finding(s) in 2 tool(s)"));
        assert!(out.contains("evil_tool"));
        assert!(out.contains("TPA-001"));
    }

    #[test]
    fn json_structure_is_valid() {
        let findings = vec![finding(
            "tool_a",
            Signal::CredentialReference,
            Severity::Critical,
        )];
        let out = render_json(&findings, 5).unwrap();
        let val: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(val["tools_scanned"], 5);
        assert_eq!(val["findings"].as_array().unwrap().len(), 1);
        assert_eq!(val["findings"][0]["tool"], "tool_a");
        assert_eq!(val["findings"][0]["severity"], "critical");
    }

    #[test]
    fn sarif_top_level_structure() {
        let findings = vec![finding("t", Signal::HtmlInjectionTag, Severity::Critical)];
        let out = render_sarif(&findings).unwrap();
        let val: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(val["version"], "2.1.0");
        let run = &val["runs"][0];
        assert_eq!(run["tool"]["driver"]["name"], "fuzzd");
        assert_eq!(run["results"].as_array().unwrap().len(), 1);
        assert_eq!(run["results"][0]["ruleId"], "FUZZD-010");
        assert_eq!(run["results"][0]["level"], "error");
    }

    #[test]
    fn sarif_rules_covers_all_signals() {
        let rules = sarif_rules();
        assert_eq!(rules.len(), 14);
    }

    #[test]
    fn sarif_severity_mapping() {
        assert_eq!(severity_level(&Severity::Critical), "error");
        assert_eq!(severity_level(&Severity::High), "error");
        assert_eq!(severity_level(&Severity::Medium), "warning");
        assert_eq!(severity_level(&Severity::Low), "note");
        assert_eq!(severity_level(&Severity::Info), "none");
    }

    #[test]
    fn benchmark_markdown_shows_all_metrics() {
        let report = BenchmarkReport {
            tools_total: 10,
            tp: 4,
            fp: 1,
            fn_count: 2,
            tn: 3,
            precision: 0.8,
            recall: 0.667,
            f1: 0.727,
        };
        let out = render_benchmark_markdown(&report);
        assert!(out.contains("10 tools"));
        assert!(out.contains("True positives:  4"));
        assert!(out.contains("False positives: 1"));
        assert!(out.contains("False negatives: 2"));
        assert!(out.contains("True negatives:  3"));
        assert!(out.contains("Precision: 0.800"));
        assert!(out.contains("F1:        0.727"));
    }

    #[test]
    fn benchmark_json_structure() {
        let report = BenchmarkReport {
            tools_total: 5,
            tp: 2,
            fp: 0,
            fn_count: 1,
            tn: 2,
            precision: 1.0,
            recall: 0.667,
            f1: 0.8,
        };
        let out = render_benchmark_json(&report).unwrap();
        let val: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(val["tools_total"], 5);
        assert_eq!(val["tp"], 2);
        assert_eq!(val["fn"], 1);
    }

    #[test]
    fn write_findings_stdout_markdown() {
        let findings = vec![finding("t", Signal::ImperativeOverride, Severity::High)];
        assert!(write_findings(&findings, 1, &OutputFormat::Markdown, None).is_ok());
    }

    #[test]
    fn write_findings_file_json() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out.json");
        let findings = vec![finding(
            "t",
            Signal::CredentialReference,
            Severity::Critical,
        )];
        write_findings(&findings, 1, &OutputFormat::Json, Some(&path)).unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        let val: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(val["tools_scanned"], 1);
    }
}

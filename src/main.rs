use std::collections::HashSet;

use anyhow::Result;
use clap::Parser;
use tracing_subscriber::EnvFilter;

mod cli;
mod corpus;
mod fuzzer;
mod protocol;
mod reporter;
mod runner;
mod suppress;
#[cfg(test)]
mod testutil;
mod utils;

use cli::{Cli, Command, CorpusAction, TransportKind};
use corpus::{Category, Corpus, Severity};
use fuzzer::argument::ArgumentFuzzer;
use fuzzer::description::DescriptionScanner;
use fuzzer::Finding;
use protocol::mcp::ListToolsResult;
use protocol::transport::Transport;
use reporter::BenchmarkReport;
use runner::harness::Harness;
use runner::observer::Observer;
use suppress::{SuppressConfig, DEFAULT_SUPPRESS_PATH};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();

    match cli.command {
        Command::Audit(args) => match args.transport {
            TransportKind::Stdio => {
                let cmd = args.cmd.as_deref().expect("stdio transport requires --cmd");
                let transport = protocol::transport::stdio::StdioTransport::spawn(cmd).await?;
                run_audit(Harness::new(transport), &args).await?;
            }
            TransportKind::Http => {
                anyhow::bail!("HTTP transport not yet implemented — use --transport stdio");
            }
        },
        Command::Scan(args) => {
            let src = std::fs::read_to_string(&args.schema)?;
            let tools = serde_json::from_str::<ListToolsResult>(&src)
                .map(|r| r.tools)
                .or_else(|_| serde_json::from_str(&src))?;
            let suppress =
                SuppressConfig::load_or_empty(std::path::Path::new(DEFAULT_SUPPRESS_PATH))?;
            let mut findings = DescriptionScanner::scan(&tools);
            apply_suppressions(&mut findings, &suppress);
            reporter::write_findings(&findings, tools.len(), &args.output, args.out.as_deref())?;
            exit_if_blocking(&findings);
        }
        Command::Benchmark(args) => {
            let labelled: Vec<LabelledTool> = utils::read_json_file(&args.schema)?;
            let findings = DescriptionScanner::scan(labelled.iter().map(|lt| &lt.tool));
            let report = compute_benchmark(&labelled, &findings);
            reporter::write_benchmark(&report, &args.output, args.out.as_deref())?;
        }
        Command::Suppress(args) => {
            SuppressConfig::append(&args.suppress_file, &args.tool, &args.signal, &args.reason)?;
            println!(
                "suppressed {}/{} in {}",
                args.tool,
                args.signal,
                args.suppress_file.display()
            );
        }
        Command::Corpus(args) => {
            let mut corpus = Corpus::embedded();
            if let Some(dir) = &args.corpus_dir {
                let extra = Corpus::load_dir(dir)?;
                corpus.records.extend(extra.records);
            }

            match args.action {
                CorpusAction::List { category, severity } => {
                    let cat_filter = category
                        .as_deref()
                        .map(|s| s.parse::<Category>())
                        .transpose()?;
                    let sev_filter = severity
                        .as_deref()
                        .map(|s| s.parse::<Severity>())
                        .transpose()?;

                    let records: Vec<_> = corpus
                        .records
                        .iter()
                        .filter(|r| cat_filter.as_ref().is_none_or(|c| &r.category == c))
                        .filter(|r| sev_filter.as_ref().is_none_or(|s| &r.severity >= s))
                        .collect();

                    if records.is_empty() {
                        eprintln!("no records match the given filters");
                    } else {
                        println!(
                            "{:<10} {:<20} {:<10} {:<10} SUBCATEGORY",
                            "ID", "CATEGORY", "SEVERITY", "PARADIGM"
                        );
                        println!("{}", "-".repeat(72));
                        for r in records {
                            println!(
                                "{:<10} {:<20} {:<10} {:<10} {}",
                                r.id,
                                r.category.to_string(),
                                r.severity.to_string(),
                                r.paradigm.map_or("-".to_string(), |p| p.to_string()),
                                r.subcategory,
                            );
                        }
                    }
                }
                CorpusAction::Add { path } => {
                    let record = Corpus::load_file(&path)?;
                    if let Some(dir) = &args.corpus_dir {
                        let dest = dir.join(format!("{}.json", record.id));
                        std::fs::copy(&path, &dest)?;
                        println!("{}: added to {}", record.id, dest.display());
                    } else {
                        eprintln!(
                            "{}: valid — use --corpus-dir to specify where to save it",
                            record.id
                        );
                    }
                }
                CorpusAction::Validate { path } => match Corpus::load_file(&path) {
                    Ok(r) => println!("{}: ok ({})", path.display(), r.id),
                    Err(e) => {
                        eprintln!("{}: {e}", path.display());
                        std::process::exit(1);
                    }
                },
            }
        }
    }

    Ok(())
}

async fn run_audit<T: Transport>(mut harness: Harness<T>, args: &cli::AuditArgs) -> Result<()> {
    harness.initialize().await?;
    let tools = harness.enumerate_tools().await?;

    // Deduplicate so the same module flag passed twice doesn't double-scan.
    let unique_attacks: HashSet<&cli::AttackModule> = args.attacks.iter().collect();
    let mut findings = Vec::new();

    // Static analysis — no live connection needed after enumeration.
    if unique_attacks.contains(&cli::AttackModule::ToolPoisoning) {
        findings.extend(DescriptionScanner::scan(&tools));
    }

    // Dynamic analysis — argument boundary fuzzer with response scanning.
    let mut observer = Observer::new(harness);
    if unique_attacks.contains(&cli::AttackModule::Argument) {
        for tool in &tools {
            for case in ArgumentFuzzer::fuzz(&tool.input_schema) {
                if let Err(e) = observer.call_tool(&tool.name, Some(case.args)).await {
                    eprintln!("warn: fuzz {}/{}: {e}", tool.name, case.label);
                }
            }
        }
        findings.extend(observer.all_findings().cloned());
    }
    observer.close().await?;

    for module in &unique_attacks {
        match module {
            cli::AttackModule::ToolPoisoning | cli::AttackModule::Argument => {}
            other => eprintln!("warning: attack module '{other}' not yet implemented — skipping"),
        }
    }

    let suppress = SuppressConfig::load_or_empty(std::path::Path::new(DEFAULT_SUPPRESS_PATH))?;
    apply_suppressions(&mut findings, &suppress);

    reporter::write_findings(&findings, tools.len(), &args.output, args.out.as_deref())?;
    exit_if_blocking(&findings);
    Ok(())
}

/// Mark findings as suppressed and warn about stale suppress entries.
fn apply_suppressions(findings: &mut [Finding], config: &SuppressConfig) {
    for f in findings.iter_mut() {
        if config.is_suppressed(f) {
            f.suppressed = true;
        }
    }
    for entry in config.stale_entries(findings) {
        eprintln!(
            "warn: suppress entry {}/{} has no matching finding — the tool may be fixed",
            entry.tool, entry.signal
        );
    }
}

fn exit_if_blocking(findings: &[Finding]) {
    if findings
        .iter()
        .any(|f| !f.suppressed && f.severity >= Severity::High)
    {
        std::process::exit(1);
    }
}

fn compute_benchmark(labelled: &[LabelledTool], findings: &[Finding]) -> BenchmarkReport {
    let detected: HashSet<&str> = findings.iter().map(|f| f.tool_name.as_str()).collect();
    let mut tp = 0usize;
    let mut fp = 0usize;
    let mut fn_count = 0usize;
    let mut tn = 0usize;
    for lt in labelled {
        match (lt.meta.is_attack, detected.contains(lt.tool.name.as_str())) {
            (true, true) => tp += 1,
            (false, true) => fp += 1,
            (true, false) => fn_count += 1,
            (false, false) => tn += 1,
        }
    }
    let precision = if tp + fp == 0 {
        0.0
    } else {
        tp as f64 / (tp + fp) as f64
    };
    let recall = if tp + fn_count == 0 {
        0.0
    } else {
        tp as f64 / (tp + fn_count) as f64
    };
    let f1 = if precision + recall == 0.0 {
        0.0
    } else {
        2.0 * precision * recall / (precision + recall)
    };
    BenchmarkReport {
        tools_total: labelled.len(),
        tp,
        fp,
        fn_count,
        tn,
        precision,
        recall,
        f1,
    }
}

/// Tool definition extended with an optional `_meta` label for benchmark mode.
#[derive(serde::Deserialize)]
struct LabelledTool {
    #[serde(flatten)]
    tool: protocol::mcp::ToolDefinition,
    #[serde(default, rename = "_meta")]
    meta: ToolMeta,
}

#[derive(Default, serde::Deserialize)]
struct ToolMeta {
    #[serde(default)]
    is_attack: bool,
}

#[cfg(test)]
mod benchmark_fixture_tests {
    use super::*;

    fn load_fixture(path: &str) -> Vec<LabelledTool> {
        utils::read_json_file(std::path::Path::new(path))
            .unwrap_or_else(|e| panic!("failed to parse {path}: {e}"))
    }

    #[test]
    fn representative_fixture_parses_and_has_attack_labels() {
        let tools = load_fixture("bench/mcptox_representative.json");
        assert!(!tools.is_empty(), "fixture must not be empty");
        assert!(
            tools.iter().any(|t| t.meta.is_attack),
            "fixture must contain at least one is_attack=true entry"
        );
    }

    #[test]
    fn clean_fixture_parses_and_has_no_attack_labels() {
        let tools = load_fixture("bench/clean_tools.json");
        assert!(!tools.is_empty(), "fixture must not be empty");
        assert!(
            tools.iter().all(|t| !t.meta.is_attack),
            "clean fixture must have no is_attack=true entries"
        );
    }

    #[test]
    fn representative_fixture_achieves_full_recall() {
        let tools = load_fixture("bench/mcptox_representative.json");
        let findings =
            fuzzer::description::DescriptionScanner::scan(tools.iter().map(|lt| &lt.tool));
        let report = compute_benchmark(&tools, &findings);
        assert_eq!(
            report.fn_count, 0,
            "no attack tool should be missed (recall must be 1.0)"
        );
        assert!(
            report.recall >= 1.0,
            "recall must be 1.0, got {}",
            report.recall
        );
    }

    #[test]
    fn actual_fixture_parses_and_has_attack_labels() {
        let tools = load_fixture("bench/mcptox_actual.json");
        assert!(!tools.is_empty(), "fixture must not be empty");
        assert!(
            tools.iter().all(|t| t.meta.is_attack),
            "all tools in mcptox_actual must have is_attack=true"
        );
    }

    #[test]
    fn combined_benchmark_precision_within_bounds() {
        // Locks in the known false-positive count so regressions don't go unnoticed.
        // If precision drops significantly, a new pattern is causing false positives
        // on clean tools and needs investigation.
        let attacks = load_fixture("bench/mcptox_representative.json");
        let clean = load_fixture("bench/clean_tools.json");
        let combined: Vec<_> = attacks.into_iter().chain(clean).collect();
        let findings =
            fuzzer::description::DescriptionScanner::scan(combined.iter().map(|lt| &lt.tool));
        let report = compute_benchmark(&combined, &findings);
        assert_eq!(report.fn_count, 0, "recall must remain 1.0");
        assert!(
            report.precision >= 0.90,
            "precision dropped below 0.90 — check for new false positives, got {:.3}",
            report.precision
        );
    }
}

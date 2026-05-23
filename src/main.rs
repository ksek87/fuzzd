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
#[cfg(test)]
mod testutil;
mod utils;

use cli::{Cli, Command, CorpusAction, TransportKind};
use corpus::{Category, Corpus, Severity};
use fuzzer::description::DescriptionScanner;
use protocol::mcp::ListToolsResult;
use protocol::transport::Transport;
use runner::harness::Harness;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();

    match cli.command {
        Command::Audit(args) => match args.transport {
            TransportKind::Stdio => {
                let cmd = args.cmd.as_deref().unwrap();
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
            let findings = DescriptionScanner::scan(&tools);
            reporter::write_findings(&findings, tools.len(), &args.output, args.out.as_deref())?;
            if findings.iter().any(|f| f.severity >= Severity::High) {
                std::process::exit(1);
            }
        }
        Command::Benchmark(args) => {
            let src = std::fs::read_to_string(&args.schema)?;
            let labelled: Vec<LabelledTool> = serde_json::from_str(&src)?;
            let tools: Vec<_> = labelled.iter().map(|lt| lt.tool.clone()).collect();
            let findings = DescriptionScanner::scan(&tools);
            let detected: HashSet<&str> = findings.iter().map(|f| f.tool_name.as_str()).collect();
            let mut tp = 0usize;
            let mut fp = 0usize;
            let mut fn_count = 0usize;
            let mut tn = 0usize;
            for lt in &labelled {
                let name = lt.tool.name.as_str();
                match (lt.meta.is_attack, detected.contains(name)) {
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
            reporter::write_benchmark(
                &reporter::BenchmarkReport {
                    tools_total: labelled.len(),
                    tp,
                    fp,
                    fn_count,
                    tn,
                    precision,
                    recall,
                    f1,
                },
                &args.output,
                args.out.as_deref(),
            )?;
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
    harness.close().await?;

    let mut findings = Vec::new();
    for module in &args.attacks {
        match module {
            cli::AttackModule::ToolPoisoning => {
                findings.extend(DescriptionScanner::scan(&tools));
            }
            other => {
                eprintln!("warning: attack module '{other}' not yet implemented — skipping");
            }
        }
    }

    reporter::write_findings(&findings, tools.len(), &args.output, args.out.as_deref())?;
    if findings.iter().any(|f| f.severity >= Severity::High) {
        std::process::exit(1);
    }
    Ok(())
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

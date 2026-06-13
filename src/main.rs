use std::collections::HashSet;
use std::path::Path;

use anyhow::Result;
use clap::Parser;
use tracing_subscriber::EnvFilter;

mod analyzer;
mod cli;
mod config;
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
        Command::Audit(args) => {
            if let Some(ref config_arg) = args.from_config.clone() {
                run_config_audit(&args, config_arg).await?;
            } else {
                match args.transport {
                    TransportKind::Stdio => {
                        let cmd = args
                            .cmd
                            .as_deref()
                            .ok_or_else(|| anyhow::anyhow!("stdio transport requires --cmd"))?;
                        let transport =
                            protocol::transport::stdio::StdioTransport::spawn(cmd).await?;
                        run_audit(Harness::new(transport), &args, Some(cmd)).await?;
                    }
                    TransportKind::Http => {
                        let url = args
                            .url
                            .as_deref()
                            .ok_or_else(|| anyhow::anyhow!("http transport requires --url"))?;
                        let transport =
                            protocol::transport::http::HttpTransport::connect(url).await?;
                        run_audit(Harness::new(transport), &args, None).await?;
                    }
                }
            }
        }
        Command::Scan(args) => {
            let src = std::fs::read_to_string(&args.schema)?;
            let tools = serde_json::from_str::<ListToolsResult>(&src)
                .map(|r| r.tools)
                .or_else(|_| serde_json::from_str(&src))?;
            let suppress = SuppressConfig::load_or_empty(Path::new(DEFAULT_SUPPRESS_PATH))?;
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

/// Collect all findings for a single server session without applying suppressions
/// or writing a report. `spawn_cmd` is the command string to re-spawn the server
/// for protocol/chain fuzzing (None = skip those modules).
async fn collect_audit_findings<T: Transport>(
    mut harness: Harness<T>,
    args: &cli::AuditArgs,
    spawn_cmd: Option<&str>,
) -> Result<(Vec<Finding>, usize)> {
    let unique_attacks: HashSet<&cli::AttackModule> = args.attacks.iter().collect();
    let mut findings = Vec::new();
    let mut tools_scanned = 0usize;

    // Protocol fuzzing re-spawns the server fresh per case (lifecycle probes need
    // a clean session) and is independent of the shared session — it must run even
    // against a server that never completes the initialize handshake, since probing
    // exactly that is its job. stdio only.
    if unique_attacks.contains(&cli::AttackModule::Protocol) {
        match spawn_cmd {
            Some(cmd) => findings.extend(fuzzer::protocol::fuzz_stdio(cmd).await?),
            None => {
                eprintln!("warning: protocol fuzzing requires a spawnable --cmd (stdio) — skipping")
            }
        }
    }

    // Chain fuzzing executes scripted multi-step sequences in their own fresh
    // stdio sessions (independent of the shared session, like protocol). It needs
    // both a spawnable --cmd and chain scripts via --chains.
    if unique_attacks.contains(&cli::AttackModule::Chain) {
        match (args.chains.as_deref(), spawn_cmd) {
            (Some(path), Some(cmd)) => {
                let chains = fuzzer::chain::load_chains(path)?;
                if chains.is_empty() {
                    eprintln!(
                        "warning: no chain scripts found at {} — skipping chain module",
                        path.display()
                    );
                } else {
                    findings.extend(fuzzer::chain::fuzz_stdio(cmd, &chains).await?);
                }
            }
            (None, _) => {
                eprintln!("warning: chain fuzzing requires --chains <PATH> — skipping")
            }
            (Some(_), None) => {
                eprintln!("warning: chain fuzzing requires a spawnable --cmd (stdio) — skipping")
            }
        }
    }

    // Peer-injection fuzzing: inject each TPA corpus record as a mock peer tool
    // and detect it via static scan + sequence diff.
    if unique_attacks.contains(&cli::AttackModule::Peer) {
        let corpus = corpus::Corpus::embedded();
        findings.extend(fuzzer::peer::fuzz_peer_stdio(&corpus.records).await?);
    }

    // The static (tool-poisoning) and dynamic (argument) modules need the live
    // tool list, so they require a successful handshake. Only pay for it when one
    // of them is requested; otherwise close the unused transport.
    let needs_tools = unique_attacks.contains(&cli::AttackModule::ToolPoisoning)
        || unique_attacks.contains(&cli::AttackModule::Argument);
    if needs_tools {
        harness.initialize().await?;
        let tools = harness.enumerate_tools().await?;
        tools_scanned = tools.len();

        if unique_attacks.contains(&cli::AttackModule::ToolPoisoning) {
            findings.extend(DescriptionScanner::scan(&tools));
            // Also scan prompts and resources — optional MCP surfaces.
            // Gracefully skip if the server doesn't implement these endpoints.
            if let Ok(prompts) = harness.enumerate_prompts().await {
                findings.extend(DescriptionScanner::scan_surface(
                    prompts
                        .iter()
                        .map(|p| (p.name.as_str(), p.description.as_deref())),
                ));
            }
            if let Ok(resources) = harness.enumerate_resources().await {
                findings.extend(DescriptionScanner::scan_surface(
                    resources
                        .iter()
                        .map(|r| (r.name.as_str(), r.description.as_deref())),
                ));
            }
            // Tool pinning: re-fetch tools/list and flag any definition that changed.
            // A changing definition between calls is the rug-pull / conditional-activation
            // pattern (FUZZD-011) — the server shows a benign tool until certain conditions
            // are met, then swaps to a malicious one.
            if let Ok(changed) = harness.recheck_tool_integrity().await {
                for name in changed {
                    findings.push(fuzzer::Finding {
                        tool_name: name,
                        signal: fuzzer::Signal::ConditionalActivation,
                        severity: Severity::Critical,
                        matched_text: "tool definition changed between tools/list calls"
                            .to_string(),
                        detail: "Tool definition mutated between two tools/list calls in the \
                            same session — rug-pull / conditional-activation attack (FUZZD-011)"
                            .to_string(),
                        corpus_refs: &[],
                        suppressed: false,
                    });
                }
            }
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
    } else {
        harness.close().await?;
    }

    if unique_attacks.contains(&cli::AttackModule::Escape) {
        findings.extend(fuzzer::escape::fuzz_escape().await?);
    }

    Ok((findings, tools_scanned))
}

async fn run_audit<T: Transport>(
    harness: Harness<T>,
    args: &cli::AuditArgs,
    spawn_cmd: Option<&str>,
) -> Result<()> {
    let (mut findings, tools_scanned) = collect_audit_findings(harness, args, spawn_cmd).await?;
    let suppress = SuppressConfig::load_or_empty(Path::new(DEFAULT_SUPPRESS_PATH))?;
    apply_suppressions(&mut findings, &suppress);
    reporter::write_findings(&findings, tools_scanned, &args.output, args.out.as_deref())?;
    exit_if_blocking(&findings);
    Ok(())
}

/// Audit every MCP server listed in a Claude Desktop / Cline config file.
/// Each server is audited independently and findings are tagged `server/tool_name`.
async fn run_config_audit(args: &cli::AuditArgs, config_arg: &str) -> Result<()> {
    let desktop_config = if config_arg == "auto" {
        match config::auto_detect() {
            Some((path, cfg)) => {
                eprintln!("fuzzd: using config at {}", path.display());
                cfg
            }
            None => anyhow::bail!(
                "no Claude Desktop config found at standard paths — use --from-config <PATH>"
            ),
        }
    } else {
        config::load_config(Path::new(config_arg))?
    };

    if desktop_config.mcp_servers.is_empty() {
        eprintln!("fuzzd: no MCP servers found in config");
        return Ok(());
    }

    let suppress = SuppressConfig::load_or_empty(Path::new(DEFAULT_SUPPRESS_PATH))?;
    let mut all_findings = Vec::new();
    let mut total_tools = 0usize;
    let mut server_summaries: Vec<(String, usize)> = Vec::new();

    let mut servers: Vec<_> = desktop_config.mcp_servers.into_iter().collect();
    servers.sort_by(|a, b| a.0.cmp(&b.0));

    for (server_name, server) in servers {
        eprintln!("fuzzd: auditing '{server_name}'");
        let spawn_cmd = server.spawn_cmd();
        let transport = match protocol::transport::stdio::StdioTransport::spawn_with_args(
            &server.command,
            &server.args,
            &server.env,
        )
        .await
        {
            Ok(t) => t,
            Err(e) => {
                eprintln!("fuzzd: skipping '{server_name}': {e}");
                server_summaries.push((server_name, 0));
                continue;
            }
        };

        match collect_audit_findings(Harness::new(transport), args, Some(&spawn_cmd)).await {
            Ok((mut findings, tools_scanned)) => {
                total_tools += tools_scanned;
                for f in &mut findings {
                    f.tool_name = format!("{server_name}/{}", f.tool_name);
                }
                let n = findings.len();
                server_summaries.push((server_name, n));
                all_findings.extend(findings);
            }
            Err(e) => {
                eprintln!("fuzzd: audit of '{server_name}' failed: {e}");
                server_summaries.push((server_name, 0));
            }
        }
    }

    apply_suppressions(&mut all_findings, &suppress);

    if server_summaries.len() > 1 {
        eprintln!("\nper-server findings:");
        for (name, n) in &server_summaries {
            eprintln!("  {name}: {n}");
        }
        eprintln!();
    }

    reporter::write_findings(
        &all_findings,
        total_tools,
        &args.output,
        args.out.as_deref(),
    )?;
    exit_if_blocking(&all_findings);
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

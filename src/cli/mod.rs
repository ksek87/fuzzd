use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "fuzzd",
    version,
    about = "Adversarial fuzzer for MCP servers and agentic tool surfaces",
    long_about = None
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Connect to a live MCP server and run fuzzing modules.
    Audit(AuditArgs),

    /// Statically analyze tool descriptions without a live server.
    Scan(ScanArgs),

    /// Measure detection precision/recall against labelled fixtures.
    Benchmark(BenchmarkArgs),

    /// Manage the attack corpus.
    Corpus(CorpusArgs),

    /// Suppress a known finding so it no longer blocks CI.
    Suppress(SuppressArgs),
}

// ── audit ──────────────────────────────────────────────────────────────────

#[derive(Debug, clap::Args)]
pub struct AuditArgs {
    /// Transport to use.
    #[arg(long, default_value = "stdio")]
    pub transport: TransportKind,

    /// Command to spawn (stdio transport only).
    #[arg(long, required_if_eq("transport", "stdio"))]
    pub cmd: Option<String>,

    /// Server URL (http transport only).
    #[arg(long, required_if_eq("transport", "http"))]
    pub url: Option<String>,

    /// Attack modules to run (comma-separated).
    /// Available: tool_poisoning, argument, protocol, chain, escape
    #[arg(long, value_delimiter = ',', default_values_t = AttackModule::all())]
    pub attacks: Vec<AttackModule>,

    /// Output format.
    #[arg(long, default_value = "markdown")]
    pub output: OutputFormat,

    /// Write output to file (default: stdout).
    #[arg(long)]
    pub out: Option<PathBuf>,
}

// ── scan ───────────────────────────────────────────────────────────────────

#[derive(Debug, clap::Args)]
pub struct ScanArgs {
    /// Path to a JSON file containing tool definitions (MCP tools/list format).
    #[arg(long)]
    pub schema: PathBuf,

    /// Output format.
    #[arg(long, default_value = "markdown")]
    pub output: OutputFormat,

    /// Write output to file (default: stdout).
    #[arg(long)]
    pub out: Option<PathBuf>,
}

// ── benchmark ──────────────────────────────────────────────────────────────

#[derive(Debug, clap::Args)]
pub struct BenchmarkArgs {
    /// Path to a labelled fixture JSON file (tool definitions with optional _meta.is_attack field).
    #[arg(long)]
    pub schema: PathBuf,

    /// Output format.
    #[arg(long, default_value = "markdown")]
    pub output: OutputFormat,

    /// Write output to file (default: stdout).
    #[arg(long)]
    pub out: Option<PathBuf>,
}

// ── corpus ─────────────────────────────────────────────────────────────────

#[derive(Debug, clap::Args)]
pub struct CorpusArgs {
    #[command(subcommand)]
    pub action: CorpusAction,

    /// Path to an additional corpus directory to load.
    #[arg(long)]
    pub corpus_dir: Option<PathBuf>,
}

#[derive(Debug, Subcommand)]
pub enum CorpusAction {
    /// List attack records.
    List {
        /// Filter by category (e.g. tool_poisoning).
        #[arg(long)]
        category: Option<String>,

        /// Filter by severity.
        #[arg(long)]
        severity: Option<String>,
    },
    /// Add a new attack record to the corpus.
    Add {
        /// Path to the JSON record file.
        path: PathBuf,
    },
    /// Validate an attack record without adding it.
    Validate {
        /// Path to the JSON record file.
        path: PathBuf,
    },
}

// ── suppress ───────────────────────────────────────────────────────────────

#[derive(Debug, clap::Args)]
pub struct SuppressArgs {
    /// Tool name to suppress (must match the finding's tool name exactly).
    pub tool: String,

    /// Signal to suppress (e.g. message_hijacking, privileged_path).
    pub signal: String,

    /// Human-readable reason recorded in .fuzzd/suppress.toml.
    #[arg(long)]
    pub reason: String,

    /// Path to the suppress file (default: .fuzzd/suppress.toml).
    #[arg(long, default_value = ".fuzzd/suppress.toml")]
    pub suppress_file: std::path::PathBuf,
}

// ── value enums ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, ValueEnum)]
#[value(rename_all = "lowercase")]
pub enum TransportKind {
    Stdio,
    Http,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, ValueEnum)]
#[value(rename_all = "snake_case")]
pub enum AttackModule {
    ToolPoisoning,
    Argument,
    Protocol,
    Chain,
    Escape,
}

impl AttackModule {
    pub fn all() -> Vec<Self> {
        vec![
            Self::ToolPoisoning,
            Self::Argument,
            Self::Protocol,
            Self::Chain,
            Self::Escape,
        ]
    }
}

impl std::fmt::Display for AttackModule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ToolPoisoning => write!(f, "tool_poisoning"),
            Self::Argument => write!(f, "argument"),
            Self::Protocol => write!(f, "protocol"),
            Self::Chain => write!(f, "chain"),
            Self::Escape => write!(f, "escape"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, ValueEnum)]
#[value(rename_all = "lowercase")]
pub enum OutputFormat {
    Json,
    Sarif,
    Markdown,
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_debug_assert() {
        // Verifies clap configuration is valid at compile time equivalent
        Cli::command().debug_assert();
    }

    #[test]
    fn audit_stdio_parses() {
        let cli = Cli::try_parse_from([
            "fuzzd",
            "audit",
            "--transport",
            "stdio",
            "--cmd",
            "node server.js",
        ])
        .unwrap();
        match cli.command {
            Command::Audit(args) => {
                assert_eq!(args.transport, TransportKind::Stdio);
                assert_eq!(args.cmd.as_deref(), Some("node server.js"));
            }
            _ => panic!("expected audit"),
        }
    }

    #[test]
    fn audit_http_parses() {
        let cli = Cli::try_parse_from([
            "fuzzd",
            "audit",
            "--transport",
            "http",
            "--url",
            "http://localhost:8000",
        ])
        .unwrap();
        match cli.command {
            Command::Audit(args) => {
                assert_eq!(args.transport, TransportKind::Http);
                assert_eq!(args.url.as_deref(), Some("http://localhost:8000"));
            }
            _ => panic!("expected audit"),
        }
    }

    #[test]
    fn scan_parses() {
        let cli = Cli::try_parse_from(["fuzzd", "scan", "--schema", "/tmp/tools.json"]).unwrap();
        match cli.command {
            Command::Scan(args) => {
                assert_eq!(args.schema, PathBuf::from("/tmp/tools.json"));
            }
            _ => panic!("expected scan"),
        }
    }

    #[test]
    fn corpus_list_parses() {
        let cli = Cli::try_parse_from(["fuzzd", "corpus", "list", "--category", "tool_poisoning"])
            .unwrap();
        match cli.command {
            Command::Corpus(args) => match args.action {
                CorpusAction::List { category, .. } => {
                    assert_eq!(category.as_deref(), Some("tool_poisoning"));
                }
                _ => panic!("expected list"),
            },
            _ => panic!("expected corpus"),
        }
    }

    #[test]
    fn corpus_validate_parses() {
        let cli = Cli::try_parse_from(["fuzzd", "corpus", "validate", "/tmp/attack.json"]).unwrap();
        match cli.command {
            Command::Corpus(args) => match args.action {
                CorpusAction::Validate { path } => {
                    assert_eq!(path, PathBuf::from("/tmp/attack.json"));
                }
                _ => panic!("expected validate"),
            },
            _ => panic!("expected corpus"),
        }
    }

    #[test]
    fn attacks_flag_parses_comma_separated() {
        let cli = Cli::try_parse_from([
            "fuzzd",
            "audit",
            "--transport",
            "stdio",
            "--cmd",
            "node server.js",
            "--attacks",
            "tool_poisoning,argument",
        ])
        .unwrap();
        match cli.command {
            Command::Audit(args) => {
                assert_eq!(
                    args.attacks,
                    vec![AttackModule::ToolPoisoning, AttackModule::Argument]
                );
            }
            _ => panic!("expected audit"),
        }
    }

    #[test]
    fn output_format_sarif_parses() {
        let cli = Cli::try_parse_from([
            "fuzzd",
            "audit",
            "--transport",
            "stdio",
            "--cmd",
            "server",
            "--output",
            "sarif",
        ])
        .unwrap();
        match cli.command {
            Command::Audit(args) => assert_eq!(args.output, OutputFormat::Sarif),
            _ => panic!(),
        }
    }

    #[test]
    fn attack_module_all_has_five_entries() {
        assert_eq!(AttackModule::all().len(), 5);
    }

    #[test]
    fn benchmark_parses() {
        let cli =
            Cli::try_parse_from(["fuzzd", "benchmark", "--schema", "/tmp/fixtures.json"]).unwrap();
        match cli.command {
            Command::Benchmark(args) => {
                assert_eq!(args.schema, PathBuf::from("/tmp/fixtures.json"));
                assert_eq!(args.output, OutputFormat::Markdown);
            }
            _ => panic!("expected benchmark"),
        }
    }

    #[test]
    fn benchmark_sarif_output_parses() {
        let cli = Cli::try_parse_from([
            "fuzzd",
            "benchmark",
            "--schema",
            "/tmp/fixtures.json",
            "--output",
            "sarif",
        ])
        .unwrap();
        match cli.command {
            Command::Benchmark(args) => assert_eq!(args.output, OutputFormat::Sarif),
            _ => panic!("expected benchmark"),
        }
    }
}

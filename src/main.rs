use anyhow::Result;
use clap::Parser;
use tracing_subscriber::EnvFilter;

mod analyzer;
mod cli;
mod corpus;
mod fuzzer;
mod protocol;
mod reporter;
mod runner;

use cli::{Cli, Command, CorpusAction};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();

    match cli.command {
        Command::Audit(args) => {
            eprintln!(
                "audit: transport={:?} attacks={:?}",
                args.transport, args.attacks
            );
            eprintln!("(fuzzer modules not yet implemented — coming in v0.3+)");
        }
        Command::Scan(args) => {
            eprintln!("scan: schema={}", args.schema.display());
            eprintln!("(description scanner not yet implemented — coming in v0.3)");
        }
        Command::Corpus(args) => match args.action {
            CorpusAction::List { category, severity } => {
                eprintln!("corpus list: category={category:?} severity={severity:?}");
                eprintln!("(corpus loader not yet implemented — coming in v0.2)");
            }
            CorpusAction::Add { path } => {
                eprintln!("corpus add: {}", path.display());
            }
            CorpusAction::Validate { path } => {
                eprintln!("corpus validate: {}", path.display());
            }
        },
    }

    Ok(())
}

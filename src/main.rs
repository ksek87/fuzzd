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
#[cfg(test)]
mod testutil;
mod utils;

use cli::{Cli, Command, CorpusAction};
use corpus::{Category, Corpus, Severity};

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

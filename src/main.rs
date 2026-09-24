#![forbid(unsafe_code)]

use std::fs::File;
use std::io::{self, Read};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, ValueEnum};
use lease_lint::{Report, audit};

#[derive(Debug, Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    /// JSONL event file, or '-' to read from standard input.
    #[arg(value_name = "EVENTS.jsonl", default_value = "-")]
    input: PathBuf,

    /// Report representation.
    #[arg(long, value_enum, default_value_t = OutputFormat::Human)]
    format: OutputFormat,

    /// Explicit clock-skew grace added to lease deadlines.
    #[arg(long, default_value_t = 0)]
    grace_ms: u64,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum OutputFormat {
    Human,
    Json,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(&cli) {
        Ok(report) => {
            match cli.format {
                OutputFormat::Human => print_human(&report),
                OutputFormat::Json => {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&report)
                            .expect("report serialization cannot fail")
                    );
                }
            }
            if report.is_clean() {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(2)
            }
        }
        Err(error) => {
            eprintln!("lease-lint: error: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: &Cli) -> Result<Report, Box<dyn std::error::Error>> {
    if cli.input.as_os_str() == "-" {
        let stdin = io::stdin();
        return Ok(audit(stdin.lock(), cli.grace_ms)?);
    }

    let mut file = File::open(&cli.input).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("could not open {}: {error}", cli.input.display()),
        )
    })?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;
    Ok(audit(buffer.as_slice(), cli.grace_ms)?)
}

fn print_human(report: &Report) {
    if report.is_clean() {
        println!(
            "clean: {} events across {} resources",
            report.events_read, report.resources_seen
        );
        return;
    }

    println!(
        "{} violations: {} events across {} resources",
        report.violations.len(),
        report.events_read,
        report.resources_seen
    );
    for finding in &report.violations {
        println!(
            "line {} seq {} resource {:?} [{}] {}",
            finding.line, finding.seq, finding.resource, finding.code, finding.message
        );
    }
}

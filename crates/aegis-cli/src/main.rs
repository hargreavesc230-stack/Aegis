#![deny(warnings)]
#![deny(clippy::all)]

use std::fs::File;
use std::path::Path;
use std::path::PathBuf;

use aegis_format::{read_header, ContainerHeader, FormatError, HEADER_LEN};
use clap::{Parser, Subcommand};
use thiserror::Error;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

const EXIT_SUCCESS: i32 = 0;
const EXIT_CLI: i32 = 2;
const EXIT_FORMAT: i32 = 3;
const EXIT_IO: i32 = 4;
const EXIT_CRYPTO: i32 = 5;

#[derive(Parser, Debug)]
#[command(name = "aegis", version, about = "Aegis secure container tools")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Inspect a container header
    Inspect { path: PathBuf },
    /// Encrypt a payload into a new container (stub)
    Enc { input: PathBuf, output: PathBuf },
    /// Decrypt a container payload (stub)
    Dec { input: PathBuf, output: PathBuf },
}

#[derive(Debug, Error)]
enum CliError {
    #[error("format error: {0}")]
    Format(#[from] FormatError),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Not implemented yet")]
    NotImplemented,
}

fn main() {
    let exit_code = run();
    std::process::exit(exit_code);
}

fn run() -> i32 {
    init_tracing();

    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(err) => {
            let _ = err.print();
            return EXIT_CLI;
        }
    };

    let result = match cli.command {
        Commands::Inspect { path } => cmd_inspect(&path),
        Commands::Enc { input, output } => cmd_enc(&input, &output),
        Commands::Dec { input, output } => cmd_dec(&input, &output),
    };

    match result {
        Ok(()) => EXIT_SUCCESS,
        Err(err) => {
            report_error(&err);
            map_exit_code(&err)
        }
    }
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .finish();
    let _ = tracing::subscriber::set_global_default(subscriber);
}

fn report_error(err: &CliError) {
    error!(error = %err, "command failed");
    eprintln!("error: {err}");
}

fn map_exit_code(err: &CliError) -> i32 {
    match err {
        CliError::Format(_) => EXIT_FORMAT,
        CliError::Io(_) => EXIT_IO,
        CliError::NotImplemented => EXIT_CRYPTO,
    }
}

fn cmd_inspect(path: &Path) -> Result<(), CliError> {
    info!(path = %path.display(), "reading container header");

    let mut file = File::open(path)?;
    let header = read_header(&mut file)?;

    print_header(path, &header);
    Ok(())
}

fn cmd_enc(_input: &Path, _output: &Path) -> Result<(), CliError> {
    Err(CliError::NotImplemented)
}

fn cmd_dec(_input: &Path, _output: &Path) -> Result<(), CliError> {
    Err(CliError::NotImplemented)
}

fn print_header(path: &Path, header: &ContainerHeader) {
    println!("Aegis container header");
    println!("  Path: {}", path.display());
    println!("  Version: {:?}", header.version);
    println!("  Header length: {} bytes", HEADER_LEN);
    println!("  Flags: 0x{flags:08X}", flags = header.flags);
}

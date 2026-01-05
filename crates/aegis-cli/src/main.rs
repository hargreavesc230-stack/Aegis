#![deny(warnings)]
#![deny(clippy::all)]

use std::fs::File;
use std::path::Path;
use std::path::PathBuf;

use aegis_format::{
    extract_data_chunk, read_container_with_status, write_container, ChunkType, FormatError,
    ParsedContainer, WriteChunkSource,
};
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
    /// Inspect a container header and checksum
    Inspect { path: PathBuf },
    /// Pack a container from input data
    Pack {
        input: PathBuf,
        output: PathBuf,
        #[arg(long)]
        metadata: Option<PathBuf>,
    },
    /// Unpack the data chunk from a container
    Unpack { input: PathBuf, output: PathBuf },
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
        Commands::Pack {
            input,
            output,
            metadata,
        } => cmd_pack(&input, &output, metadata.as_deref()),
        Commands::Unpack { input, output } => cmd_unpack(&input, &output),
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
        CliError::Format(FormatError::Io(_)) => EXIT_IO,
        CliError::Io(_) => EXIT_IO,
        CliError::Format(_) => EXIT_FORMAT,
        CliError::NotImplemented => EXIT_CRYPTO,
    }
}

fn cmd_inspect(path: &Path) -> Result<(), CliError> {
    info!(path = %path.display(), "reading container");

    let mut file = File::open(path)?;
    let parsed = read_container_with_status(&mut file)?;

    print_container(path, &parsed);
    Ok(())
}

fn cmd_pack(input: &Path, output: &Path, metadata: Option<&Path>) -> Result<(), CliError> {
    info!(
        input = %input.display(),
        output = %output.display(),
        "packing container"
    );

    let input_len = std::fs::metadata(input)?.len();
    let input_file = File::open(input)?;

    let mut chunks = Vec::new();
    chunks.push(WriteChunkSource {
        chunk_id: 1,
        chunk_type: ChunkType::Data,
        flags: 0,
        length: input_len,
        reader: Box::new(input_file),
    });

    if let Some(meta_path) = metadata {
        let meta_len = std::fs::metadata(meta_path)?.len();
        let meta_file = File::open(meta_path)?;
        chunks.push(WriteChunkSource {
            chunk_id: 2,
            chunk_type: ChunkType::Metadata,
            flags: 0,
            length: meta_len,
            reader: Box::new(meta_file),
        });
    }

    let mut output_file = File::create(output)?;
    let _written = write_container(&mut output_file, &mut chunks)?;

    Ok(())
}

fn cmd_unpack(input: &Path, output: &Path) -> Result<(), CliError> {
    info!(
        input = %input.display(),
        output = %output.display(),
        "unpacking container"
    );

    let mut input_file = File::open(input)?;
    let mut output_file = File::create(output)?;

    let _parsed = extract_data_chunk(&mut input_file, &mut output_file)?;

    Ok(())
}

fn cmd_enc(_input: &Path, _output: &Path) -> Result<(), CliError> {
    Err(CliError::NotImplemented)
}

fn cmd_dec(_input: &Path, _output: &Path) -> Result<(), CliError> {
    Err(CliError::NotImplemented)
}

fn print_container(path: &Path, parsed: &ParsedContainer) {
    println!("Aegis container");
    println!("  Path: {}", path.display());
    println!("  Version: {}", parsed.header.version);
    println!("  Header length: {} bytes", parsed.header.header_len);
    println!("  Flags: 0x{flags:08X}", flags = parsed.header.flags);
    println!("  Chunk count: {}", parsed.header.chunk_count);
    println!(
        "  Chunk table offset: {} bytes",
        parsed.header.chunk_table_offset
    );
    println!("  Footer offset: {} bytes", parsed.header.footer_offset);
    println!("Chunks:");

    for chunk in &parsed.chunks {
        println!(
            "  - id: {} type: {:?} flags: 0x{:04X} offset: {} length: {}",
            chunk.chunk_id, chunk.chunk_type, chunk.flags, chunk.offset, chunk.length
        );
    }

    println!("Checksum:");
    println!("  Type: {:?}", parsed.footer.checksum_type);
    println!(
        "  Expected: 0x{expected:08X}",
        expected = parsed.footer.checksum
    );
    println!(
        "  Computed: 0x{computed:08X}",
        computed = parsed.computed_checksum
    );
    println!(
        "  Status: {}",
        if parsed.checksum_valid { "OK" } else { "FAIL" }
    );
}

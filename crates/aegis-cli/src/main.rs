#![deny(warnings)]
#![deny(clippy::all)]

use std::fs::File;
use std::path::{Path, PathBuf};

use aegis_core::crypto::keyfile::{generate_key, read_keyfile, write_keyfile};
use aegis_core::crypto::CryptoError;
use aegis_format::{
    decrypt_container, extract_data_chunk, read_container_with_status, read_header,
    write_container, write_encrypted_container, ChunkType, FormatError, ParsedContainer,
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
const KEY_LEN: usize = 32;

#[derive(Parser, Debug)]
#[command(name = "aegis", version, about = "Aegis secure container tools")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Inspect a container header and checksum status
    Inspect { path: PathBuf },
    /// Pack a container from input data (v0, no encryption)
    Pack {
        input: PathBuf,
        output: PathBuf,
        #[arg(long)]
        metadata: Option<PathBuf>,
    },
    /// Unpack the data chunk from a v0 container
    Unpack { input: PathBuf, output: PathBuf },
    /// Generate a new key file
    Keygen {
        output: PathBuf,
        #[arg(long)]
        force: bool,
    },
    /// Encrypt a payload into a new container
    Enc {
        input: PathBuf,
        output: PathBuf,
        #[arg(long)]
        key: PathBuf,
    },
    /// Decrypt a container payload
    Dec {
        input: PathBuf,
        output: PathBuf,
        #[arg(long)]
        key: PathBuf,
    },
}

#[derive(Debug, Error)]
enum CliError {
    #[error("format error: {0}")]
    Format(#[from] FormatError),
    #[error("crypto error: {0}")]
    Crypto(#[from] CryptoError),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
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
        Commands::Keygen { output, force } => cmd_keygen(&output, force),
        Commands::Enc { input, output, key } => cmd_enc(&input, &output, &key),
        Commands::Dec { input, output, key } => cmd_dec(&input, &output, &key),
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
        CliError::Format(FormatError::Crypto(_)) => EXIT_CRYPTO,
        CliError::Crypto(_) => EXIT_CRYPTO,
        CliError::Format(_) => EXIT_FORMAT,
    }
}

fn cmd_inspect(path: &Path) -> Result<(), CliError> {
    info!(path = %path.display(), "reading container");

    let mut file = File::open(path)?;
    let (header, _) = read_header(&mut file)?;

    print_header(path, &header);

    if header.version == aegis_format::ACF_VERSION_V0 {
        let mut file = File::open(path)?;
        let parsed = read_container_with_status(&mut file)?;
        print_v0_details(&parsed);
    } else if header.version == aegis_format::ACF_VERSION_V1 {
        print_v1_details(&header);
    }

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
    chunks.push(aegis_format::WriteChunkSource {
        chunk_id: 1,
        chunk_type: ChunkType::Data,
        flags: 0,
        length: input_len,
        reader: Box::new(input_file),
    });

    if let Some(meta_path) = metadata {
        let meta_len = std::fs::metadata(meta_path)?.len();
        let meta_file = File::open(meta_path)?;
        chunks.push(aegis_format::WriteChunkSource {
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

fn cmd_keygen(output: &Path, force: bool) -> Result<(), CliError> {
    info!(output = %output.display(), "generating key file");

    let key = generate_key(KEY_LEN)?;
    write_keyfile(output, key.as_slice(), force)?;

    Ok(())
}

fn cmd_enc(input: &Path, output: &Path, key_path: &Path) -> Result<(), CliError> {
    info!(
        input = %input.display(),
        output = %output.display(),
        key = %key_path.display(),
        "encrypting container"
    );

    let keyfile = read_keyfile(key_path)?;
    let input_len = std::fs::metadata(input)?.len();
    let input_file = File::open(input)?;

    let mut chunks = vec![aegis_format::WriteChunkSource {
        chunk_id: 1,
        chunk_type: ChunkType::Data,
        flags: 0,
        length: input_len,
        reader: Box::new(input_file),
    }];

    let tmp_path = temp_path_for(output);
    let mut output_file = File::create(&tmp_path)?;
    let _written =
        write_encrypted_container(&mut output_file, &mut chunks, keyfile.key.as_slice())?;

    finalize_output(&tmp_path, output)?;
    Ok(())
}

fn cmd_dec(input: &Path, output: &Path, key_path: &Path) -> Result<(), CliError> {
    info!(
        input = %input.display(),
        output = %output.display(),
        key = %key_path.display(),
        "decrypting container"
    );

    let keyfile = read_keyfile(key_path)?;
    let mut input_file = File::open(input)?;

    let tmp_path = temp_path_for(output);
    let mut output_file = File::create(&tmp_path)?;

    let result = decrypt_container(&mut input_file, &mut output_file, keyfile.key.as_slice());
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp_path);
    }
    result?;

    finalize_output(&tmp_path, output)?;
    Ok(())
}

fn temp_path_for(output: &Path) -> PathBuf {
    output.with_extension("tmp")
}

fn finalize_output(tmp_path: &Path, output: &Path) -> Result<(), std::io::Error> {
    if output.exists() {
        std::fs::remove_file(output)?;
    }
    std::fs::rename(tmp_path, output)
}

fn print_header(path: &Path, header: &aegis_format::FileHeader) {
    println!("Aegis container");
    println!("  Path: {}", path.display());
    println!("  Version: {}", header.version);
    println!("  Header length: {} bytes", header.header_len);
    println!("  Flags: 0x{flags:08X}", flags = header.flags);
    println!("  Chunk count: {}", header.chunk_count);
    println!("  Chunk table offset: {} bytes", header.chunk_table_offset);
    println!("  Footer offset: {} bytes", header.footer_offset);
}

fn print_v0_details(parsed: &ParsedContainer) {
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

fn print_v1_details(header: &aegis_format::FileHeader) {
    println!("Encryption:");
    if let Some(crypto) = header.crypto.as_ref() {
        println!("  Cipher: {:?}", crypto.cipher_id);
        println!("  KDF: {:?}", crypto.kdf_id);
        println!("  Salt length: {} bytes", crypto.salt.len());
        println!("  Nonce length: {} bytes", crypto.nonce.len());
        println!("  Payload: encrypted");
    } else {
        println!("  Missing crypto header");
    }
}

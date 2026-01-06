#![deny(warnings)]
#![deny(clippy::all)]

use std::fs::File;
use std::path::{Path, PathBuf};

use aegis_core::crypto::keyfile::{generate_key, read_keyfile, write_keyfile};
use aegis_core::crypto::CryptoError;
use aegis_format::{
    decrypt_container, decrypt_container_v2, decrypt_container_v3, extract_data_chunk,
    read_container_with_status, read_header, rotate_container_v3, write_container,
    write_encrypted_container_v3, ChunkType, CryptoHeader, FormatError, ParsedContainer,
    RecipientSpec, WrapType, ACF_VERSION_V2, ACF_VERSION_V3,
};
use clap::{Parser, Subcommand};
use rpassword::prompt_password;
use thiserror::Error;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;
use zeroize::Zeroizing;

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
        #[arg(long = "recipient-key", alias = "key", value_name = "PATH")]
        recipient_keys: Vec<PathBuf>,
        #[arg(long = "recipient-password", alias = "password")]
        recipient_password: bool,
    },
    /// Decrypt a container payload
    Dec {
        input: PathBuf,
        output: PathBuf,
        #[arg(long = "recipient-key", alias = "key", value_name = "PATH")]
        recipient_key: Option<PathBuf>,
        #[arg(long = "recipient-password", alias = "password")]
        recipient_password: bool,
    },
    /// List recipients in a v3 container
    ListRecipients { input: PathBuf },
    /// Rotate recipients in a v3 container
    Rotate {
        input: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long = "auth-key", value_name = "PATH")]
        auth_key: Option<PathBuf>,
        #[arg(long = "auth-password")]
        auth_password: bool,
        #[arg(long = "add-recipient-key", value_name = "PATH")]
        add_recipient_keys: Vec<PathBuf>,
        #[arg(long = "add-recipient-password")]
        add_recipient_password: bool,
        #[arg(long = "remove-recipient", value_name = "ID")]
        remove_recipient_ids: Vec<u32>,
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
    #[error("{0}")]
    Cli(String),
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
        Commands::Enc {
            input,
            output,
            recipient_keys,
            recipient_password,
        } => cmd_enc(&input, &output, &recipient_keys, recipient_password),
        Commands::Dec {
            input,
            output,
            recipient_key,
            recipient_password,
        } => cmd_dec(
            &input,
            &output,
            recipient_key.as_deref(),
            recipient_password,
        ),
        Commands::ListRecipients { input } => cmd_list_recipients(&input),
        Commands::Rotate {
            input,
            output,
            auth_key,
            auth_password,
            add_recipient_keys,
            add_recipient_password,
            remove_recipient_ids,
        } => cmd_rotate(
            &input,
            &output,
            auth_key.as_deref(),
            auth_password,
            &add_recipient_keys,
            add_recipient_password,
            &remove_recipient_ids,
        ),
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
        CliError::Cli(_) => EXIT_CLI,
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
    } else if header.version == ACF_VERSION_V2 {
        print_v2_details(&header);
    } else if header.version == ACF_VERSION_V3 {
        print_v3_details(&header);
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

enum AuthMode<'a> {
    Keyfile(&'a Path),
    Password,
}

fn resolve_mode<'a>(key_path: Option<&'a Path>, password: bool) -> Result<AuthMode<'a>, CliError> {
    match (key_path, password) {
        (Some(path), false) => Ok(AuthMode::Keyfile(path)),
        (None, true) => Ok(AuthMode::Password),
        (Some(_), true) => Err(CliError::Cli(
            "choose either --recipient-key or --recipient-password, not both".to_string(),
        )),
        (None, false) => Err(CliError::Cli(
            "missing --recipient-key or --recipient-password".to_string(),
        )),
    }
}

fn resolve_auth_mode<'a>(
    key_path: Option<&'a Path>,
    password: bool,
) -> Result<AuthMode<'a>, CliError> {
    match (key_path, password) {
        (Some(path), false) => Ok(AuthMode::Keyfile(path)),
        (None, true) => Ok(AuthMode::Password),
        (Some(_), true) => Err(CliError::Cli(
            "choose either --auth-key or --auth-password, not both".to_string(),
        )),
        (None, false) => Err(CliError::Cli(
            "missing --auth-key or --auth-password".to_string(),
        )),
    }
}

fn read_password(confirm: bool) -> Result<Zeroizing<Vec<u8>>, CliError> {
    if let Ok(password) = std::env::var("AEGIS_PASSWORD") {
        if confirm {
            if let Ok(confirm_pw) = std::env::var("AEGIS_PASSWORD_CONFIRM") {
                if confirm_pw != password {
                    return Err(CliError::Cli("passwords do not match".to_string()));
                }
            }
        }
        return Ok(Zeroizing::new(password.into_bytes()));
    }

    let password = Zeroizing::new(prompt_password("Enter password: ")?);
    if confirm {
        let confirm_pw = Zeroizing::new(prompt_password("Confirm password: ")?);
        if password.as_str() != confirm_pw.as_str() {
            return Err(CliError::Cli("passwords do not match".to_string()));
        }
    }

    Ok(Zeroizing::new(password.as_bytes().to_vec()))
}

fn cmd_enc(
    input: &Path,
    output: &Path,
    recipient_keys: &[PathBuf],
    recipient_password: bool,
) -> Result<(), CliError> {
    if recipient_keys.is_empty() && !recipient_password {
        return Err(CliError::Cli(
            "missing --recipient-key or --recipient-password".to_string(),
        ));
    }

    info!(
        input = %input.display(),
        output = %output.display(),
        "encrypting container"
    );

    let input_len = std::fs::metadata(input)?.len();
    let input_file = File::open(input)?;

    let mut chunks = vec![aegis_format::WriteChunkSource {
        chunk_id: 1,
        chunk_type: ChunkType::Data,
        flags: 0,
        length: input_len,
        reader: Box::new(input_file),
    }];

    let total_recipients = recipient_keys.len() + if recipient_password { 1 } else { 0 };
    let mut materials: Vec<(WrapType, Zeroizing<Vec<u8>>)> = Vec::new();
    materials.reserve_exact(total_recipients);

    for key_path in recipient_keys {
        let keyfile = read_keyfile(key_path)?;
        materials.push((WrapType::Keyfile, keyfile.key));
    }

    if recipient_password {
        let password_bytes = read_password(true)?;
        materials.push((WrapType::Password, password_bytes));
    }

    let mut recipients: Vec<RecipientSpec<'_>> = Vec::with_capacity(materials.len());
    for (index, (recipient_type, material)) in materials.iter().enumerate() {
        recipients.push(RecipientSpec {
            recipient_id: (index as u32) + 1,
            recipient_type: *recipient_type,
            key_material: material.as_slice(),
        });
    }

    let tmp_path = temp_path_for(output);
    let mut output_file = File::create(&tmp_path)?;

    let _written = write_encrypted_container_v3(&mut output_file, &mut chunks, &recipients)?;

    finalize_output(&tmp_path, output)?;
    Ok(())
}

fn cmd_list_recipients(input: &Path) -> Result<(), CliError> {
    let mut file = File::open(input)?;
    let (header, _) = read_header(&mut file)?;

    if header.version != ACF_VERSION_V3 {
        return Err(CliError::Cli(
            "recipients are only available in v3 containers".to_string(),
        ));
    }

    let recipients = match header.crypto.as_ref() {
        Some(CryptoHeader::V3 { recipients, .. }) => recipients,
        _ => return Err(CliError::Format(FormatError::MissingCryptoHeader)),
    };

    println!("Recipients:");
    for recipient in recipients {
        println!(
            "  - id: {} type: {:?} wrap: {:?} wrapped: {} bytes",
            recipient.recipient_id,
            recipient.recipient_type,
            recipient.wrap_alg,
            recipient.wrapped_key.len()
        );
    }

    Ok(())
}

fn cmd_rotate(
    input: &Path,
    output: &Path,
    auth_key: Option<&Path>,
    auth_password: bool,
    add_recipient_keys: &[PathBuf],
    add_recipient_password: bool,
    remove_recipient_ids: &[u32],
) -> Result<(), CliError> {
    if add_recipient_keys.is_empty() && !add_recipient_password && remove_recipient_ids.is_empty() {
        return Err(CliError::Cli(
            "rotation requires --add-recipient-key, --add-recipient-password, or --remove-recipient"
                .to_string(),
        ));
    }

    let mut header_file = File::open(input)?;
    let (header, _) = read_header(&mut header_file)?;

    if header.version != ACF_VERSION_V3 {
        return Err(CliError::Cli(
            "rotation only supports v3 containers".to_string(),
        ));
    }

    let recipients = match header.crypto.as_ref() {
        Some(CryptoHeader::V3 { recipients, .. }) => recipients,
        _ => return Err(CliError::Format(FormatError::MissingCryptoHeader)),
    };

    let has_key = recipients
        .iter()
        .any(|recipient| recipient.recipient_type == WrapType::Keyfile);
    let has_password = recipients
        .iter()
        .any(|recipient| recipient.recipient_type == WrapType::Password);

    let mode = resolve_auth_mode(auth_key, auth_password)?;
    match &mode {
        AuthMode::Keyfile(_) if !has_key => {
            return Err(CliError::Cli(
                "container expects a password, not a key file".to_string(),
            ))
        }
        AuthMode::Password if !has_password => {
            return Err(CliError::Cli(
                "container expects a key file, not a password".to_string(),
            ))
        }
        _ => {}
    }

    let add_count = add_recipient_keys.len() + if add_recipient_password { 1 } else { 0 };
    let mut add_materials: Vec<(WrapType, Zeroizing<Vec<u8>>)> = Vec::new();
    add_materials.reserve_exact(add_count);
    let mut add_specs: Vec<RecipientSpec<'_>> = Vec::with_capacity(add_count);
    let next_id = recipients
        .iter()
        .map(|recipient| recipient.recipient_id)
        .max()
        .unwrap_or(0)
        .saturating_add(1);

    for key_path in add_recipient_keys {
        let keyfile = read_keyfile(key_path)?;
        add_materials.push((WrapType::Keyfile, keyfile.key));
    }

    if add_recipient_password {
        let password_bytes = read_password(true)?;
        add_materials.push((WrapType::Password, password_bytes));
    }

    for (offset, (recipient_type, material)) in add_materials.iter().enumerate() {
        let recipient_id = next_id.saturating_add(offset as u32);
        add_specs.push(RecipientSpec {
            recipient_id,
            recipient_type: *recipient_type,
            key_material: material.as_slice(),
        });
    }

    let (auth_wrap_type, auth_material) = match mode {
        AuthMode::Keyfile(path) => (WrapType::Keyfile, read_keyfile(path)?.key),
        AuthMode::Password => (WrapType::Password, read_password(false)?),
    };

    info!(
        input = %input.display(),
        output = %output.display(),
        "rotating recipients"
    );

    let tmp_path = temp_path_for(output);
    let mut output_file = File::create(&tmp_path)?;
    let mut input_file = File::open(input)?;

    let result = rotate_container_v3(
        &mut input_file,
        &mut output_file,
        auth_material.as_slice(),
        auth_wrap_type,
        &add_specs,
        remove_recipient_ids,
    );
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp_path);
    }
    result?;

    finalize_output(&tmp_path, output)?;
    Ok(())
}

fn cmd_dec(
    input: &Path,
    output: &Path,
    recipient_key: Option<&Path>,
    recipient_password: bool,
) -> Result<(), CliError> {
    let mut header_file = File::open(input)?;
    let (header, _) = read_header(&mut header_file)?;

    match header.version {
        aegis_format::ACF_VERSION_V1 => {
            if recipient_password {
                return Err(CliError::Cli(
                    "v1 containers require a key file, not a password".to_string(),
                ));
            }
            let key_path = recipient_key.ok_or_else(|| {
                CliError::Cli("missing --recipient-key for v1 container".to_string())
            })?;

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

            let result =
                decrypt_container(&mut input_file, &mut output_file, keyfile.key.as_slice());
            if result.is_err() {
                let _ = std::fs::remove_file(&tmp_path);
            }
            result?;

            finalize_output(&tmp_path, output)?;
            Ok(())
        }
        ACF_VERSION_V2 => {
            let wrap_type = match header.crypto.as_ref() {
                Some(CryptoHeader::V2 { wrap_type, .. }) => *wrap_type,
                _ => return Err(CliError::Format(FormatError::MissingCryptoHeader)),
            };

            match wrap_type {
                WrapType::Keyfile => {
                    if recipient_password {
                        return Err(CliError::Cli(
                            "container expects a key file, not a password".to_string(),
                        ));
                    }
                    let key_path = recipient_key.ok_or_else(|| {
                        CliError::Cli("missing --recipient-key for keyfile container".to_string())
                    })?;

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

                    let result = decrypt_container_v2(
                        &mut input_file,
                        &mut output_file,
                        keyfile.key.as_slice(),
                        WrapType::Keyfile,
                    );
                    if result.is_err() {
                        let _ = std::fs::remove_file(&tmp_path);
                    }
                    result?;
                    finalize_output(&tmp_path, output)?;
                    Ok(())
                }
                WrapType::Password => {
                    if recipient_key.is_some() {
                        return Err(CliError::Cli(
                            "container expects a password, not a key file".to_string(),
                        ));
                    }
                    if !recipient_password {
                        return Err(CliError::Cli(
                            "missing --recipient-password for password container".to_string(),
                        ));
                    }

                    info!(
                        input = %input.display(),
                        output = %output.display(),
                        "decrypting container"
                    );

                    let password_bytes = read_password(false)?;
                    let mut input_file = File::open(input)?;

                    let tmp_path = temp_path_for(output);
                    let mut output_file = File::create(&tmp_path)?;

                    let result = decrypt_container_v2(
                        &mut input_file,
                        &mut output_file,
                        password_bytes.as_slice(),
                        WrapType::Password,
                    );
                    if result.is_err() {
                        let _ = std::fs::remove_file(&tmp_path);
                    }
                    result?;
                    finalize_output(&tmp_path, output)?;
                    Ok(())
                }
            }
        }
        ACF_VERSION_V3 => {
            let recipients = match header.crypto.as_ref() {
                Some(CryptoHeader::V3 { recipients, .. }) => recipients,
                _ => return Err(CliError::Format(FormatError::MissingCryptoHeader)),
            };

            let has_key = recipients
                .iter()
                .any(|recipient| recipient.recipient_type == WrapType::Keyfile);
            let has_password = recipients
                .iter()
                .any(|recipient| recipient.recipient_type == WrapType::Password);

            let mode = resolve_mode(recipient_key, recipient_password)?;

            match mode {
                AuthMode::Keyfile(key_path) => {
                    if !has_key {
                        return Err(CliError::Cli(
                            "container expects a password, not a key file".to_string(),
                        ));
                    }

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

                    let result = decrypt_container_v3(
                        &mut input_file,
                        &mut output_file,
                        keyfile.key.as_slice(),
                        WrapType::Keyfile,
                    );
                    if result.is_err() {
                        let _ = std::fs::remove_file(&tmp_path);
                    }
                    result?;
                    finalize_output(&tmp_path, output)?;
                    Ok(())
                }
                AuthMode::Password => {
                    if !has_password {
                        return Err(CliError::Cli(
                            "container expects a key file, not a password".to_string(),
                        ));
                    }

                    info!(
                        input = %input.display(),
                        output = %output.display(),
                        "decrypting container"
                    );

                    let password_bytes = read_password(false)?;
                    let mut input_file = File::open(input)?;

                    let tmp_path = temp_path_for(output);
                    let mut output_file = File::create(&tmp_path)?;

                    let result = decrypt_container_v3(
                        &mut input_file,
                        &mut output_file,
                        password_bytes.as_slice(),
                        WrapType::Password,
                    );
                    if result.is_err() {
                        let _ = std::fs::remove_file(&tmp_path);
                    }
                    result?;
                    finalize_output(&tmp_path, output)?;
                    Ok(())
                }
            }
        }
        other => Err(CliError::Format(FormatError::UnsupportedVersion(other))),
    }
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
    if let Some(CryptoHeader::V1 {
        cipher_id,
        kdf_id,
        salt,
        nonce,
    }) = header.crypto.as_ref()
    {
        println!("  Cipher: {:?}", cipher_id);
        println!("  KDF: {:?}", kdf_id);
        println!("  Salt length: {} bytes", salt.len());
        println!("  Nonce length: {} bytes", nonce.len());
        println!("  Payload: encrypted");
        return;
    }
    println!("  Missing crypto header");
}

fn print_v2_details(header: &aegis_format::FileHeader) {
    println!("Encryption (v2):");
    if let Some(CryptoHeader::V2 {
        cipher_id,
        kdf_id,
        kdf_params,
        salt,
        nonce,
        wrap_type,
        wrapped_key,
    }) = header.crypto.as_ref()
    {
        println!("  Cipher: {:?}", cipher_id);
        println!("  KDF: {:?}", kdf_id);
        println!(
            "  KDF params: mem={} KiB, iterations={}, parallelism={}",
            kdf_params.memory_kib, kdf_params.iterations, kdf_params.parallelism
        );
        println!("  Salt length: {} bytes", salt.len());
        println!("  Nonce length: {} bytes", nonce.len());
        println!("  Wrap type: {:?}", wrap_type);
        println!("  Wrapped key length: {} bytes", wrapped_key.len());
        println!("  Payload: encrypted");
        return;
    }
    println!("  Missing crypto header");
}

fn print_v3_details(header: &aegis_format::FileHeader) {
    println!("Encryption (v3):");
    if let Some(CryptoHeader::V3 {
        cipher_id,
        kdf_id,
        kdf_params,
        salt,
        nonce,
        recipients,
    }) = header.crypto.as_ref()
    {
        println!("  Cipher: {:?}", cipher_id);
        println!("  KDF: {:?}", kdf_id);
        println!(
            "  KDF params: mem={} KiB, iterations={}, parallelism={}",
            kdf_params.memory_kib, kdf_params.iterations, kdf_params.parallelism
        );
        println!("  Salt length: {} bytes", salt.len());
        println!("  Nonce length: {} bytes", nonce.len());
        println!("  Recipients: {}", recipients.len());
        for recipient in recipients {
            println!(
                "  - id: {} type: {:?} wrap: {:?} wrapped: {} bytes",
                recipient.recipient_id,
                recipient.recipient_type,
                recipient.wrap_alg,
                recipient.wrapped_key.len()
            );
        }
        println!("  Payload: encrypted");
        return;
    }
    println!("  Missing crypto header");
}

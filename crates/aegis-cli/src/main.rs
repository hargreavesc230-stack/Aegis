#![deny(warnings)]
#![deny(clippy::all)]

use std::fmt::Write;
use std::fs::File;
use std::path::{Path, PathBuf};

use aegis_core::crypto::keyfile::{generate_key, read_keyfile, write_keyfile};
use aegis_core::crypto::public_key::{
    generate_keypair, read_private_keyfile, read_public_keyfile, write_private_keyfile,
    write_public_keyfile,
};
use aegis_core::crypto::CryptoError;
use aegis_format::{
    decrypt_container, decrypt_container_v2, decrypt_container_v3, decrypt_container_v4,
    extract_data_chunk, read_container_with_status, read_header, rotate_container_v3,
    rotate_container_v4, write_container, write_encrypted_container_v3,
    write_encrypted_container_v4, ChunkType, CryptoHeader, FormatError, ParsedContainer,
    RecipientSpec, WrapType, ACF_VERSION_V2, ACF_VERSION_V3, ACF_VERSION_V4,
};
use clap::{Parser, Subcommand};
use rpassword::prompt_password;
use thiserror::Error;
use tracing::info;
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
    Inspect {
        path: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Pack a container from input data (v0, no encryption)
    Pack {
        input: PathBuf,
        output: PathBuf,
        #[arg(long)]
        metadata: Option<PathBuf>,
        #[arg(long)]
        force: bool,
    },
    /// Unpack the data chunk from a v0 container
    Unpack {
        input: PathBuf,
        output: PathBuf,
        #[arg(long)]
        force: bool,
    },
    /// Generate a new key file
    Keygen {
        #[arg(value_name = "PATH")]
        output: Option<PathBuf>,
        #[arg(long)]
        force: bool,
        #[arg(long = "public", value_name = "PATH")]
        public: Option<PathBuf>,
        #[arg(long = "private", value_name = "PATH")]
        private: Option<PathBuf>,
    },
    /// Encrypt a payload into a new container
    Enc {
        input: PathBuf,
        output: PathBuf,
        #[arg(long = "recipient-key", alias = "key", value_name = "PATH")]
        recipient_keys: Vec<PathBuf>,
        #[arg(long = "recipient-pubkey", value_name = "PATH")]
        recipient_pubkeys: Vec<PathBuf>,
        #[arg(long = "recipient-password", alias = "password")]
        recipient_password: bool,
        #[arg(long)]
        force: bool,
        #[arg(long = "allow-mixed-recipients")]
        allow_mixed_recipients: bool,
    },
    /// Decrypt a container payload
    Dec {
        input: PathBuf,
        output: PathBuf,
        #[arg(long = "recipient-key", alias = "key", value_name = "PATH")]
        recipient_key: Option<PathBuf>,
        #[arg(long = "private-key", value_name = "PATH")]
        private_key: Option<PathBuf>,
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
        #[arg(long)]
        force: bool,
        #[arg(long = "allow-mixed-recipients")]
        allow_mixed_recipients: bool,
        #[arg(long = "auth-key", value_name = "PATH")]
        auth_key: Option<PathBuf>,
        #[arg(long = "auth-private-key", value_name = "PATH")]
        auth_private_key: Option<PathBuf>,
        #[arg(long = "auth-password")]
        auth_password: bool,
        #[arg(long = "add-recipient-key", value_name = "PATH")]
        add_recipient_keys: Vec<PathBuf>,
        #[arg(long = "add-recipient-pubkey", value_name = "PATH")]
        add_recipient_pubkeys: Vec<PathBuf>,
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
            if err.exit_code() == 0 {
                let _ = err.print();
                return EXIT_SUCCESS;
            }
            let message = err.to_string();
            let line = message.lines().next().unwrap_or("error: invalid arguments");
            eprintln!("{line}");
            return EXIT_CLI;
        }
    };

    let result = match cli.command {
        Commands::Inspect { path, json } => cmd_inspect(&path, json),
        Commands::Pack {
            input,
            output,
            metadata,
            force,
        } => cmd_pack(&input, &output, metadata.as_deref(), force),
        Commands::Unpack {
            input,
            output,
            force,
        } => cmd_unpack(&input, &output, force),
        Commands::Keygen {
            output,
            force,
            public,
            private,
        } => cmd_keygen(
            output.as_deref(),
            public.as_deref(),
            private.as_deref(),
            force,
        ),
        Commands::Enc {
            input,
            output,
            recipient_keys,
            recipient_pubkeys,
            recipient_password,
            force,
            allow_mixed_recipients,
        } => cmd_enc(
            &input,
            &output,
            &recipient_keys,
            &recipient_pubkeys,
            recipient_password,
            force,
            allow_mixed_recipients,
        ),
        Commands::Dec {
            input,
            output,
            recipient_key,
            private_key,
            recipient_password,
        } => cmd_dec(
            &input,
            &output,
            recipient_key.as_deref(),
            private_key.as_deref(),
            recipient_password,
        ),
        Commands::ListRecipients { input } => cmd_list_recipients(&input),
        Commands::Rotate {
            input,
            output,
            force,
            allow_mixed_recipients,
            auth_key,
            auth_private_key,
            auth_password,
            add_recipient_keys,
            add_recipient_pubkeys,
            add_recipient_password,
            remove_recipient_ids,
        } => cmd_rotate(RotateArgs {
            input: &input,
            output: &output,
            force,
            allow_mixed_recipients,
            auth_key: auth_key.as_deref(),
            auth_private_key: auth_private_key.as_deref(),
            auth_password,
            add_recipient_keys: &add_recipient_keys,
            add_recipient_pubkeys: &add_recipient_pubkeys,
            add_recipient_password,
            remove_recipient_ids: &remove_recipient_ids,
        }),
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
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn"));
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .finish();
    let _ = tracing::subscriber::set_global_default(subscriber);
}

fn report_error(err: &CliError) {
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

fn cmd_inspect(path: &Path, json: bool) -> Result<(), CliError> {
    info!(path = %path.display(), "reading container");

    let mut file = File::open(path)?;
    let (header, _) = read_header(&mut file)?;

    if json {
        print_json_inspect(path, &header)?;
        return Ok(());
    }

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
    } else if header.version == ACF_VERSION_V4 {
        print_v4_details(&header);
    }

    Ok(())
}

fn cmd_pack(
    input: &Path,
    output: &Path,
    metadata: Option<&Path>,
    force: bool,
) -> Result<(), CliError> {
    ensure_output_path(output, force)?;
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

    let tmp_path = prepare_temp_output(output)?;
    let mut output_file = File::create(&tmp_path)?;

    let result = write_container(&mut output_file, &mut chunks);
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp_path);
    }
    let _written = result?;
    finalize_output(&tmp_path, output, force)?;

    Ok(())
}

fn cmd_unpack(input: &Path, output: &Path, force: bool) -> Result<(), CliError> {
    ensure_output_path(output, force)?;
    info!(
        input = %input.display(),
        output = %output.display(),
        "unpacking container"
    );

    let mut input_file = File::open(input)?;
    let tmp_path = prepare_temp_output(output)?;
    let mut output_file = File::create(&tmp_path)?;

    let result = extract_data_chunk(&mut input_file, &mut output_file);
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp_path);
    }
    let _parsed = result?;
    finalize_output(&tmp_path, output, force)?;

    Ok(())
}

fn cmd_keygen(
    output: Option<&Path>,
    public: Option<&Path>,
    private: Option<&Path>,
    force: bool,
) -> Result<(), CliError> {
    match (output, public, private) {
        (Some(_), Some(_), _) | (Some(_), _, Some(_)) => Err(CliError::Cli(
            "use either key file output or --public/--private, not both".to_string(),
        )),
        (_, Some(pub_path), Some(priv_path)) => {
            ensure_output_path(pub_path, force)?;
            ensure_output_path(priv_path, force)?;
            info!(
                public = %pub_path.display(),
                private = %priv_path.display(),
                "generating public/private keypair"
            );
            let (private_key, public_key) = generate_keypair()?;
            write_public_keyfile(pub_path, &public_key, force)?;
            write_private_keyfile(priv_path, &private_key, force)?;
            Ok(())
        }
        (_, None, Some(_)) | (_, Some(_), None) => Err(CliError::Cli(
            "both --public and --private are required for keypair generation".to_string(),
        )),
        (Some(out_path), None, None) => {
            ensure_output_path(out_path, force)?;
            info!(output = %out_path.display(), "generating key file");
            let key = generate_key(KEY_LEN)?;
            write_keyfile(out_path, key.as_slice(), force)?;
            Ok(())
        }
        (None, None, None) => Err(CliError::Cli(
            "missing output path for key generation".to_string(),
        )),
    }
}

enum AuthMode<'a> {
    Keyfile(&'a Path),
    Password,
    PrivateKey(&'a Path),
}

fn resolve_mode<'a>(
    key_path: Option<&'a Path>,
    private_key: Option<&'a Path>,
    password: bool,
) -> Result<AuthMode<'a>, CliError> {
    match (key_path, private_key, password) {
        (Some(path), None, false) => Ok(AuthMode::Keyfile(path)),
        (None, Some(path), false) => Ok(AuthMode::PrivateKey(path)),
        (None, None, true) => Ok(AuthMode::Password),
        (Some(_), _, true) | (_, Some(_), true) | (Some(_), Some(_), false) => Err(CliError::Cli(
            "choose only one of --recipient-key, --private-key, or --recipient-password"
                .to_string(),
        )),
        (None, None, false) => Err(CliError::Cli(
            "missing --recipient-key, --private-key, or --recipient-password".to_string(),
        )),
    }
}

fn resolve_auth_mode<'a>(
    key_path: Option<&'a Path>,
    private_key: Option<&'a Path>,
    password: bool,
) -> Result<AuthMode<'a>, CliError> {
    match (key_path, private_key, password) {
        (Some(path), None, false) => Ok(AuthMode::Keyfile(path)),
        (None, Some(path), false) => Ok(AuthMode::PrivateKey(path)),
        (None, None, true) => Ok(AuthMode::Password),
        (Some(_), _, true) | (_, Some(_), true) | (Some(_), Some(_), false) => Err(CliError::Cli(
            "choose only one of --auth-key, --auth-private-key, or --auth-password".to_string(),
        )),
        (None, None, false) => Err(CliError::Cli(
            "missing --auth-key, --auth-private-key, or --auth-password".to_string(),
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
    recipient_pubkeys: &[PathBuf],
    recipient_password: bool,
    force: bool,
    allow_mixed_recipients: bool,
) -> Result<(), CliError> {
    if recipient_keys.is_empty() && recipient_pubkeys.is_empty() && !recipient_password {
        return Err(CliError::Cli(
            "missing --recipient-key, --recipient-pubkey, or --recipient-password".to_string(),
        ));
    }
    let mut recipient_types = 0u8;
    if !recipient_keys.is_empty() {
        recipient_types += 1;
    }
    if !recipient_pubkeys.is_empty() {
        recipient_types += 1;
    }
    if recipient_password {
        recipient_types += 1;
    }
    if recipient_types > 1 && !allow_mixed_recipients {
        return Err(CliError::Cli(
            "multiple recipient types require --allow-mixed-recipients".to_string(),
        ));
    }
    ensure_output_path(output, force)?;

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

    let total_recipients =
        recipient_keys.len() + recipient_pubkeys.len() + if recipient_password { 1 } else { 0 };
    let mut materials: Vec<(WrapType, Zeroizing<Vec<u8>>)> = Vec::new();
    materials.reserve_exact(total_recipients);
    let mut public_keys: Vec<[u8; 32]> = Vec::new();
    public_keys.reserve_exact(recipient_pubkeys.len());

    for key_path in recipient_keys {
        let keyfile = read_keyfile(key_path)?;
        materials.push((WrapType::Keyfile, keyfile.key));
    }

    for pubkey_path in recipient_pubkeys {
        let pubkey = read_public_keyfile(pubkey_path)?;
        public_keys.push(pubkey.key);
    }

    if recipient_password {
        let password_bytes = read_password(true)?;
        materials.push((WrapType::Password, password_bytes));
    }

    let mut recipients: Vec<RecipientSpec<'_>> =
        Vec::with_capacity(materials.len() + public_keys.len());
    let mut next_id = 1u32;
    for (recipient_type, material) in &materials {
        recipients.push(RecipientSpec {
            recipient_id: next_id,
            recipient_type: *recipient_type,
            key_material: Some(material.as_slice()),
            public_key: None,
        });
        next_id = next_id.saturating_add(1);
    }

    for pubkey in &public_keys {
        recipients.push(RecipientSpec {
            recipient_id: next_id,
            recipient_type: WrapType::PublicKey,
            key_material: None,
            public_key: Some(*pubkey),
        });
        next_id = next_id.saturating_add(1);
    }

    let tmp_path = prepare_temp_output(output)?;
    let mut output_file = File::create(&tmp_path)?;

    if recipient_pubkeys.is_empty() {
        let _written = write_encrypted_container_v3(&mut output_file, &mut chunks, &recipients)?;
    } else {
        let _written = write_encrypted_container_v4(&mut output_file, &mut chunks, &recipients)?;
    }

    finalize_output(&tmp_path, output, force)?;
    Ok(())
}

fn cmd_list_recipients(input: &Path) -> Result<(), CliError> {
    let mut file = File::open(input)?;
    let (header, _) = read_header(&mut file)?;

    if header.version != ACF_VERSION_V3 && header.version != ACF_VERSION_V4 {
        return Err(CliError::Cli(
            "recipients are only available in v3/v4 containers".to_string(),
        ));
    }

    let recipients = match header.crypto.as_ref() {
        Some(CryptoHeader::V3 { recipients, .. }) => recipients,
        Some(CryptoHeader::V4 { recipients, .. }) => recipients,
        _ => return Err(CliError::Format(FormatError::MissingCryptoHeader)),
    };

    println!("Recipients:");
    for recipient in recipients {
        if recipient.recipient_type == WrapType::PublicKey {
            let pubkey = recipient
                .recipient_pubkey
                .as_ref()
                .map(|bytes| to_hex(bytes))
                .unwrap_or_else(|| "<missing>".to_string());
            let ephemeral = recipient
                .ephemeral_pubkey
                .as_ref()
                .map(|bytes| to_hex(bytes))
                .unwrap_or_else(|| "<missing>".to_string());
            println!(
                "  - id: {} type: {:?} wrap: {:?} wrapped: {} bytes pubkey: {} eph: {}",
                recipient.recipient_id,
                recipient.recipient_type,
                recipient.wrap_alg,
                recipient.wrapped_key.len(),
                pubkey,
                ephemeral
            );
        } else {
            println!(
                "  - id: {} type: {:?} wrap: {:?} wrapped: {} bytes",
                recipient.recipient_id,
                recipient.recipient_type,
                recipient.wrap_alg,
                recipient.wrapped_key.len()
            );
        }
    }

    Ok(())
}

struct RotateArgs<'a> {
    input: &'a Path,
    output: &'a Path,
    force: bool,
    allow_mixed_recipients: bool,
    auth_key: Option<&'a Path>,
    auth_private_key: Option<&'a Path>,
    auth_password: bool,
    add_recipient_keys: &'a [PathBuf],
    add_recipient_pubkeys: &'a [PathBuf],
    add_recipient_password: bool,
    remove_recipient_ids: &'a [u32],
}

fn cmd_rotate(args: RotateArgs<'_>) -> Result<(), CliError> {
    let RotateArgs {
        input,
        output,
        force,
        allow_mixed_recipients,
        auth_key,
        auth_private_key,
        auth_password,
        add_recipient_keys,
        add_recipient_pubkeys,
        add_recipient_password,
        remove_recipient_ids,
    } = args;
    if add_recipient_keys.is_empty()
        && add_recipient_pubkeys.is_empty()
        && !add_recipient_password
        && remove_recipient_ids.is_empty()
    {
        return Err(CliError::Cli(
            "rotation requires add/remove recipient options".to_string(),
        ));
    }
    let mut add_types = 0u8;
    if !add_recipient_keys.is_empty() {
        add_types += 1;
    }
    if !add_recipient_pubkeys.is_empty() {
        add_types += 1;
    }
    if add_recipient_password {
        add_types += 1;
    }
    if add_types > 1 && !allow_mixed_recipients {
        return Err(CliError::Cli(
            "multiple recipient types require --allow-mixed-recipients".to_string(),
        ));
    }
    ensure_output_path(output, force)?;

    let mut header_file = File::open(input)?;
    let (header, _) = read_header(&mut header_file)?;

    match header.version {
        ACF_VERSION_V3 => {
            if auth_private_key.is_some() || !add_recipient_pubkeys.is_empty() {
                return Err(CliError::Cli(
                    "v3 rotation does not support public key recipients".to_string(),
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

            let mode = resolve_auth_mode(auth_key, None, auth_password)?;
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
                AuthMode::PrivateKey(_) => {
                    return Err(CliError::Cli(
                        "v3 rotation does not support private keys".to_string(),
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
                    key_material: Some(material.as_slice()),
                    public_key: None,
                });
            }

            let (auth_wrap_type, auth_material) = match mode {
                AuthMode::Keyfile(path) => (WrapType::Keyfile, read_keyfile(path)?.key),
                AuthMode::Password => (WrapType::Password, read_password(false)?),
                AuthMode::PrivateKey(_) => {
                    return Err(CliError::Cli(
                        "v3 rotation does not support private keys".to_string(),
                    ))
                }
            };

            info!(
                input = %input.display(),
                output = %output.display(),
                "rotating recipients"
            );

            let tmp_path = prepare_temp_output(output)?;
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

            finalize_output(&tmp_path, output, force)?;
            Ok(())
        }
        ACF_VERSION_V4 => {
            let recipients = match header.crypto.as_ref() {
                Some(CryptoHeader::V4 { recipients, .. }) => recipients,
                _ => return Err(CliError::Format(FormatError::MissingCryptoHeader)),
            };

            let has_key = recipients
                .iter()
                .any(|recipient| recipient.recipient_type == WrapType::Keyfile);
            let has_password = recipients
                .iter()
                .any(|recipient| recipient.recipient_type == WrapType::Password);
            let has_public = recipients
                .iter()
                .any(|recipient| recipient.recipient_type == WrapType::PublicKey);

            let mode = resolve_auth_mode(auth_key, auth_private_key, auth_password)?;
            match &mode {
                AuthMode::Keyfile(_) if !has_key => {
                    return Err(CliError::Cli(
                        "container expects a password or private key, not a key file".to_string(),
                    ))
                }
                AuthMode::Password if !has_password => {
                    return Err(CliError::Cli(
                        "container expects a key file or private key, not a password".to_string(),
                    ))
                }
                AuthMode::PrivateKey(_) if !has_public => {
                    return Err(CliError::Cli(
                        "container expects a key file or password, not a private key".to_string(),
                    ))
                }
                _ => {}
            }

            let mut add_materials: Vec<(WrapType, Zeroizing<Vec<u8>>)> = Vec::new();
            add_materials.reserve_exact(
                add_recipient_keys.len() + if add_recipient_password { 1 } else { 0 },
            );
            for key_path in add_recipient_keys {
                let keyfile = read_keyfile(key_path)?;
                add_materials.push((WrapType::Keyfile, keyfile.key));
            }
            if add_recipient_password {
                let password_bytes = read_password(true)?;
                add_materials.push((WrapType::Password, password_bytes));
            }

            let mut add_public_keys: Vec<[u8; 32]> = Vec::new();
            add_public_keys.reserve_exact(add_recipient_pubkeys.len());
            for pubkey_path in add_recipient_pubkeys {
                let pubkey = read_public_keyfile(pubkey_path)?;
                add_public_keys.push(pubkey.key);
            }

            let total_add = add_materials.len() + add_public_keys.len();
            let mut add_specs: Vec<RecipientSpec<'_>> = Vec::with_capacity(total_add);
            let mut next_id = recipients
                .iter()
                .map(|recipient| recipient.recipient_id)
                .max()
                .unwrap_or(0)
                .saturating_add(1);

            for (recipient_type, material) in &add_materials {
                add_specs.push(RecipientSpec {
                    recipient_id: next_id,
                    recipient_type: *recipient_type,
                    key_material: Some(material.as_slice()),
                    public_key: None,
                });
                next_id = next_id.saturating_add(1);
            }

            for pubkey in &add_public_keys {
                add_specs.push(RecipientSpec {
                    recipient_id: next_id,
                    recipient_type: WrapType::PublicKey,
                    key_material: None,
                    public_key: Some(*pubkey),
                });
                next_id = next_id.saturating_add(1);
            }

            let (auth_wrap_type, auth_material) = match mode {
                AuthMode::Keyfile(path) => (WrapType::Keyfile, read_keyfile(path)?.key),
                AuthMode::Password => (WrapType::Password, read_password(false)?),
                AuthMode::PrivateKey(path) => {
                    let keyfile = read_private_keyfile(path)?;
                    let key_vec = Zeroizing::new(keyfile.key.as_ref().to_vec());
                    (WrapType::PublicKey, key_vec)
                }
            };

            info!(
                input = %input.display(),
                output = %output.display(),
                "rotating recipients"
            );

            let tmp_path = prepare_temp_output(output)?;
            let mut output_file = File::create(&tmp_path)?;
            let mut input_file = File::open(input)?;

            let result = rotate_container_v4(
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

            finalize_output(&tmp_path, output, force)?;
            Ok(())
        }
        _ => Err(CliError::Cli(
            "rotation only supports v3/v4 containers".to_string(),
        )),
    }
}

fn cmd_dec(
    input: &Path,
    output: &Path,
    recipient_key: Option<&Path>,
    private_key: Option<&Path>,
    recipient_password: bool,
) -> Result<(), CliError> {
    ensure_output_path(output, false)?;
    let mut header_file = File::open(input)?;
    let (header, _) = read_header(&mut header_file)?;

    match header.version {
        aegis_format::ACF_VERSION_V1 => {
            if recipient_password || private_key.is_some() {
                return Err(CliError::Cli(
                    "v1 containers require a key file, not a password or private key".to_string(),
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

            let tmp_path = prepare_temp_output(output)?;
            let mut output_file = File::create(&tmp_path)?;

            let result =
                decrypt_container(&mut input_file, &mut output_file, keyfile.key.as_slice());
            if result.is_err() {
                let _ = std::fs::remove_file(&tmp_path);
            }
            result?;

            finalize_output(&tmp_path, output, false)?;
            Ok(())
        }
        ACF_VERSION_V2 => {
            let wrap_type = match header.crypto.as_ref() {
                Some(CryptoHeader::V2 { wrap_type, .. }) => *wrap_type,
                _ => return Err(CliError::Format(FormatError::MissingCryptoHeader)),
            };

            match wrap_type {
                WrapType::Keyfile => {
                    if recipient_password || private_key.is_some() {
                        return Err(CliError::Cli(
                            "container expects a key file, not a password or private key"
                                .to_string(),
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

                    let tmp_path = prepare_temp_output(output)?;
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
                    finalize_output(&tmp_path, output, false)?;
                    Ok(())
                }
                WrapType::Password => {
                    if recipient_key.is_some() || private_key.is_some() {
                        return Err(CliError::Cli(
                            "container expects a password, not a key file or private key"
                                .to_string(),
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

                    let tmp_path = prepare_temp_output(output)?;
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
                    finalize_output(&tmp_path, output, false)?;
                    Ok(())
                }
                WrapType::PublicKey => Err(CliError::Cli(
                    "v2 containers do not support public key recipients".to_string(),
                )),
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

            if private_key.is_some() {
                return Err(CliError::Cli(
                    "v3 containers do not support private key recipients".to_string(),
                ));
            }
            let mode = resolve_mode(recipient_key, None, recipient_password)?;

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

                    let tmp_path = prepare_temp_output(output)?;
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
                    finalize_output(&tmp_path, output, false)?;
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

                    let tmp_path = prepare_temp_output(output)?;
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
                    finalize_output(&tmp_path, output, false)?;
                    Ok(())
                }
                AuthMode::PrivateKey(_) => Err(CliError::Cli(
                    "v3 containers do not support private key recipients".to_string(),
                )),
            }
        }
        ACF_VERSION_V4 => {
            let recipients = match header.crypto.as_ref() {
                Some(CryptoHeader::V4 { recipients, .. }) => recipients,
                _ => return Err(CliError::Format(FormatError::MissingCryptoHeader)),
            };

            let has_key = recipients
                .iter()
                .any(|recipient| recipient.recipient_type == WrapType::Keyfile);
            let has_password = recipients
                .iter()
                .any(|recipient| recipient.recipient_type == WrapType::Password);
            let has_public = recipients
                .iter()
                .any(|recipient| recipient.recipient_type == WrapType::PublicKey);

            let mode = resolve_mode(recipient_key, private_key, recipient_password)?;

            match mode {
                AuthMode::Keyfile(key_path) => {
                    if !has_key {
                        return Err(CliError::Cli(
                            "container expects a password or private key, not a key file"
                                .to_string(),
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

                    let tmp_path = prepare_temp_output(output)?;
                    let mut output_file = File::create(&tmp_path)?;

                    let result = decrypt_container_v4(
                        &mut input_file,
                        &mut output_file,
                        keyfile.key.as_slice(),
                        WrapType::Keyfile,
                    );
                    if result.is_err() {
                        let _ = std::fs::remove_file(&tmp_path);
                    }
                    result?;
                    finalize_output(&tmp_path, output, false)?;
                    Ok(())
                }
                AuthMode::Password => {
                    if !has_password {
                        return Err(CliError::Cli(
                            "container expects a key file or private key, not a password"
                                .to_string(),
                        ));
                    }

                    info!(
                        input = %input.display(),
                        output = %output.display(),
                        "decrypting container"
                    );

                    let password_bytes = read_password(false)?;
                    let mut input_file = File::open(input)?;

                    let tmp_path = prepare_temp_output(output)?;
                    let mut output_file = File::create(&tmp_path)?;

                    let result = decrypt_container_v4(
                        &mut input_file,
                        &mut output_file,
                        password_bytes.as_slice(),
                        WrapType::Password,
                    );
                    if result.is_err() {
                        let _ = std::fs::remove_file(&tmp_path);
                    }
                    result?;
                    finalize_output(&tmp_path, output, false)?;
                    Ok(())
                }
                AuthMode::PrivateKey(key_path) => {
                    if !has_public {
                        return Err(CliError::Cli(
                            "container expects a key file or password, not a private key"
                                .to_string(),
                        ));
                    }

                    info!(
                        input = %input.display(),
                        output = %output.display(),
                        key = %key_path.display(),
                        "decrypting container"
                    );

                    let keyfile = read_private_keyfile(key_path)?;
                    let mut input_file = File::open(input)?;

                    let tmp_path = prepare_temp_output(output)?;
                    let mut output_file = File::create(&tmp_path)?;

                    let result = decrypt_container_v4(
                        &mut input_file,
                        &mut output_file,
                        keyfile.key.as_ref(),
                        WrapType::PublicKey,
                    );
                    if result.is_err() {
                        let _ = std::fs::remove_file(&tmp_path);
                    }
                    result?;
                    finalize_output(&tmp_path, output, false)?;
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

fn ensure_output_path(output: &Path, allow_overwrite: bool) -> Result<(), CliError> {
    if output.exists() {
        if output.is_dir() {
            return Err(CliError::Cli(format!(
                "output path is a directory: {}",
                output.display()
            )));
        }
        if !allow_overwrite {
            return Err(CliError::Cli(format!(
                "output path already exists: {}",
                output.display()
            )));
        }
    }
    Ok(())
}

fn prepare_temp_output(output: &Path) -> Result<PathBuf, CliError> {
    let tmp_path = temp_path_for(output);
    if tmp_path.exists() {
        if tmp_path.is_dir() {
            return Err(CliError::Cli(format!(
                "temporary output path is a directory: {}",
                tmp_path.display()
            )));
        }
        std::fs::remove_file(&tmp_path)?;
    }
    Ok(tmp_path)
}

fn finalize_output(tmp_path: &Path, output: &Path, allow_overwrite: bool) -> Result<(), CliError> {
    if output.exists() {
        if output.is_dir() {
            let _ = std::fs::remove_file(tmp_path);
            return Err(CliError::Cli(format!(
                "output path is a directory: {}",
                output.display()
            )));
        }
        if !allow_overwrite {
            let _ = std::fs::remove_file(tmp_path);
            return Err(CliError::Cli(format!(
                "output path already exists: {}",
                output.display()
            )));
        }
        std::fs::remove_file(output)?;
    }
    match std::fs::rename(tmp_path, output) {
        Ok(()) => Ok(()),
        Err(err) => {
            let _ = std::fs::remove_file(tmp_path);
            Err(CliError::Io(err))
        }
    }
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

fn print_json_inspect(path: &Path, header: &aegis_format::FileHeader) -> Result<(), CliError> {
    let mut out = String::new();
    out.push_str("{\n");
    json_field_str(&mut out, 1, "path", &path.display().to_string(), true);
    json_field_u64(&mut out, 1, "version", header.version as u64, true);
    json_field_u64(&mut out, 1, "header_len", header.header_len as u64, true);
    json_field_u64(&mut out, 1, "flags", header.flags as u64, true);
    json_field_u64(&mut out, 1, "chunk_count", header.chunk_count as u64, true);
    json_field_u64(
        &mut out,
        1,
        "chunk_table_offset",
        header.chunk_table_offset,
        true,
    );
    json_field_u64(&mut out, 1, "footer_offset", header.footer_offset, true);

    if header.version == aegis_format::ACF_VERSION_V0 {
        let mut file = File::open(path)?;
        let parsed = read_container_with_status(&mut file)?;
        json_field_chunks(&mut out, 1, &parsed.chunks, true);
        json_field_checksum(
            &mut out,
            1,
            parsed.footer.checksum_type,
            parsed.footer.checksum,
            parsed.computed_checksum,
            parsed.checksum_valid,
            false,
        );
    } else {
        json_indent(&mut out, 1);
        json_string(&mut out, "encryption");
        out.push_str(": {\n");
        match header.version {
            aegis_format::ACF_VERSION_V1 => {
                if let Some(CryptoHeader::V1 {
                    cipher_id,
                    kdf_id,
                    salt,
                    nonce,
                }) = header.crypto.as_ref()
                {
                    json_field_str(&mut out, 2, "cipher_id", &format!("{cipher_id:?}"), true);
                    json_field_str(&mut out, 2, "kdf_id", &format!("{kdf_id:?}"), true);
                    json_field_u64(&mut out, 2, "salt_len", salt.len() as u64, true);
                    json_field_u64(&mut out, 2, "nonce_len", nonce.len() as u64, true);
                    json_field_bool(&mut out, 2, "payload_encrypted", true, false);
                } else {
                    json_field_bool(&mut out, 2, "missing", true, false);
                }
            }
            ACF_VERSION_V2 => {
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
                    json_field_str(&mut out, 2, "cipher_id", &format!("{cipher_id:?}"), true);
                    json_field_str(&mut out, 2, "kdf_id", &format!("{kdf_id:?}"), true);
                    json_field_kdf_params(&mut out, 2, kdf_params, true);
                    json_field_u64(&mut out, 2, "salt_len", salt.len() as u64, true);
                    json_field_u64(&mut out, 2, "nonce_len", nonce.len() as u64, true);
                    json_field_str(&mut out, 2, "wrap_type", &format!("{wrap_type:?}"), true);
                    json_field_u64(
                        &mut out,
                        2,
                        "wrapped_key_len",
                        wrapped_key.len() as u64,
                        true,
                    );
                    json_field_bool(&mut out, 2, "payload_encrypted", true, false);
                } else {
                    json_field_bool(&mut out, 2, "missing", true, false);
                }
            }
            ACF_VERSION_V3 => {
                if let Some(CryptoHeader::V3 {
                    cipher_id,
                    kdf_id,
                    kdf_params,
                    salt,
                    nonce,
                    recipients,
                }) = header.crypto.as_ref()
                {
                    json_field_str(&mut out, 2, "cipher_id", &format!("{cipher_id:?}"), true);
                    json_field_str(&mut out, 2, "kdf_id", &format!("{kdf_id:?}"), true);
                    json_field_kdf_params(&mut out, 2, kdf_params, true);
                    json_field_u64(&mut out, 2, "salt_len", salt.len() as u64, true);
                    json_field_u64(&mut out, 2, "nonce_len", nonce.len() as u64, true);
                    json_field_recipients(&mut out, 2, recipients, true);
                    json_field_bool(&mut out, 2, "payload_encrypted", true, false);
                } else {
                    json_field_bool(&mut out, 2, "missing", true, false);
                }
            }
            ACF_VERSION_V4 => {
                if let Some(CryptoHeader::V4 {
                    cipher_id,
                    kdf_id,
                    kdf_params,
                    salt,
                    nonce,
                    recipients,
                }) = header.crypto.as_ref()
                {
                    json_field_str(&mut out, 2, "cipher_id", &format!("{cipher_id:?}"), true);
                    json_field_str(&mut out, 2, "kdf_id", &format!("{kdf_id:?}"), true);
                    json_field_kdf_params(&mut out, 2, kdf_params, true);
                    json_field_u64(&mut out, 2, "salt_len", salt.len() as u64, true);
                    json_field_u64(&mut out, 2, "nonce_len", nonce.len() as u64, true);
                    json_field_recipients(&mut out, 2, recipients, true);
                    json_field_bool(&mut out, 2, "payload_encrypted", true, false);
                } else {
                    json_field_bool(&mut out, 2, "missing", true, false);
                }
            }
            _ => {
                json_field_bool(&mut out, 2, "missing", true, false);
            }
        }
        json_indent(&mut out, 1);
        out.push_str("}\n");
    }

    out.push_str("}\n");
    print!("{out}");
    Ok(())
}

fn json_indent(out: &mut String, depth: usize) {
    for _ in 0..depth {
        out.push_str("  ");
    }
}

fn json_string(out: &mut String, value: &str) {
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c <= '\u{1f}' => {
                write!(out, "\\u{:04X}", c as u32).expect("write to string");
            }
            _ => out.push(ch),
        }
    }
    out.push('"');
}

fn json_key(out: &mut String, depth: usize, key: &str) {
    json_indent(out, depth);
    json_string(out, key);
    out.push_str(": ");
}

fn json_field_str(out: &mut String, depth: usize, key: &str, value: &str, trailing_comma: bool) {
    json_key(out, depth, key);
    json_string(out, value);
    if trailing_comma {
        out.push(',');
    }
    out.push('\n');
}

fn json_field_u64(out: &mut String, depth: usize, key: &str, value: u64, trailing_comma: bool) {
    json_key(out, depth, key);
    write!(out, "{value}").expect("write to string");
    if trailing_comma {
        out.push(',');
    }
    out.push('\n');
}

fn json_field_bool(out: &mut String, depth: usize, key: &str, value: bool, trailing_comma: bool) {
    json_key(out, depth, key);
    if value {
        out.push_str("true");
    } else {
        out.push_str("false");
    }
    if trailing_comma {
        out.push(',');
    }
    out.push('\n');
}

fn json_field_kdf_params(
    out: &mut String,
    depth: usize,
    params: &aegis_format::KdfParamsHeader,
    trailing_comma: bool,
) {
    json_key(out, depth, "kdf_params");
    out.push_str("{\n");
    json_field_u64(out, depth + 1, "memory_kib", params.memory_kib as u64, true);
    json_field_u64(out, depth + 1, "iterations", params.iterations as u64, true);
    json_field_u64(
        out,
        depth + 1,
        "parallelism",
        params.parallelism as u64,
        false,
    );
    json_indent(out, depth);
    out.push('}');
    if trailing_comma {
        out.push(',');
    }
    out.push('\n');
}

fn json_field_chunks(
    out: &mut String,
    depth: usize,
    chunks: &[aegis_format::ChunkEntry],
    trailing_comma: bool,
) {
    json_key(out, depth, "chunks");
    out.push_str("[\n");
    for (index, chunk) in chunks.iter().enumerate() {
        json_indent(out, depth + 1);
        out.push_str("{\n");
        json_field_u64(out, depth + 2, "chunk_id", chunk.chunk_id as u64, true);
        json_field_str(
            out,
            depth + 2,
            "chunk_type",
            &format!("{:?}", chunk.chunk_type),
            true,
        );
        json_field_u64(out, depth + 2, "flags", chunk.flags as u64, true);
        json_field_u64(out, depth + 2, "offset", chunk.offset, true);
        json_field_u64(out, depth + 2, "length", chunk.length, false);
        json_indent(out, depth + 1);
        out.push('}');
        if index + 1 < chunks.len() {
            out.push(',');
        }
        out.push('\n');
    }
    json_indent(out, depth);
    out.push(']');
    if trailing_comma {
        out.push(',');
    }
    out.push('\n');
}

fn json_field_checksum(
    out: &mut String,
    depth: usize,
    checksum_type: aegis_format::ChecksumType,
    expected: u32,
    computed: u32,
    valid: bool,
    trailing_comma: bool,
) {
    json_key(out, depth, "checksum");
    out.push_str("{\n");
    json_field_str(out, depth + 1, "type", &format!("{checksum_type:?}"), true);
    json_field_u64(out, depth + 1, "expected", expected as u64, true);
    json_field_u64(out, depth + 1, "computed", computed as u64, true);
    json_field_bool(out, depth + 1, "valid", valid, false);
    json_indent(out, depth);
    out.push('}');
    if trailing_comma {
        out.push(',');
    }
    out.push('\n');
}

fn json_field_recipients(
    out: &mut String,
    depth: usize,
    recipients: &[aegis_format::RecipientEntry],
    trailing_comma: bool,
) {
    json_key(out, depth, "recipients");
    out.push_str("[\n");
    for (index, recipient) in recipients.iter().enumerate() {
        json_indent(out, depth + 1);
        out.push_str("{\n");
        json_field_u64(
            out,
            depth + 2,
            "recipient_id",
            recipient.recipient_id as u64,
            true,
        );
        json_field_str(
            out,
            depth + 2,
            "recipient_type",
            &format!("{:?}", recipient.recipient_type),
            true,
        );
        json_field_str(
            out,
            depth + 2,
            "wrap_alg",
            &format!("{:?}", recipient.wrap_alg),
            true,
        );

        let has_pubkey = recipient.recipient_pubkey.is_some();
        let has_ephemeral = recipient.ephemeral_pubkey.is_some();
        let has_extra = has_pubkey || has_ephemeral;

        json_field_u64(
            out,
            depth + 2,
            "wrapped_key_len",
            recipient.wrapped_key.len() as u64,
            has_extra,
        );

        if let Some(pubkey) = recipient.recipient_pubkey.as_ref() {
            json_field_str(
                out,
                depth + 2,
                "recipient_pubkey",
                &to_hex(pubkey),
                has_ephemeral,
            );
        }
        if let Some(ephemeral) = recipient.ephemeral_pubkey.as_ref() {
            json_field_str(
                out,
                depth + 2,
                "ephemeral_pubkey",
                &to_hex(ephemeral),
                false,
            );
        }

        json_indent(out, depth + 1);
        out.push('}');
        if index + 1 < recipients.len() {
            out.push(',');
        }
        out.push('\n');
    }
    json_indent(out, depth);
    out.push(']');
    if trailing_comma {
        out.push(',');
    }
    out.push('\n');
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

fn print_v4_details(header: &aegis_format::FileHeader) {
    println!("Encryption (v4):");
    if let Some(CryptoHeader::V4 {
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
            if recipient.recipient_type == WrapType::PublicKey {
                let pubkey = recipient
                    .recipient_pubkey
                    .as_ref()
                    .map(|bytes| to_hex(bytes))
                    .unwrap_or_else(|| "<missing>".to_string());
                let ephemeral = recipient
                    .ephemeral_pubkey
                    .as_ref()
                    .map(|bytes| to_hex(bytes))
                    .unwrap_or_else(|| "<missing>".to_string());
                println!(
                    "  - id: {} type: {:?} wrap: {:?} wrapped: {} bytes pubkey: {} eph: {}",
                    recipient.recipient_id,
                    recipient.recipient_type,
                    recipient.wrap_alg,
                    recipient.wrapped_key.len(),
                    pubkey,
                    ephemeral
                );
            } else {
                println!(
                    "  - id: {} type: {:?} wrap: {:?} wrapped: {} bytes",
                    recipient.recipient_id,
                    recipient.recipient_type,
                    recipient.wrap_alg,
                    recipient.wrapped_key.len()
                );
            }
        }
        println!("  Payload: encrypted");
        return;
    }
    println!("  Missing crypto header");
}

fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02X}");
    }
    out
}

#![deny(warnings)]
#![deny(clippy::all)]

use std::fmt::Write;
use std::fs::File;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use aegis_core::crypto::kdf::{
    KdfParams, DEFAULT_KEYFILE_PARAMS, DEFAULT_PASSWORD_PARAMS, KDF_ITERATIONS_MAX,
    KDF_ITERATIONS_MIN, KDF_MEMORY_KIB_MAX, KDF_MEMORY_KIB_MIN, KDF_PARALLELISM_MAX,
    KDF_PARALLELISM_MIN,
};
use aegis_core::crypto::keyfile::{generate_key, read_keyfile, write_keyfile};
use aegis_core::crypto::public_key::{
    generate_keypair, read_private_keyfile, read_public_keyfile, write_private_keyfile,
    write_public_keyfile,
};
use aegis_core::crypto::CryptoError;
use aegis_format::{
    decrypt_container_v1_with_outputs, decrypt_container_v2_with_outputs,
    decrypt_container_v3_with_outputs, decrypt_container_v4_with_outputs, extract_data_chunk,
    read_container, read_container_with_status, read_header, rotate_container_v3,
    rotate_container_v4, write_container, write_encrypted_container_v3,
    write_encrypted_container_v3_with_kdf, write_encrypted_container_v4,
    write_encrypted_container_v4_with_kdf, ChunkType, CryptoHeader, FormatError, ParsedContainer,
    RecipientSpec, WrapType, ACF_VERSION_V2, ACF_VERSION_V3, ACF_VERSION_V4,
};
use clap::{Parser, Subcommand, ValueEnum};
use rpassword::prompt_password;
use sha2::Digest;
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
    #[arg(
        long,
        global = true,
        value_name = "PATH",
        conflicts_with = "password_stdin"
    )]
    password_file: Option<PathBuf>,
    #[arg(long, global = true, conflicts_with = "password_file")]
    password_stdin: bool,
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
        #[arg(
            value_name = "INPUT",
            required_unless_present = "stdin",
            conflicts_with = "stdin"
        )]
        input: Option<PathBuf>,
        #[arg(
            value_name = "OUTPUT",
            required_unless_present = "stdout",
            conflicts_with = "stdout"
        )]
        output: Option<PathBuf>,
        #[arg(long)]
        stdin: bool,
        #[arg(long)]
        stdout: bool,
        #[arg(long)]
        metadata: Option<PathBuf>,
        #[arg(long, conflicts_with = "stdout")]
        force: bool,
    },
    /// Unpack the data chunk from a v0 container
    Unpack {
        #[arg(
            value_name = "INPUT",
            required_unless_present = "stdin",
            conflicts_with = "stdin"
        )]
        input: Option<PathBuf>,
        #[arg(
            value_name = "OUTPUT",
            required_unless_present = "stdout",
            conflicts_with = "stdout"
        )]
        output: Option<PathBuf>,
        #[arg(long)]
        stdin: bool,
        #[arg(long)]
        stdout: bool,
        #[arg(long, conflicts_with = "stdout")]
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
        #[arg(
            value_name = "INPUT",
            required_unless_present = "stdin",
            conflicts_with = "stdin"
        )]
        input: Option<PathBuf>,
        #[arg(
            value_name = "OUTPUT",
            required_unless_present = "stdout",
            conflicts_with = "stdout"
        )]
        output: Option<PathBuf>,
        #[arg(long)]
        stdin: bool,
        #[arg(long)]
        stdout: bool,
        #[arg(long, value_name = "PATH")]
        metadata: Option<PathBuf>,
        #[arg(long = "recipient-key", alias = "key", value_name = "PATH")]
        recipient_keys: Vec<PathBuf>,
        #[arg(long = "recipient-pubkey", value_name = "PATH")]
        recipient_pubkeys: Vec<PathBuf>,
        #[arg(long = "recipient-password", alias = "password")]
        recipient_password: bool,
        #[arg(long, conflicts_with = "stdout")]
        force: bool,
        #[arg(long = "allow-mixed-recipients")]
        allow_mixed_recipients: bool,
        #[arg(long, value_enum, value_name = "PRESET")]
        kdf_preset: Option<KdfPreset>,
        #[arg(long, value_name = "KIB")]
        kdf_memory_kib: Option<u32>,
        #[arg(long, value_name = "COUNT")]
        kdf_iterations: Option<u32>,
        #[arg(long, value_name = "COUNT")]
        kdf_parallelism: Option<u32>,
    },
    /// Decrypt a container payload
    Dec {
        #[arg(
            value_name = "INPUT",
            required_unless_present = "stdin",
            conflicts_with = "stdin"
        )]
        input: Option<PathBuf>,
        #[arg(
            value_name = "OUTPUT",
            required_unless_present = "stdout",
            conflicts_with = "stdout"
        )]
        output: Option<PathBuf>,
        #[arg(long)]
        stdin: bool,
        #[arg(long)]
        stdout: bool,
        #[arg(long, value_name = "PATH")]
        metadata: Option<PathBuf>,
        #[arg(long = "recipient-key", alias = "key", value_name = "PATH")]
        recipient_key: Option<PathBuf>,
        #[arg(long = "private-key", value_name = "PATH")]
        private_key: Option<PathBuf>,
        #[arg(long = "recipient-password", alias = "password")]
        recipient_password: bool,
    },
    /// List recipients in a v3/v4 container
    ListRecipients {
        #[arg(
            value_name = "INPUT",
            required_unless_present = "stdin",
            conflicts_with = "stdin"
        )]
        input: Option<PathBuf>,
        #[arg(long)]
        stdin: bool,
        #[arg(long)]
        json: bool,
    },
    /// Verify a container without writing plaintext
    Verify {
        #[arg(
            value_name = "INPUT",
            required_unless_present = "stdin",
            conflicts_with = "stdin"
        )]
        input: Option<PathBuf>,
        #[arg(long)]
        stdin: bool,
        #[arg(long = "recipient-key", alias = "key", value_name = "PATH")]
        recipient_key: Option<PathBuf>,
        #[arg(long = "private-key", value_name = "PATH")]
        private_key: Option<PathBuf>,
        #[arg(long = "recipient-password", alias = "password")]
        recipient_password: bool,
    },
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

#[derive(Clone, Copy, Debug, ValueEnum)]
enum KdfPreset {
    Keyfile,
    Password,
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

    let password_source =
        match PasswordSource::new(cli.password_file.as_deref(), cli.password_stdin) {
            Ok(source) => source,
            Err(err) => {
                report_error(&err);
                return map_exit_code(&err);
            }
        };

    let result = match cli.command {
        Commands::Inspect { path, json } => cmd_inspect(&path, json),
        Commands::Pack {
            input,
            output,
            stdin,
            stdout,
            metadata,
            force,
        } => cmd_pack(
            input.as_deref(),
            output.as_deref(),
            stdin,
            stdout,
            metadata.as_deref(),
            force,
        ),
        Commands::Unpack {
            input,
            output,
            stdin,
            stdout,
            force,
        } => cmd_unpack(input.as_deref(), output.as_deref(), stdin, stdout, force),
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
            stdin,
            stdout,
            metadata,
            recipient_keys,
            recipient_pubkeys,
            recipient_password,
            force,
            allow_mixed_recipients,
            kdf_preset,
            kdf_memory_kib,
            kdf_iterations,
            kdf_parallelism,
        } => cmd_enc(EncArgs {
            input: input.as_deref(),
            output: output.as_deref(),
            stdin,
            stdout,
            metadata: metadata.as_deref(),
            recipient_keys: &recipient_keys,
            recipient_pubkeys: &recipient_pubkeys,
            recipient_password,
            force,
            allow_mixed_recipients,
            kdf_preset,
            kdf_memory_kib,
            kdf_iterations,
            kdf_parallelism,
            password_source: &password_source,
        }),
        Commands::Dec {
            input,
            output,
            stdin,
            stdout,
            metadata,
            recipient_key,
            private_key,
            recipient_password,
        } => cmd_dec(DecArgs {
            input: input.as_deref(),
            output: output.as_deref(),
            stdin,
            stdout,
            metadata: metadata.as_deref(),
            recipient_key: recipient_key.as_deref(),
            private_key: private_key.as_deref(),
            recipient_password,
            password_source: &password_source,
        }),
        Commands::ListRecipients { input, stdin, json } => {
            cmd_list_recipients(input.as_deref(), stdin, json)
        }
        Commands::Verify {
            input,
            stdin,
            recipient_key,
            private_key,
            recipient_password,
        } => cmd_verify(
            input.as_deref(),
            stdin,
            recipient_key.as_deref(),
            private_key.as_deref(),
            recipient_password,
            &password_source,
        ),
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
            password_source,
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
    input: Option<&Path>,
    output: Option<&Path>,
    stdin: bool,
    stdout: bool,
    metadata: Option<&Path>,
    force: bool,
) -> Result<(), CliError> {
    if stdout && force {
        return Err(CliError::Cli(
            "--stdout cannot be combined with --force".to_string(),
        ));
    }

    let mut temp_input = None;
    let input_path = if stdin {
        let temp = read_stdin_to_temp("pack-input")?;
        let path = temp.path().to_path_buf();
        temp_input = Some(temp);
        path
    } else {
        input
            .ok_or_else(|| CliError::Cli("missing input path".to_string()))?
            .to_path_buf()
    };

    let input_len = std::fs::metadata(&input_path)?.len();
    let input_file = File::open(&input_path)?;

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

    if stdout {
        info!("packing container to stdout");
        let mut out = io::stdout();
        let result = write_container(&mut out, &mut chunks);
        let _written = result?;
        return Ok(());
    }

    let output_path = output.ok_or_else(|| CliError::Cli("missing output path".to_string()))?;
    ensure_output_path(output_path, force)?;
    info!(
        input = %input_path.display(),
        output = %output_path.display(),
        "packing container"
    );

    let tmp_path = prepare_temp_output(output_path)?;
    let mut output_file = File::create(&tmp_path)?;

    let result = write_container(&mut output_file, &mut chunks);
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp_path);
    }
    let _written = result?;
    finalize_output(&tmp_path, output_path, force)?;

    drop(temp_input);
    Ok(())
}

fn cmd_unpack(
    input: Option<&Path>,
    output: Option<&Path>,
    stdin: bool,
    stdout: bool,
    force: bool,
) -> Result<(), CliError> {
    if stdout && force {
        return Err(CliError::Cli(
            "--stdout cannot be combined with --force".to_string(),
        ));
    }

    let mut temp_input = None;
    let input_path = if stdin {
        let temp = read_stdin_to_temp("unpack-input")?;
        let path = temp.path().to_path_buf();
        temp_input = Some(temp);
        path
    } else {
        input
            .ok_or_else(|| CliError::Cli("missing input path".to_string()))?
            .to_path_buf()
    };

    if stdout {
        info!("unpacking container to stdout");
        let mut input_file = File::open(&input_path)?;
        let mut out = io::stdout();
        let _parsed = extract_data_chunk(&mut input_file, &mut out)?;
        drop(temp_input);
        return Ok(());
    }

    let output_path = output.ok_or_else(|| CliError::Cli("missing output path".to_string()))?;
    ensure_output_path(output_path, force)?;
    info!(
        input = %input_path.display(),
        output = %output_path.display(),
        "unpacking container"
    );

    let mut input_file = File::open(&input_path)?;
    let tmp_path = prepare_temp_output(output_path)?;
    let mut output_file = File::create(&tmp_path)?;

    let result = extract_data_chunk(&mut input_file, &mut output_file);
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp_path);
    }
    let _parsed = result?;
    finalize_output(&tmp_path, output_path, force)?;

    drop(temp_input);
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

#[derive(Clone, Copy)]
struct PasswordSource<'a> {
    file: Option<&'a Path>,
    stdin: bool,
}

impl<'a> PasswordSource<'a> {
    fn new(file: Option<&'a Path>, stdin: bool) -> Result<Self, CliError> {
        if file.is_some() && stdin {
            return Err(CliError::Cli(
                "choose only one of --password-file or --password-stdin".to_string(),
            ));
        }
        Ok(Self { file, stdin })
    }
}

struct TempPath {
    path: PathBuf,
}

impl TempPath {
    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempPath {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

fn read_stdin_to_temp(prefix: &str) -> Result<TempPath, CliError> {
    let mut dir = PathBuf::from("target");
    dir.push("aegis-stdin");
    std::fs::create_dir_all(&dir)?;

    let filename = format!("{prefix}-{}.bin", std::process::id());
    let path = dir.join(filename);
    if path.exists() {
        std::fs::remove_file(&path)?;
    }

    let mut file = File::create(&path)?;
    let mut stdin = io::stdin();
    io::copy(&mut stdin, &mut file)?;
    file.sync_all()?;

    Ok(TempPath { path })
}

fn trim_password_bytes(bytes: &mut Vec<u8>) {
    while matches!(bytes.last(), Some(b'\n' | b'\r')) {
        bytes.pop();
    }
}

fn read_password(
    confirm: bool,
    source: &PasswordSource<'_>,
) -> Result<Zeroizing<Vec<u8>>, CliError> {
    if let Some(path) = source.file {
        let mut bytes = std::fs::read(path)?;
        trim_password_bytes(&mut bytes);
        return Ok(Zeroizing::new(bytes));
    }

    if source.stdin {
        let mut bytes = Vec::new();
        io::stdin().read_to_end(&mut bytes)?;
        trim_password_bytes(&mut bytes);
        return Ok(Zeroizing::new(bytes));
    }

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

fn resolve_kdf_params(
    preset: Option<KdfPreset>,
    memory_kib: Option<u32>,
    iterations: Option<u32>,
    parallelism: Option<u32>,
    has_password: bool,
) -> Result<Option<KdfParams>, CliError> {
    let has_override =
        preset.is_some() || memory_kib.is_some() || iterations.is_some() || parallelism.is_some();
    if !has_override {
        return Ok(None);
    }

    if matches!(preset, Some(KdfPreset::Keyfile)) && has_password {
        return Err(CliError::Cli(
            "keyfile KDF preset cannot be used with password recipients".to_string(),
        ));
    }

    let base = match preset {
        Some(KdfPreset::Keyfile) => DEFAULT_KEYFILE_PARAMS,
        Some(KdfPreset::Password) => DEFAULT_PASSWORD_PARAMS,
        None => {
            if has_password {
                DEFAULT_PASSWORD_PARAMS
            } else {
                DEFAULT_KEYFILE_PARAMS
            }
        }
    };

    let params = KdfParams {
        memory_kib: memory_kib.unwrap_or(base.memory_kib),
        iterations: iterations.unwrap_or(base.iterations),
        parallelism: parallelism.unwrap_or(base.parallelism),
        output_len: aegis_core::crypto::aead::AEAD_KEY_LEN,
    };

    validate_kdf_params(&params)?;
    Ok(Some(params))
}

fn validate_kdf_params(params: &KdfParams) -> Result<(), CliError> {
    if params.memory_kib < KDF_MEMORY_KIB_MIN || params.memory_kib > KDF_MEMORY_KIB_MAX {
        return Err(CliError::Cli(format!(
            "kdf memory must be between {KDF_MEMORY_KIB_MIN} and {KDF_MEMORY_KIB_MAX} KiB"
        )));
    }
    if params.iterations < KDF_ITERATIONS_MIN || params.iterations > KDF_ITERATIONS_MAX {
        return Err(CliError::Cli(format!(
            "kdf iterations must be between {KDF_ITERATIONS_MIN} and {KDF_ITERATIONS_MAX}"
        )));
    }
    if params.parallelism < KDF_PARALLELISM_MIN || params.parallelism > KDF_PARALLELISM_MAX {
        return Err(CliError::Cli(format!(
            "kdf parallelism must be between {KDF_PARALLELISM_MIN} and {KDF_PARALLELISM_MAX}"
        )));
    }
    Ok(())
}

struct EncArgs<'a, 'b> {
    input: Option<&'a Path>,
    output: Option<&'a Path>,
    stdin: bool,
    stdout: bool,
    metadata: Option<&'a Path>,
    recipient_keys: &'a [PathBuf],
    recipient_pubkeys: &'a [PathBuf],
    recipient_password: bool,
    force: bool,
    allow_mixed_recipients: bool,
    kdf_preset: Option<KdfPreset>,
    kdf_memory_kib: Option<u32>,
    kdf_iterations: Option<u32>,
    kdf_parallelism: Option<u32>,
    password_source: &'a PasswordSource<'b>,
}

fn cmd_enc(args: EncArgs<'_, '_>) -> Result<(), CliError> {
    let EncArgs {
        input,
        output,
        stdin,
        stdout,
        metadata,
        recipient_keys,
        recipient_pubkeys,
        recipient_password,
        force,
        allow_mixed_recipients,
        kdf_preset,
        kdf_memory_kib,
        kdf_iterations,
        kdf_parallelism,
        password_source,
    } = args;
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

    if stdin && password_source.stdin && recipient_password {
        return Err(CliError::Cli(
            "cannot combine --stdin with --password-stdin".to_string(),
        ));
    }

    if stdout && force {
        return Err(CliError::Cli(
            "--stdout cannot be combined with --force".to_string(),
        ));
    }

    let mut temp_input = None;
    let input_path = if stdin {
        let temp = read_stdin_to_temp("enc-input")?;
        let path = temp.path().to_path_buf();
        temp_input = Some(temp);
        path
    } else {
        input
            .ok_or_else(|| CliError::Cli("missing input path".to_string()))?
            .to_path_buf()
    };

    let input_len = std::fs::metadata(&input_path)?.len();
    let input_file = File::open(&input_path)?;

    let mut chunks = vec![aegis_format::WriteChunkSource {
        chunk_id: 1,
        chunk_type: ChunkType::Data,
        flags: 0,
        length: input_len,
        reader: Box::new(input_file),
    }];

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
        let password_bytes = read_password(true, password_source)?;
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

    let has_password = recipient_password;
    let kdf_params = resolve_kdf_params(
        kdf_preset,
        kdf_memory_kib,
        kdf_iterations,
        kdf_parallelism,
        has_password,
    )?;

    if stdout {
        info!("encrypting container to stdout");
        let mut out = io::stdout();
        if recipient_pubkeys.is_empty() {
            if let Some(params) = kdf_params {
                let _written = write_encrypted_container_v3_with_kdf(
                    &mut out,
                    &mut chunks,
                    &recipients,
                    params,
                )?;
            } else {
                let _written = write_encrypted_container_v3(&mut out, &mut chunks, &recipients)?;
            }
        } else if let Some(params) = kdf_params {
            let _written =
                write_encrypted_container_v4_with_kdf(&mut out, &mut chunks, &recipients, params)?;
        } else {
            let _written = write_encrypted_container_v4(&mut out, &mut chunks, &recipients)?;
        }
        drop(temp_input);
        return Ok(());
    }

    let output_path = output.ok_or_else(|| CliError::Cli("missing output path".to_string()))?;
    ensure_output_path(output_path, force)?;

    info!(
        input = %input_path.display(),
        output = %output_path.display(),
        "encrypting container"
    );

    let tmp_path = prepare_temp_output(output_path)?;
    let mut output_file = File::create(&tmp_path)?;

    if recipient_pubkeys.is_empty() {
        if let Some(params) = kdf_params {
            let _written = write_encrypted_container_v3_with_kdf(
                &mut output_file,
                &mut chunks,
                &recipients,
                params,
            )?;
        } else {
            let _written =
                write_encrypted_container_v3(&mut output_file, &mut chunks, &recipients)?;
        }
    } else if let Some(params) = kdf_params {
        let _written = write_encrypted_container_v4_with_kdf(
            &mut output_file,
            &mut chunks,
            &recipients,
            params,
        )?;
    } else {
        let _written = write_encrypted_container_v4(&mut output_file, &mut chunks, &recipients)?;
    }

    finalize_output(&tmp_path, output_path, force)?;
    drop(temp_input);
    Ok(())
}

fn cmd_list_recipients(input: Option<&Path>, stdin: bool, json: bool) -> Result<(), CliError> {
    let mut temp_input = None;
    let input_path = if stdin {
        let temp = read_stdin_to_temp("list-input")?;
        let path = temp.path().to_path_buf();
        temp_input = Some(temp);
        path
    } else {
        input
            .ok_or_else(|| CliError::Cli("missing input path".to_string()))?
            .to_path_buf()
    };

    let mut file = File::open(&input_path)?;
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

    if json {
        print_json_recipients(&input_path, recipients)?;
        drop(temp_input);
        return Ok(());
    }

    println!("Recipients:");
    for recipient in recipients {
        if recipient.recipient_type == WrapType::PublicKey {
            let pubkey = recipient
                .recipient_pubkey
                .as_ref()
                .map(|bytes| to_hex(bytes))
                .unwrap_or_else(|| "<missing>".to_string());
            let fingerprint = recipient
                .recipient_pubkey
                .as_ref()
                .map(|bytes| fingerprint_short(bytes))
                .unwrap_or_else(|| "<missing>".to_string());
            let ephemeral = recipient
                .ephemeral_pubkey
                .as_ref()
                .map(|bytes| to_hex(bytes))
                .unwrap_or_else(|| "<missing>".to_string());
            println!(
                "  - id: {} type: {:?} wrap: {:?} wrapped: {} bytes pubkey: {} fp: {} eph: {}",
                recipient.recipient_id,
                recipient.recipient_type,
                recipient.wrap_alg,
                recipient.wrapped_key.len(),
                pubkey,
                fingerprint,
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

    drop(temp_input);
    Ok(())
}

fn cmd_verify(
    input: Option<&Path>,
    stdin: bool,
    recipient_key: Option<&Path>,
    private_key: Option<&Path>,
    recipient_password: bool,
    password_source: &PasswordSource<'_>,
) -> Result<(), CliError> {
    if stdin && password_source.stdin && recipient_password {
        return Err(CliError::Cli(
            "cannot combine --stdin with --password-stdin".to_string(),
        ));
    }
    let mut temp_input = None;
    let input_path = if stdin {
        let temp = read_stdin_to_temp("verify-input")?;
        let path = temp.path().to_path_buf();
        temp_input = Some(temp);
        path
    } else {
        input
            .ok_or_else(|| CliError::Cli("missing input path".to_string()))?
            .to_path_buf()
    };

    let mut header_file = File::open(&input_path)?;
    let (header, _) = read_header(&mut header_file)?;

    match header.version {
        aegis_format::ACF_VERSION_V0 => {
            let mut input_file = File::open(&input_path)?;
            let _parsed = read_container(&mut input_file)?;
            drop(temp_input);
            Ok(())
        }
        aegis_format::ACF_VERSION_V1 => {
            if recipient_password || private_key.is_some() {
                return Err(CliError::Cli(
                    "v1 containers require a key file, not a password or private key".to_string(),
                ));
            }
            let key_path = recipient_key.ok_or_else(|| {
                CliError::Cli("missing --recipient-key for v1 container".to_string())
            })?;

            let keyfile = read_keyfile(key_path)?;
            let mut input_file = File::open(&input_path)?;
            decrypt_container_v1_with_outputs(&mut input_file, None, None, keyfile.key.as_slice())?;
            drop(temp_input);
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

                    let keyfile = read_keyfile(key_path)?;
                    let mut input_file = File::open(&input_path)?;
                    decrypt_container_v2_with_outputs(
                        &mut input_file,
                        None,
                        None,
                        keyfile.key.as_slice(),
                        WrapType::Keyfile,
                    )?;
                    drop(temp_input);
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

                    let password_bytes = read_password(false, password_source)?;
                    let mut input_file = File::open(&input_path)?;
                    decrypt_container_v2_with_outputs(
                        &mut input_file,
                        None,
                        None,
                        password_bytes.as_slice(),
                        WrapType::Password,
                    )?;
                    drop(temp_input);
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

                    let keyfile = read_keyfile(key_path)?;
                    let mut input_file = File::open(&input_path)?;
                    decrypt_container_v3_with_outputs(
                        &mut input_file,
                        None,
                        None,
                        keyfile.key.as_slice(),
                        WrapType::Keyfile,
                    )?;
                    drop(temp_input);
                    Ok(())
                }
                AuthMode::Password => {
                    if !has_password {
                        return Err(CliError::Cli(
                            "container expects a key file, not a password".to_string(),
                        ));
                    }

                    let password_bytes = read_password(false, password_source)?;
                    let mut input_file = File::open(&input_path)?;
                    decrypt_container_v3_with_outputs(
                        &mut input_file,
                        None,
                        None,
                        password_bytes.as_slice(),
                        WrapType::Password,
                    )?;
                    drop(temp_input);
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

                    let keyfile = read_keyfile(key_path)?;
                    let mut input_file = File::open(&input_path)?;
                    decrypt_container_v4_with_outputs(
                        &mut input_file,
                        None,
                        None,
                        keyfile.key.as_slice(),
                        WrapType::Keyfile,
                    )?;
                    drop(temp_input);
                    Ok(())
                }
                AuthMode::Password => {
                    if !has_password {
                        return Err(CliError::Cli(
                            "container expects a key file or private key, not a password"
                                .to_string(),
                        ));
                    }

                    let password_bytes = read_password(false, password_source)?;
                    let mut input_file = File::open(&input_path)?;
                    decrypt_container_v4_with_outputs(
                        &mut input_file,
                        None,
                        None,
                        password_bytes.as_slice(),
                        WrapType::Password,
                    )?;
                    drop(temp_input);
                    Ok(())
                }
                AuthMode::PrivateKey(key_path) => {
                    if !has_public {
                        return Err(CliError::Cli(
                            "container expects a key file or password, not a private key"
                                .to_string(),
                        ));
                    }

                    let keyfile = read_private_keyfile(key_path)?;
                    let mut input_file = File::open(&input_path)?;
                    decrypt_container_v4_with_outputs(
                        &mut input_file,
                        None,
                        None,
                        keyfile.key.as_ref(),
                        WrapType::PublicKey,
                    )?;
                    drop(temp_input);
                    Ok(())
                }
            }
        }
        other => Err(CliError::Format(FormatError::UnsupportedVersion(other))),
    }
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
    password_source: PasswordSource<'a>,
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
        password_source,
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

    if password_source.stdin && auth_password && add_recipient_password {
        return Err(CliError::Cli(
            "--password-stdin cannot be used for multiple password prompts".to_string(),
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
                let password_bytes = read_password(true, &password_source)?;
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
                AuthMode::Password => (WrapType::Password, read_password(false, &password_source)?),
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
                let password_bytes = read_password(true, &password_source)?;
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
                AuthMode::Password => (WrapType::Password, read_password(false, &password_source)?),
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

struct DecArgs<'a, 'b> {
    input: Option<&'a Path>,
    output: Option<&'a Path>,
    stdin: bool,
    stdout: bool,
    metadata: Option<&'a Path>,
    recipient_key: Option<&'a Path>,
    private_key: Option<&'a Path>,
    recipient_password: bool,
    password_source: &'a PasswordSource<'b>,
}

fn cmd_dec(args: DecArgs<'_, '_>) -> Result<(), CliError> {
    let DecArgs {
        input,
        output,
        stdin,
        stdout,
        metadata,
        recipient_key,
        private_key,
        recipient_password,
        password_source,
    } = args;
    if stdin && password_source.stdin && recipient_password {
        return Err(CliError::Cli(
            "cannot combine --stdin with --password-stdin".to_string(),
        ));
    }
    let mut temp_input = None;
    let input_path = if stdin {
        let temp = read_stdin_to_temp("dec-input")?;
        let path = temp.path().to_path_buf();
        temp_input = Some(temp);
        path
    } else {
        input
            .ok_or_else(|| CliError::Cli("missing input path".to_string()))?
            .to_path_buf()
    };
    if let (Some(meta_path), Some(out_path)) = (metadata, output) {
        if meta_path == out_path {
            return Err(CliError::Cli(
                "metadata output must be a different path from payload output".to_string(),
            ));
        }
    }
    if let Some(meta_path) = metadata {
        ensure_output_path(meta_path, false)?;
    }
    let mut header_file = File::open(&input_path)?;
    let (header, _) = read_header(&mut header_file)?;
    let mut meta_tmp: Option<(PathBuf, PathBuf)> = None;
    let mut meta_file: Option<File> = None;
    if let Some(meta_path) = metadata {
        let tmp_path = prepare_temp_output(meta_path)?;
        meta_file = Some(File::create(&tmp_path)?);
        meta_tmp = Some((tmp_path, meta_path.to_path_buf()));
    }
    let decrypt_with_outputs =
        |data_out: &mut dyn std::io::Write, meta_out: Option<&mut dyn std::io::Write>| match header
            .version
        {
            aegis_format::ACF_VERSION_V1 => {
                if recipient_password || private_key.is_some() {
                    return Err(CliError::Cli(
                        "v1 containers require a key file, not a password or private key"
                            .to_string(),
                    ));
                }
                let key_path = recipient_key.ok_or_else(|| {
                    CliError::Cli("missing --recipient-key for v1 container".to_string())
                })?;
                let keyfile = read_keyfile(key_path)?;
                let mut input_file = File::open(&input_path)?;
                decrypt_container_v1_with_outputs(
                    &mut input_file,
                    Some(data_out),
                    meta_out,
                    keyfile.key.as_slice(),
                )?;
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
                            CliError::Cli(
                                "missing --recipient-key for keyfile container".to_string(),
                            )
                        })?;
                        let keyfile = read_keyfile(key_path)?;
                        let mut input_file = File::open(&input_path)?;
                        decrypt_container_v2_with_outputs(
                            &mut input_file,
                            Some(data_out),
                            meta_out,
                            keyfile.key.as_slice(),
                            WrapType::Keyfile,
                        )?;
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
                        let password_bytes = read_password(false, password_source)?;
                        let mut input_file = File::open(&input_path)?;
                        decrypt_container_v2_with_outputs(
                            &mut input_file,
                            Some(data_out),
                            meta_out,
                            password_bytes.as_slice(),
                            WrapType::Password,
                        )?;
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
                        let keyfile = read_keyfile(key_path)?;
                        let mut input_file = File::open(&input_path)?;
                        decrypt_container_v3_with_outputs(
                            &mut input_file,
                            Some(data_out),
                            meta_out,
                            keyfile.key.as_slice(),
                            WrapType::Keyfile,
                        )?;
                        Ok(())
                    }
                    AuthMode::Password => {
                        if !has_password {
                            return Err(CliError::Cli(
                                "container expects a key file, not a password".to_string(),
                            ));
                        }
                        let password_bytes = read_password(false, password_source)?;
                        let mut input_file = File::open(&input_path)?;
                        decrypt_container_v3_with_outputs(
                            &mut input_file,
                            Some(data_out),
                            meta_out,
                            password_bytes.as_slice(),
                            WrapType::Password,
                        )?;
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
                        let keyfile = read_keyfile(key_path)?;
                        let mut input_file = File::open(&input_path)?;
                        decrypt_container_v4_with_outputs(
                            &mut input_file,
                            Some(data_out),
                            meta_out,
                            keyfile.key.as_slice(),
                            WrapType::Keyfile,
                        )?;
                        Ok(())
                    }
                    AuthMode::Password => {
                        if !has_password {
                            return Err(CliError::Cli(
                                "container expects a key file or private key, not a password"
                                    .to_string(),
                            ));
                        }
                        let password_bytes = read_password(false, password_source)?;
                        let mut input_file = File::open(&input_path)?;
                        decrypt_container_v4_with_outputs(
                            &mut input_file,
                            Some(data_out),
                            meta_out,
                            password_bytes.as_slice(),
                            WrapType::Password,
                        )?;
                        Ok(())
                    }
                    AuthMode::PrivateKey(key_path) => {
                        if !has_public {
                            return Err(CliError::Cli(
                                "container expects a key file or password, not a private key"
                                    .to_string(),
                            ));
                        }
                        let keyfile = read_private_keyfile(key_path)?;
                        let mut input_file = File::open(&input_path)?;
                        decrypt_container_v4_with_outputs(
                            &mut input_file,
                            Some(data_out),
                            meta_out,
                            keyfile.key.as_ref(),
                            WrapType::PublicKey,
                        )?;
                        Ok(())
                    }
                }
            }
            other => Err(CliError::Format(FormatError::UnsupportedVersion(other))),
        };
    if stdout {
        info!(input = %input_path.display(), "decrypting container to stdout");
        let mut out = io::stdout();
        let result = decrypt_with_outputs(
            &mut out,
            meta_file
                .as_mut()
                .map(|file| file as &mut dyn std::io::Write),
        );
        if result.is_err() {
            if let Some((tmp_path, _)) = meta_tmp {
                let _ = std::fs::remove_file(&tmp_path);
            }
        } else if let Some((tmp_path, meta_path)) = meta_tmp {
            finalize_output(&tmp_path, &meta_path, false)?;
        }
        drop(temp_input);
        return result;
    }
    let output_path = output.ok_or_else(|| CliError::Cli("missing output path".to_string()))?;
    ensure_output_path(output_path, false)?;
    info!(
        input = %input_path.display(),
        output = %output_path.display(),
        "decrypting container"
    );
    let tmp_path = prepare_temp_output(output_path)?;
    let mut output_file = File::create(&tmp_path)?;
    let result = decrypt_with_outputs(
        &mut output_file,
        meta_file
            .as_mut()
            .map(|file| file as &mut dyn std::io::Write),
    );
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp_path);
        if let Some((meta_tmp_path, _)) = meta_tmp {
            let _ = std::fs::remove_file(&meta_tmp_path);
        }
        drop(temp_input);
        return result;
    }
    if let Some((meta_tmp_path, meta_path)) = meta_tmp {
        if let Err(err) = finalize_output(&meta_tmp_path, &meta_path, false) {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(err);
        }
    }
    if let Err(err) = finalize_output(&tmp_path, output_path, false) {
        if let Some(meta_path) = metadata {
            let _ = std::fs::remove_file(meta_path);
        }
        return Err(err);
    }
    drop(temp_input);
    result
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

fn print_json_recipients(
    path: &Path,
    recipients: &[aegis_format::RecipientEntry],
) -> Result<(), CliError> {
    let mut out = String::new();
    out.push_str("{\n");
    json_field_str(&mut out, 1, "path", &path.display().to_string(), true);

    json_key(&mut out, 1, "recipients");
    out.push_str("[\n");
    for (index, recipient) in recipients.iter().enumerate() {
        json_indent(&mut out, 2);
        out.push_str("{\n");
        json_field_u64(
            &mut out,
            3,
            "recipient_id",
            recipient.recipient_id as u64,
            true,
        );
        json_field_str(
            &mut out,
            3,
            "recipient_type",
            &format!("{:?}", recipient.recipient_type),
            true,
        );
        json_field_str(
            &mut out,
            3,
            "wrap_alg",
            &format!("{:?}", recipient.wrap_alg),
            true,
        );
        json_field_u64(
            &mut out,
            3,
            "wrapped_key_len",
            recipient.wrapped_key.len() as u64,
            recipient.recipient_pubkey.is_some() || recipient.ephemeral_pubkey.is_some(),
        );

        if let Some(pubkey) = recipient.recipient_pubkey.as_ref() {
            json_field_str(&mut out, 3, "recipient_pubkey", &to_hex(pubkey), true);
            json_field_str(
                &mut out,
                3,
                "recipient_pubkey_fingerprint",
                &fingerprint_short(pubkey),
                recipient.ephemeral_pubkey.is_some(),
            );
        }
        if let Some(ephemeral) = recipient.ephemeral_pubkey.as_ref() {
            json_field_str(&mut out, 3, "ephemeral_pubkey", &to_hex(ephemeral), false);
        }

        json_indent(&mut out, 2);
        out.push('}');
        if index + 1 < recipients.len() {
            out.push(',');
        }
        out.push('\n');
    }
    json_indent(&mut out, 1);
    out.push_str("]\n");

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

fn fingerprint_short(bytes: &[u8]) -> String {
    let digest = sha2::Sha256::digest(bytes);
    to_hex(&digest[..8])
}

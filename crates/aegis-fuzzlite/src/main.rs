use std::env;
use std::io::{self, Cursor};

use aegis_core::crypto::ids::{CipherId, KdfId};
use aegis_core::crypto::kdf::{
    KDF_ITERATIONS_MAX, KDF_ITERATIONS_MIN, KDF_MEMORY_KIB_MAX, KDF_MEMORY_KIB_MIN,
    KDF_PARALLELISM_MAX,
};
use aegis_core::crypto::public_key::public_key_from_private;
use aegis_format::acf::{encode_header, MAX_HEADER_LEN};
use aegis_format::{
    decrypt_container_v2, decrypt_container_v3, decrypt_container_v4, extract_data_chunk,
    read_container, read_container_with_status, read_header, rotate_container_v3,
    rotate_container_v4, write_container, write_encrypted_container,
    write_encrypted_container_password, write_encrypted_container_v3, write_encrypted_container_v4,
    ChunkType, CryptoHeader, FileHeader, KdfParamsHeader, RecipientEntry, RecipientSpec,
    V2HeaderParams, V3HeaderParams, V4HeaderParams, WrapAlg, WrapType, WriteChunkSource,
    ACF_VERSION_V0, ACF_VERSION_V2, ACF_VERSION_V3, ACF_VERSION_V4, CHUNK_LEN, FILE_MAGIC,
    FOOTER_MAGIC, HEADER_BASE_LEN, MAX_CHUNK_COUNT, MAX_WRAPPED_KEY_LEN, RECIPIENT_ENTRY_BASE_LEN,
    RECIPIENT_EPHEMERAL_KEY_LEN, RECIPIENT_PUBLIC_KEY_LEN,
};

const DEFAULT_ITERS: u64 = 200;
const DEFAULT_MAX_LEN: usize = 4096;
const DEFAULT_SEED: u64 = 0xA5A5_5A5A_1234_5678;
const SEED_DATA_LEN: usize = 64;

fn main() {
    let args: Vec<String> = env::args().collect();
    let iters = parse_arg(&args, "--iters")
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(DEFAULT_ITERS);
    let max_len = parse_arg(&args, "--max-len")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(DEFAULT_MAX_LEN);
    let seed = env::var("AEGIS_FUZZ_SEED")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(DEFAULT_SEED);

    let seeds = build_seeds();
    exercise_valid_seeds(&seeds);
    check_ephemeral_uniqueness();

    let mut rng = XorShift64::new(seed);
    let mut stats = FuzzStats::default();

    for _ in 0..iters {
        let mut case = if rng.next_u64() % 100 < 60 {
            mutate_seed(&mut rng, &seeds, max_len)
        } else {
            random_case(&mut rng, max_len)
        };

        run_case(&mut stats, &mut case);
    }

    println!(
        "fuzz-lite completed: {} iterations (headers ok: {}, containers ok: {}, decrypt ok: {})",
        iters, stats.header_ok, stats.container_ok, stats.decrypt_ok
    );
}

fn parse_arg<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter()
        .position(|arg| arg == name)
        .and_then(|idx| args.get(idx + 1))
        .map(|s| s.as_str())
}

#[derive(Clone)]
struct SeedCase {
    bytes: Vec<u8>,
    key: Option<Vec<u8>>,
    wrap: Option<WrapType>,
}

#[derive(Default)]
struct FuzzStats {
    header_ok: u64,
    container_ok: u64,
    decrypt_ok: u64,
}

struct FuzzCase {
    bytes: Vec<u8>,
    key: [u8; 32],
    wrap: WrapType,
}

fn build_seeds() -> Vec<SeedCase> {
    let mut seeds = Vec::new();

    seeds.push(SeedCase {
        bytes: Vec::new(),
        key: None,
        wrap: None,
    });

    if let Ok(header) = build_header_v0() {
        seeds.push(SeedCase {
            bytes: header,
            key: None,
            wrap: None,
        });
    }

    if let Ok(header) = build_header_v2() {
        seeds.push(SeedCase {
            bytes: header,
            key: None,
            wrap: None,
        });
    }

    if let Ok(header) = build_header_v2_with_wrap(WrapType::Password) {
        seeds.push(SeedCase {
            bytes: header,
            key: None,
            wrap: None,
        });
    }

    if let Ok(header) = build_header_v3() {
        seeds.push(SeedCase {
            bytes: header,
            key: None,
            wrap: None,
        });
    }

    if let Ok(header) = build_header_v4() {
        seeds.push(SeedCase {
            bytes: header,
            key: None,
            wrap: None,
        });
    }

    if let Ok(container) = build_container_v0() {
        seeds.push(SeedCase {
            bytes: container,
            key: None,
            wrap: None,
        });
    }

    if let Ok(container) = build_container_v0_multi() {
        seeds.push(SeedCase {
            bytes: container,
            key: None,
            wrap: None,
        });
    }

    if let Ok((container, key)) = build_container_v2_keyfile() {
        seeds.push(SeedCase {
            bytes: container,
            key: Some(key),
            wrap: Some(WrapType::Keyfile),
        });
    }

    if let Ok((container, key)) = build_container_v2_keyfile_multi() {
        seeds.push(SeedCase {
            bytes: container,
            key: Some(key),
            wrap: Some(WrapType::Keyfile),
        });
    }

    if let Ok((container, password)) = build_container_v2_password() {
        seeds.push(SeedCase {
            bytes: container,
            key: Some(password),
            wrap: Some(WrapType::Password),
        });
    }

    if let Ok((container, password)) = build_container_v2_password_multi() {
        seeds.push(SeedCase {
            bytes: container,
            key: Some(password),
            wrap: Some(WrapType::Password),
        });
    }

    if let Ok((container, key)) = build_container_v3_keyfile() {
        seeds.push(SeedCase {
            bytes: container,
            key: Some(key),
            wrap: Some(WrapType::Keyfile),
        });
    }

    if let Ok((container, password)) = build_container_v3_password() {
        seeds.push(SeedCase {
            bytes: container,
            key: Some(password),
            wrap: Some(WrapType::Password),
        });
    }

    if let Ok((container, key)) = build_container_v3_multi() {
        seeds.push(SeedCase {
            bytes: container,
            key: Some(key),
            wrap: Some(WrapType::Keyfile),
        });
    }

    if let Ok((container, private_key)) = build_container_v4_public() {
        seeds.push(SeedCase {
            bytes: container,
            key: Some(private_key),
            wrap: Some(WrapType::PublicKey),
        });
    }

    if let Ok((container, private_key)) = build_container_v4_mixed() {
        seeds.push(SeedCase {
            bytes: container,
            key: Some(private_key),
            wrap: Some(WrapType::PublicKey),
        });
    }

    seeds
}

fn build_header_v0() -> Result<Vec<u8>, aegis_format::FormatError> {
    let header = FileHeader::new_v0(0, HEADER_BASE_LEN as u64);
    encode_header(&header)
}

fn build_header_v2() -> Result<Vec<u8>, aegis_format::FormatError> {
    build_header_v2_with_wrap(WrapType::Keyfile)
}

fn build_header_v2_with_wrap(wrap_type: WrapType) -> Result<Vec<u8>, aegis_format::FormatError> {
    let kdf_params = match wrap_type {
        WrapType::Keyfile => KdfParamsHeader {
            memory_kib: KDF_MEMORY_KIB_MIN,
            iterations: KDF_ITERATIONS_MIN,
            parallelism: 1,
        },
        WrapType::Password => KdfParamsHeader {
            memory_kib: 128 * 1024,
            iterations: 4,
            parallelism: 1,
        },
        WrapType::PublicKey => {
            return Err(aegis_format::FormatError::UnsupportedWrapType(
                WrapType::PublicKey as u16,
            ))
        }
    };

    let header = FileHeader::new_v2(
        1,
        HEADER_BASE_LEN as u64,
        V2HeaderParams {
            cipher_id: CipherId::XChaCha20Poly1305,
            kdf_id: KdfId::Argon2id,
            kdf_params,
            salt: vec![0x11u8; 16],
            nonce: vec![0x22u8; 20],
            wrap_type,
            wrapped_key: vec![0x33u8; 40],
        },
    )?;
    encode_header(&header)
}

fn build_header_v3() -> Result<Vec<u8>, aegis_format::FormatError> {
    let recipients = vec![
        RecipientEntry {
            recipient_id: 1,
            recipient_type: WrapType::Keyfile,
            wrap_alg: WrapAlg::XChaCha20Poly1305,
            wrapped_key: vec![0x44u8; 40],
            recipient_pubkey: None,
            ephemeral_pubkey: None,
        },
        RecipientEntry {
            recipient_id: 2,
            recipient_type: WrapType::Password,
            wrap_alg: WrapAlg::XChaCha20Poly1305,
            wrapped_key: vec![0x55u8; 40],
            recipient_pubkey: None,
            ephemeral_pubkey: None,
        },
    ];

    let header = FileHeader::new_v3(
        1,
        HEADER_BASE_LEN as u64,
        V3HeaderParams {
            cipher_id: CipherId::XChaCha20Poly1305,
            kdf_id: KdfId::Argon2id,
            kdf_params: KdfParamsHeader {
                memory_kib: 128 * 1024,
                iterations: 4,
                parallelism: 1,
            },
            salt: vec![0x11u8; 16],
            nonce: vec![0x22u8; 20],
            recipients,
        },
    )?;

    encode_header(&header)
}

fn build_header_v4() -> Result<Vec<u8>, aegis_format::FormatError> {
    let recipient_pubkey = [0x44u8; RECIPIENT_PUBLIC_KEY_LEN];
    let ephemeral_pubkey = [0x55u8; RECIPIENT_EPHEMERAL_KEY_LEN];
    let recipients = vec![RecipientEntry {
        recipient_id: 1,
        recipient_type: WrapType::PublicKey,
        wrap_alg: WrapAlg::XChaCha20Poly1305,
        wrapped_key: vec![0x66u8; 40],
        recipient_pubkey: Some(recipient_pubkey),
        ephemeral_pubkey: Some(ephemeral_pubkey),
    }];

    let header = FileHeader::new_v4(
        1,
        HEADER_BASE_LEN as u64,
        V4HeaderParams {
            cipher_id: CipherId::XChaCha20Poly1305,
            kdf_id: KdfId::Argon2id,
            kdf_params: KdfParamsHeader {
                memory_kib: 128 * 1024,
                iterations: 4,
                parallelism: 1,
            },
            salt: vec![0x11u8; 16],
            nonce: vec![0x22u8; 20],
            recipients,
        },
    )?;

    encode_header(&header)
}

fn build_container_v0() -> Result<Vec<u8>, aegis_format::FormatError> {
    let data = vec![0xABu8; SEED_DATA_LEN];
    let mut chunks = make_chunks(vec![(ChunkType::Data, data)]);
    let mut out = Vec::new();
    write_container(&mut out, &mut chunks)?;
    Ok(out)
}

fn build_container_v0_multi() -> Result<Vec<u8>, aegis_format::FormatError> {
    let data = vec![0xABu8; SEED_DATA_LEN];
    let meta = vec![0xBCu8; SEED_DATA_LEN / 2];
    let mut chunks = make_chunks(vec![(ChunkType::Data, data), (ChunkType::Metadata, meta)]);
    let mut out = Vec::new();
    write_container(&mut out, &mut chunks)?;
    Ok(out)
}

fn build_container_v2_keyfile() -> Result<(Vec<u8>, Vec<u8>), aegis_format::FormatError> {
    let data = vec![0xCDu8; SEED_DATA_LEN];
    let mut chunks = make_chunks(vec![(ChunkType::Data, data)]);
    let key = vec![0x44u8; 32];
    let mut out = Vec::new();
    write_encrypted_container(&mut out, &mut chunks, &key)?;
    Ok((out, key))
}

fn build_container_v2_keyfile_multi() -> Result<(Vec<u8>, Vec<u8>), aegis_format::FormatError> {
    let data = vec![0xCDu8; SEED_DATA_LEN];
    let meta = vec![0xCEu8; SEED_DATA_LEN / 2];
    let mut chunks = make_chunks(vec![(ChunkType::Data, data), (ChunkType::Metadata, meta)]);
    let key = vec![0x44u8; 32];
    let mut out = Vec::new();
    write_encrypted_container(&mut out, &mut chunks, &key)?;
    Ok((out, key))
}

fn build_container_v2_password() -> Result<(Vec<u8>, Vec<u8>), aegis_format::FormatError> {
    let data = vec![0xEFu8; SEED_DATA_LEN];
    let mut chunks = make_chunks(vec![(ChunkType::Data, data)]);
    let password = b"fuzz-pass".to_vec();
    let mut out = Vec::new();
    write_encrypted_container_password(&mut out, &mut chunks, &password)?;
    Ok((out, password))
}

fn build_container_v2_password_multi() -> Result<(Vec<u8>, Vec<u8>), aegis_format::FormatError> {
    let data = vec![0xEFu8; SEED_DATA_LEN];
    let meta = vec![0xF0u8; SEED_DATA_LEN / 2];
    let mut chunks = make_chunks(vec![(ChunkType::Data, data), (ChunkType::Metadata, meta)]);
    let password = b"fuzz-pass".to_vec();
    let mut out = Vec::new();
    write_encrypted_container_password(&mut out, &mut chunks, &password)?;
    Ok((out, password))
}

fn build_container_v3_keyfile() -> Result<(Vec<u8>, Vec<u8>), aegis_format::FormatError> {
    let data = vec![0x1Au8; SEED_DATA_LEN];
    let mut chunks = make_chunks(vec![(ChunkType::Data, data)]);
    let key = vec![0x2Bu8; 32];
    let recipients = vec![RecipientSpec {
        recipient_id: 1,
        recipient_type: WrapType::Keyfile,
        key_material: Some(&key),
        public_key: None,
    }];
    let mut out = Vec::new();
    write_encrypted_container_v3(&mut out, &mut chunks, &recipients)?;
    Ok((out, key))
}

fn build_container_v3_password() -> Result<(Vec<u8>, Vec<u8>), aegis_format::FormatError> {
    let data = vec![0x3Cu8; SEED_DATA_LEN];
    let mut chunks = make_chunks(vec![(ChunkType::Data, data)]);
    let password = b"fuzz-pass-v3".to_vec();
    let recipients = vec![RecipientSpec {
        recipient_id: 2,
        recipient_type: WrapType::Password,
        key_material: Some(&password),
        public_key: None,
    }];
    let mut out = Vec::new();
    write_encrypted_container_v3(&mut out, &mut chunks, &recipients)?;
    Ok((out, password))
}

fn build_container_v3_multi() -> Result<(Vec<u8>, Vec<u8>), aegis_format::FormatError> {
    let data = vec![0x4Du8; SEED_DATA_LEN];
    let meta = vec![0x5Eu8; SEED_DATA_LEN / 2];
    let mut chunks = make_chunks(vec![(ChunkType::Data, data), (ChunkType::Metadata, meta)]);
    let key = vec![0x6Fu8; 32];
    let password = b"fuzz-multi".to_vec();
    let recipients = vec![
        RecipientSpec {
            recipient_id: 10,
            recipient_type: WrapType::Keyfile,
            key_material: Some(&key),
            public_key: None,
        },
        RecipientSpec {
            recipient_id: 11,
            recipient_type: WrapType::Password,
            key_material: Some(&password),
            public_key: None,
        },
    ];
    let mut out = Vec::new();
    write_encrypted_container_v3(&mut out, &mut chunks, &recipients)?;
    Ok((out, key))
}

fn build_container_v4_public() -> Result<(Vec<u8>, Vec<u8>), aegis_format::FormatError> {
    let data = vec![0x6Au8; SEED_DATA_LEN];
    let mut chunks = make_chunks(vec![(ChunkType::Data, data)]);
    let private_key = [0x11u8; 32];
    let public_key = public_key_from_private(&private_key);
    let recipients = vec![RecipientSpec {
        recipient_id: 1,
        recipient_type: WrapType::PublicKey,
        key_material: None,
        public_key: Some(public_key),
    }];
    let mut out = Vec::new();
    write_encrypted_container_v4(&mut out, &mut chunks, &recipients)?;
    Ok((out, private_key.to_vec()))
}

fn build_container_v4_mixed() -> Result<(Vec<u8>, Vec<u8>), aegis_format::FormatError> {
    let data = vec![0x7Bu8; SEED_DATA_LEN];
    let mut chunks = make_chunks(vec![(ChunkType::Data, data)]);
    let private_key = [0x22u8; 32];
    let public_key = public_key_from_private(&private_key);
    let keyfile = vec![0x33u8; 32];
    let password = b"fuzz-v4-mixed".to_vec();
    let recipients = vec![
        RecipientSpec {
            recipient_id: 1,
            recipient_type: WrapType::Keyfile,
            key_material: Some(&keyfile),
            public_key: None,
        },
        RecipientSpec {
            recipient_id: 2,
            recipient_type: WrapType::Password,
            key_material: Some(&password),
            public_key: None,
        },
        RecipientSpec {
            recipient_id: 3,
            recipient_type: WrapType::PublicKey,
            key_material: None,
            public_key: Some(public_key),
        },
    ];
    let mut out = Vec::new();
    write_encrypted_container_v4(&mut out, &mut chunks, &recipients)?;
    Ok((out, private_key.to_vec()))
}

fn make_chunks(payloads: Vec<(ChunkType, Vec<u8>)>) -> Vec<WriteChunkSource> {
    payloads
        .into_iter()
        .enumerate()
        .map(|(idx, (chunk_type, data))| WriteChunkSource {
            chunk_id: (idx as u32) + 1,
            chunk_type,
            flags: 0,
            length: data.len() as u64,
            reader: Box::new(Cursor::new(data)),
        })
        .collect()
}

fn exercise_valid_seeds(seeds: &[SeedCase]) {
    for seed in seeds {
        let _ = read_header(&mut Cursor::new(&seed.bytes));
        let _ = read_container(&mut Cursor::new(&seed.bytes));
        let _ = read_container_with_status(&mut Cursor::new(&seed.bytes));
        if let (Some(key), Some(wrap)) = (seed.key.as_ref(), seed.wrap) {
            let mut cursor = Cursor::new(&seed.bytes);
            let mut sink = io::sink();
            let _ = decrypt_container_v2(&mut cursor, &mut sink, key.as_slice(), wrap);
            let mut cursor = Cursor::new(&seed.bytes);
            let _ = decrypt_container_v3(&mut cursor, &mut sink, key.as_slice(), wrap);
            let mut cursor = Cursor::new(&seed.bytes);
            let _ = decrypt_container_v4(&mut cursor, &mut sink, key.as_slice(), wrap);
        }
    }
}

fn check_ephemeral_uniqueness() {
    let private_key = [0xA5u8; 32];
    let public_key = public_key_from_private(&private_key);
    let recipients = vec![RecipientSpec {
        recipient_id: 1,
        recipient_type: WrapType::PublicKey,
        key_material: None,
        public_key: Some(public_key),
    }];
    let mut chunks = make_chunks(vec![(ChunkType::Data, vec![0xABu8; 16])]);

    let mut container_a = Vec::new();
    write_encrypted_container_v4(&mut container_a, &mut chunks, &recipients).expect("v4 encrypt a");

    let mut chunks = make_chunks(vec![(ChunkType::Data, vec![0xABu8; 16])]);
    let mut container_b = Vec::new();
    write_encrypted_container_v4(&mut container_b, &mut chunks, &recipients).expect("v4 encrypt b");

    let (header_a, _) = read_header(&mut Cursor::new(&container_a)).expect("header a");
    let (header_b, _) = read_header(&mut Cursor::new(&container_b)).expect("header b");

    let eph_a = match header_a.crypto.as_ref() {
        Some(CryptoHeader::V4 { recipients, .. }) => recipients
            .first()
            .and_then(|recipient| recipient.ephemeral_pubkey),
        _ => None,
    };
    let eph_b = match header_b.crypto.as_ref() {
        Some(CryptoHeader::V4 { recipients, .. }) => recipients
            .first()
            .and_then(|recipient| recipient.ephemeral_pubkey),
        _ => None,
    };

    if eph_a.is_some() && eph_a == eph_b {
        eprintln!("fuzz-lite: repeated ephemeral public key detected");
        std::process::exit(1);
    }
}

fn mutate_seed(rng: &mut XorShift64, seeds: &[SeedCase], max_len: usize) -> FuzzCase {
    let seed = &seeds[(rng.next_u64() as usize) % seeds.len()];
    let mut bytes = seed.bytes.clone();
    mutate_bytes(rng, &mut bytes, max_len);
    if rng.next_u64() % 100 < 30 {
        splice_with_seed(rng, &mut bytes, seeds, max_len);
    }
    let mut key = [0u8; 32];
    if let Some(seed_key) = seed.key.as_ref() {
        let to_copy = std::cmp::min(seed_key.len(), key.len());
        key[..to_copy].copy_from_slice(&seed_key[..to_copy]);
    } else {
        rng.fill_bytes(&mut key);
    }
    let wrap = seed.wrap.unwrap_or(WrapType::Keyfile);
    FuzzCase { bytes, key, wrap }
}

fn random_case(rng: &mut XorShift64, max_len: usize) -> FuzzCase {
    let len = (rng.next_u64() as usize) % (max_len + 1);
    let mut bytes = vec![0u8; len];
    rng.fill_bytes(&mut bytes);
    if bytes.len() >= HEADER_BASE_LEN && rng.next_u64() % 4 == 0 {
        bytes[0..8].copy_from_slice(&FILE_MAGIC);
        let version = match rng.next_u64() % 4 {
            0 => ACF_VERSION_V0,
            1 => ACF_VERSION_V2,
            2 => ACF_VERSION_V3,
            _ => ACF_VERSION_V4,
        };
        bytes[8..10].copy_from_slice(&version.to_le_bytes());
        let header_len = if rng.next_u64() % 2 == 0 {
            HEADER_BASE_LEN as u16
        } else {
            MAX_HEADER_LEN as u16
        };
        bytes[10..12].copy_from_slice(&header_len.to_le_bytes());
    }
    mutate_bytes(rng, &mut bytes, max_len);
    let mut key = [0u8; 32];
    rng.fill_bytes(&mut key);
    FuzzCase {
        bytes,
        key,
        wrap: match rng.next_u64() % 3 {
            0 => WrapType::Keyfile,
            1 => WrapType::Password,
            _ => WrapType::PublicKey,
        },
    }
}

fn run_case(stats: &mut FuzzStats, case: &mut FuzzCase) {
    let header_result = aegis_format::acf::parse_header(&case.bytes);
    if header_result.is_ok() {
        stats.header_ok += 1;
    }
    if let Ok(header) = header_result {
        if header.version == ACF_VERSION_V0 {
            let _ = read_container_with_status(&mut Cursor::new(&case.bytes));
            let _ = extract_data_chunk(&mut Cursor::new(&case.bytes), &mut io::sink());
        } else if header.version == ACF_VERSION_V3 {
            let add_spec = RecipientSpec {
                recipient_id: 999,
                recipient_type: case.wrap,
                key_material: Some(&case.key),
                public_key: None,
            };
            let _ = rotate_container_v3(
                &mut Cursor::new(&case.bytes),
                &mut io::sink(),
                &case.key,
                case.wrap,
                std::slice::from_ref(&add_spec),
                &[0u32],
            );
        } else if header.version == ACF_VERSION_V4 {
            let add_spec = RecipientSpec {
                recipient_id: 999,
                recipient_type: case.wrap,
                key_material: Some(&case.key),
                public_key: None,
            };
            let _ = rotate_container_v4(
                &mut Cursor::new(&case.bytes),
                &mut io::sink(),
                &case.key,
                case.wrap,
                std::slice::from_ref(&add_spec),
                &[0u32],
            );
        }
    }
    if read_container(&mut Cursor::new(&case.bytes)).is_ok() {
        stats.container_ok += 1;
    }
    let _ = read_header(&mut Cursor::new(&case.bytes));
    let mut decrypt_ok = decrypt_container_v2(
        &mut Cursor::new(&case.bytes),
        &mut io::sink(),
        &case.key,
        case.wrap,
    )
    .is_ok();

    if !decrypt_ok {
        decrypt_ok = decrypt_container_v3(
            &mut Cursor::new(&case.bytes),
            &mut io::sink(),
            &case.key,
            case.wrap,
        )
        .is_ok();
    }

    if !decrypt_ok {
        decrypt_ok = decrypt_container_v4(
            &mut Cursor::new(&case.bytes),
            &mut io::sink(),
            &case.key,
            case.wrap,
        )
        .is_ok();
    }

    if decrypt_ok {
        stats.decrypt_ok += 1;
    }
}

fn mutate_bytes(rng: &mut XorShift64, bytes: &mut Vec<u8>, max_len: usize) {
    if bytes.is_empty() && max_len > 0 {
        bytes.push(0);
    }

    let mutations = 1 + (rng.next_u64() % 8) as usize;
    for _ in 0..mutations {
        match rng.next_u64() % 11 {
            0 => flip_byte(rng, bytes),
            1 => insert_byte(rng, bytes, max_len),
            2 => delete_byte(rng, bytes),
            3 => truncate_bytes(rng, bytes),
            4 => overwrite_range(rng, bytes),
            5 => structured_header_tweak(rng, bytes),
            6 => duplicate_range(rng, bytes, max_len),
            7 => structured_chunk_tweak(rng, bytes),
            8 => structured_crypto_tweak(rng, bytes),
            9 => structured_footer_tweak(rng, bytes),
            _ => swap_ranges(rng, bytes),
        }
    }
}

fn flip_byte(rng: &mut XorShift64, bytes: &mut [u8]) {
    if bytes.is_empty() {
        return;
    }
    let idx = (rng.next_u64() as usize) % bytes.len();
    bytes[idx] ^= (rng.next_u64() as u8) | 1;
}

fn insert_byte(rng: &mut XorShift64, bytes: &mut Vec<u8>, max_len: usize) {
    if bytes.len() >= max_len {
        return;
    }
    let idx = (rng.next_u64() as usize) % (bytes.len() + 1);
    let value = rng.next_u64() as u8;
    bytes.insert(idx, value);
}

fn delete_byte(rng: &mut XorShift64, bytes: &mut Vec<u8>) {
    if bytes.is_empty() {
        return;
    }
    let idx = (rng.next_u64() as usize) % bytes.len();
    bytes.remove(idx);
}

fn truncate_bytes(rng: &mut XorShift64, bytes: &mut Vec<u8>) {
    if bytes.is_empty() {
        return;
    }
    let new_len = (rng.next_u64() as usize) % (bytes.len() + 1);
    bytes.truncate(new_len);
}

fn overwrite_range(rng: &mut XorShift64, bytes: &mut [u8]) {
    if bytes.is_empty() {
        return;
    }
    let start = (rng.next_u64() as usize) % bytes.len();
    let len = ((rng.next_u64() as usize) % 8).max(1);
    for i in 0..len {
        if start + i >= bytes.len() {
            break;
        }
        bytes[start + i] = rng.next_u64() as u8;
    }
}

fn duplicate_range(rng: &mut XorShift64, bytes: &mut Vec<u8>, max_len: usize) {
    if bytes.is_empty() || bytes.len() >= max_len {
        return;
    }
    let start = (rng.next_u64() as usize) % bytes.len();
    let len = ((rng.next_u64() as usize) % 16).max(1);
    let end = std::cmp::min(start + len, bytes.len());
    let slice = bytes[start..end].to_vec();
    let insert_at = std::cmp::min(bytes.len(), start);
    let remaining = max_len - bytes.len();
    let to_insert = std::cmp::min(slice.len(), remaining);
    bytes.splice(insert_at..insert_at, slice.into_iter().take(to_insert));
}

fn structured_header_tweak(rng: &mut XorShift64, bytes: &mut [u8]) {
    if bytes.len() < HEADER_BASE_LEN {
        return;
    }
    let choice = rng.next_u64() % 8;
    match choice {
        0 => {
            bytes[0..8].copy_from_slice(&FILE_MAGIC);
        }
        1 => {
            let version = match rng.next_u64() % 4 {
                0 => ACF_VERSION_V0,
                1 => ACF_VERSION_V2,
                2 => ACF_VERSION_V3,
                _ => ACF_VERSION_V4,
            };
            write_u16(bytes, 8, version);
        }
        2 => {
            let header_len = match rng.next_u64() % 4 {
                0 => HEADER_BASE_LEN as u16,
                1 => MAX_HEADER_LEN as u16,
                2 => HEADER_BASE_LEN.saturating_add(1) as u16,
                _ => rng.next_u64() as u16,
            };
            write_u16(bytes, 10, header_len);
        }
        3 => {
            let flags = rng.next_u64() as u32;
            write_u32(bytes, 12, flags);
        }
        4 => {
            let chunk_count = match rng.next_u64() % 4 {
                0 => 0,
                1 => 1,
                2 => MAX_CHUNK_COUNT,
                _ => MAX_CHUNK_COUNT.saturating_add(1),
            };
            write_u32(bytes, 16, chunk_count);
        }
        5 => {
            let header_len = read_u16(bytes, 10).unwrap_or(HEADER_BASE_LEN as u16);
            let offset = if rng.next_u64() % 2 == 0 {
                header_len as u64
            } else {
                rng.next_u64()
            };
            write_u64(bytes, 20, offset);
        }
        6 => {
            let offset = rng.next_u64();
            write_u64(bytes, 28, offset);
        }
        _ => {
            let version = rng.next_u64() as u16;
            write_u16(bytes, 8, version);
        }
    }
}

fn structured_chunk_tweak(rng: &mut XorShift64, bytes: &mut [u8]) {
    if bytes.len() < HEADER_BASE_LEN + CHUNK_LEN {
        return;
    }

    let chunk_count = read_u32(bytes, 16).unwrap_or(0);
    let table_offset = read_u64(bytes, 20).unwrap_or(HEADER_BASE_LEN as u64);
    let table_offset = match usize::try_from(table_offset) {
        Ok(offset) => offset,
        Err(_) => return,
    };
    if table_offset >= bytes.len() {
        return;
    }

    let available = bytes.len().saturating_sub(table_offset);
    let max_entries = available / CHUNK_LEN;
    if max_entries == 0 {
        return;
    }

    let entry_count = std::cmp::min(chunk_count as usize, max_entries);
    if entry_count == 0 {
        return;
    }

    let idx = (rng.next_u64() as usize) % entry_count;
    let entry_offset = table_offset + idx * CHUNK_LEN;
    if entry_offset + CHUNK_LEN > bytes.len() {
        return;
    }

    match rng.next_u64() % 5 {
        0 => {
            let chunk_id = rng.next_u64() as u32;
            write_u32(bytes, entry_offset, chunk_id);
        }
        1 => {
            let chunk_type = if rng.next_u64() % 2 == 0 {
                0x0001
            } else {
                0xBEEF
            };
            write_u16(bytes, entry_offset + 4, chunk_type);
        }
        2 => {
            let flags = rng.next_u64() as u16;
            write_u16(bytes, entry_offset + 6, flags);
        }
        3 => {
            let offset = if rng.next_u64() % 2 == 0 {
                HEADER_BASE_LEN as u64
            } else {
                rng.next_u64()
            };
            write_u64(bytes, entry_offset + 8, offset);
        }
        _ => {
            let length = rng.next_u64();
            write_u64(bytes, entry_offset + 16, length);
        }
    }
}

fn structured_crypto_tweak(rng: &mut XorShift64, bytes: &mut [u8]) {
    if bytes.len() < HEADER_BASE_LEN + 2 + 2 + 4 + 4 + 4 + 2 {
        return;
    }
    let version = read_u16(bytes, 8).unwrap_or(0);
    if version == ACF_VERSION_V2 {
        let header_len = read_u16(bytes, 10).unwrap_or(HEADER_BASE_LEN as u16) as usize;
        let header_len = std::cmp::min(header_len, bytes.len());

        let mut cursor = HEADER_BASE_LEN;
        let cipher_id_offset = cursor;
        cursor += 2;
        let kdf_id_offset = cursor;
        cursor += 2;
        let memory_offset = cursor;
        cursor += 4;
        let iterations_offset = cursor;
        cursor += 4;
        let parallelism_offset = cursor;
        cursor += 4;
        if cursor + 2 > header_len {
            return;
        }
        let salt_len_offset = cursor;
        let salt_len = read_u16(bytes, salt_len_offset).unwrap_or(0) as usize;
        cursor += 2;
        let salt_end = cursor.saturating_add(salt_len);
        if salt_end + 2 > header_len {
            return;
        }
        let nonce_len_offset = salt_end;
        let nonce_len = read_u16(bytes, nonce_len_offset).unwrap_or(0) as usize;
        let nonce_start = nonce_len_offset + 2;
        let nonce_end = nonce_start.saturating_add(nonce_len);
        if nonce_end + 4 > header_len {
            return;
        }
        let wrap_type_offset = nonce_end;
        let wrapped_len_offset = wrap_type_offset + 2;

        match rng.next_u64() % 8 {
            0 => write_u16(bytes, cipher_id_offset, rng.next_u64() as u16),
            1 => write_u16(bytes, kdf_id_offset, rng.next_u64() as u16),
            2 => write_u32(bytes, memory_offset, KDF_MEMORY_KIB_MAX),
            3 => write_u32(bytes, iterations_offset, KDF_ITERATIONS_MAX),
            4 => write_u32(bytes, parallelism_offset, KDF_PARALLELISM_MAX),
            5 => {
                let salt_len = if rng.next_u64() % 2 == 0 { 0 } else { 512 };
                write_u16(bytes, salt_len_offset, salt_len);
            }
            6 => {
                let wrap_type = if rng.next_u64() % 2 == 0 {
                    0x0001
                } else {
                    0xDEAD
                };
                write_u16(bytes, wrap_type_offset, wrap_type);
            }
            _ => {
                let wrapped_len = if rng.next_u64() % 2 == 0 {
                    0
                } else {
                    (MAX_WRAPPED_KEY_LEN as u16).saturating_add(1)
                };
                write_u16(bytes, wrapped_len_offset, wrapped_len);
            }
        }
        return;
    }

    if version != ACF_VERSION_V3 && version != ACF_VERSION_V4 {
        return;
    }

    let header_len = read_u16(bytes, 10).unwrap_or(HEADER_BASE_LEN as u16) as usize;
    let header_len = std::cmp::min(header_len, bytes.len());

    let mut cursor = HEADER_BASE_LEN;
    let cipher_id_offset = cursor;
    cursor += 2;
    let kdf_id_offset = cursor;
    cursor += 2;
    let memory_offset = cursor;
    cursor += 4;
    let iterations_offset = cursor;
    cursor += 4;
    let parallelism_offset = cursor;
    cursor += 4;
    if cursor + 2 > header_len {
        return;
    }
    let salt_len_offset = cursor;
    let salt_len = read_u16(bytes, salt_len_offset).unwrap_or(0) as usize;
    cursor += 2;
    let salt_end = cursor.saturating_add(salt_len);
    if salt_end + 2 > header_len {
        return;
    }
    let nonce_len_offset = salt_end;
    let nonce_len = read_u16(bytes, nonce_len_offset).unwrap_or(0) as usize;
    let nonce_start = nonce_len_offset + 2;
    let nonce_end = nonce_start.saturating_add(nonce_len);
    if nonce_end + 2 > header_len {
        return;
    }
    let recipient_count_offset = nonce_end;
    let _recipient_count = read_u16(bytes, recipient_count_offset).unwrap_or(0) as usize;
    let first_entry_offset = recipient_count_offset + 2;

    let mut first_entry = None;
    if first_entry_offset + RECIPIENT_ENTRY_BASE_LEN <= header_len {
        let recipient_type = read_u16(bytes, first_entry_offset + 4).unwrap_or(0);
        let extra = if version == ACF_VERSION_V4 && recipient_type == WrapType::PublicKey as u16 {
            RECIPIENT_PUBLIC_KEY_LEN + RECIPIENT_EPHEMERAL_KEY_LEN
        } else {
            0
        };
        let wrap_len_offset = first_entry_offset + 8 + extra;
        let wrap_len = read_u32(bytes, wrap_len_offset).unwrap_or(0) as usize;
        first_entry = Some((first_entry_offset, wrap_len, extra));
    }

    let mut second_entry_offset = None;
    if let Some((entry_offset, wrap_len, extra)) = first_entry {
        let next = entry_offset + RECIPIENT_ENTRY_BASE_LEN + extra + wrap_len;
        if next + 4 <= header_len {
            second_entry_offset = Some(next);
        }
    }

    let max_case = if version == ACF_VERSION_V4 { 12 } else { 10 };
    match rng.next_u64() % max_case {
        0 => write_u16(bytes, cipher_id_offset, rng.next_u64() as u16),
        1 => write_u16(bytes, kdf_id_offset, rng.next_u64() as u16),
        2 => write_u32(bytes, memory_offset, KDF_MEMORY_KIB_MAX),
        3 => write_u32(bytes, iterations_offset, KDF_ITERATIONS_MAX),
        4 => write_u32(bytes, parallelism_offset, KDF_PARALLELISM_MAX),
        5 => {
            let salt_len = if rng.next_u64() % 2 == 0 { 0 } else { 512 };
            write_u16(bytes, salt_len_offset, salt_len);
        }
        6 => {
            let count = if rng.next_u64() % 2 == 0 { 0 } else { 0xFFFF };
            write_u16(bytes, recipient_count_offset, count);
        }
        7 => {
            if let Some((entry_offset, _, _)) = first_entry {
                let wrap_alg_offset = entry_offset + 6;
                write_u16(bytes, wrap_alg_offset, 0xDEAD);
            }
        }
        8 => {
            if let Some((entry_offset, _, extra)) = first_entry {
                let wrap_len_offset = entry_offset + 8 + extra;
                let wrapped_len = if rng.next_u64() % 2 == 0 {
                    0
                } else {
                    (MAX_WRAPPED_KEY_LEN as u32).saturating_add(1)
                };
                write_u32(bytes, wrap_len_offset, wrapped_len);
            }
        }
        9 => {
            if let (Some((entry_offset, _, _)), Some(second_offset)) =
                (first_entry, second_entry_offset)
            {
                let id = read_u32(bytes, entry_offset).unwrap_or(0);
                write_u32(bytes, second_offset, id);
            }
        }
        10 => {
            if version == ACF_VERSION_V4 {
                if let Some((entry_offset, _, extra)) = first_entry {
                    if extra > 0 {
                        let pubkey_offset = entry_offset + 8;
                        write_u32(bytes, pubkey_offset, rng.next_u64() as u32);
                    }
                }
            }
        }
        _ => {
            if version == ACF_VERSION_V4 {
                if let Some((entry_offset, _, extra)) = first_entry {
                    if extra > 0 {
                        let eph_offset = entry_offset + 8 + RECIPIENT_PUBLIC_KEY_LEN;
                        write_u32(bytes, eph_offset, rng.next_u64() as u32);
                    }
                }
            }
        }
    }
}

fn structured_footer_tweak(rng: &mut XorShift64, bytes: &mut [u8]) {
    if bytes.len() < 4 {
        return;
    }
    let footer_start = bytes.len() - 4;
    if rng.next_u64() % 2 == 0 {
        bytes[footer_start..].copy_from_slice(&FOOTER_MAGIC);
    } else {
        bytes[footer_start..].copy_from_slice(&(rng.next_u64() as u32).to_le_bytes());
    }
}

fn swap_ranges(rng: &mut XorShift64, bytes: &mut [u8]) {
    if bytes.len() < 2 {
        return;
    }
    let len = ((rng.next_u64() as usize) % 8).max(1);
    let start_a = (rng.next_u64() as usize) % bytes.len();
    let start_b = (rng.next_u64() as usize) % bytes.len();
    for i in 0..len {
        let a = start_a + i;
        let b = start_b + i;
        if a >= bytes.len() || b >= bytes.len() {
            break;
        }
        bytes.swap(a, b);
    }
}

fn splice_with_seed(rng: &mut XorShift64, bytes: &mut Vec<u8>, seeds: &[SeedCase], max_len: usize) {
    if seeds.is_empty() || max_len == 0 {
        return;
    }
    let other = &seeds[(rng.next_u64() as usize) % seeds.len()].bytes;
    if other.is_empty() {
        return;
    }
    let split_self = (rng.next_u64() as usize) % (bytes.len() + 1);
    let split_other = (rng.next_u64() as usize) % (other.len() + 1);
    let mut combined = Vec::with_capacity(std::cmp::min(max_len, split_self + other.len()));
    combined.extend_from_slice(&bytes[..split_self]);
    combined.extend_from_slice(&other[split_other..]);
    if combined.len() > max_len {
        combined.truncate(max_len);
    }
    *bytes = combined;
}

fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    if offset + 2 <= bytes.len() {
        Some(u16::from_le_bytes([bytes[offset], bytes[offset + 1]]))
    } else {
        None
    }
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    if offset + 4 <= bytes.len() {
        Some(u32::from_le_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ]))
    } else {
        None
    }
}

fn read_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    if offset + 8 <= bytes.len() {
        Some(u64::from_le_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
            bytes[offset + 4],
            bytes[offset + 5],
            bytes[offset + 6],
            bytes[offset + 7],
        ]))
    } else {
        None
    }
}

fn write_u16(bytes: &mut [u8], offset: usize, value: u16) {
    if offset + 2 <= bytes.len() {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }
}

fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
    if offset + 4 <= bytes.len() {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
}

fn write_u64(bytes: &mut [u8], offset: usize, value: u64) {
    if offset + 8 <= bytes.len() {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }
}
struct XorShift64 {
    state: u64,
}

impl XorShift64 {
    fn new(seed: u64) -> Self {
        Self { state: seed.max(1) }
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }

    fn fill_bytes(&mut self, buf: &mut [u8]) {
        let mut offset = 0;
        while offset < buf.len() {
            let next = self.next_u64().to_le_bytes();
            let to_copy = std::cmp::min(next.len(), buf.len() - offset);
            buf[offset..offset + to_copy].copy_from_slice(&next[..to_copy]);
            offset += to_copy;
        }
    }
}

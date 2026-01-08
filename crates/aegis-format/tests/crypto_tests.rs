use std::io::Cursor;

use aegis_core::crypto::public_key::generate_keypair;
use aegis_format::{
    decrypt_container_v2, decrypt_container_v3, decrypt_container_v4, read_header,
    rotate_container_v3, rotate_container_v4, write_encrypted_container,
    write_encrypted_container_password, write_encrypted_container_v3, write_encrypted_container_v4,
    ChunkType, CryptoHeader, FormatError, RecipientSpec, WrapType, WriteChunkSource,
    ACF_VERSION_V2, ACF_VERSION_V4, HEADER_BASE_LEN, RECIPIENT_PUBLIC_KEY_LEN,
};
use aegis_testkit::{flip_byte, sample_bytes};

fn make_chunk(chunk_id: u32, chunk_type: ChunkType, data: Vec<u8>) -> WriteChunkSource {
    WriteChunkSource {
        chunk_id,
        chunk_type,
        flags: 0,
        length: data.len() as u64,
        reader: Box::new(Cursor::new(data)),
    }
}

#[test]
fn encrypted_roundtrip_small_keyfile() {
    let key = vec![0x11u8; 32];
    let data = sample_bytes(128);
    let mut chunks = vec![make_chunk(1, ChunkType::Data, data.clone())];

    let mut container = Vec::new();
    write_encrypted_container(&mut container, &mut chunks, &key).expect("encrypt");

    let mut output = Vec::new();
    decrypt_container_v2(
        &mut Cursor::new(container),
        &mut output,
        &key,
        WrapType::Keyfile,
    )
    .expect("decrypt");

    assert_eq!(output, data);
}

#[test]
fn encrypted_roundtrip_large_keyfile() {
    let key = vec![0x22u8; 32];
    let data = sample_bytes(2 * 1024 * 1024);
    let mut chunks = vec![make_chunk(1, ChunkType::Data, data.clone())];

    let mut container = Vec::new();
    write_encrypted_container(&mut container, &mut chunks, &key).expect("encrypt");

    let mut output = Vec::new();
    decrypt_container_v2(
        &mut Cursor::new(container),
        &mut output,
        &key,
        WrapType::Keyfile,
    )
    .expect("decrypt");

    assert_eq!(output, data);
}

#[test]
fn encrypted_roundtrip_password() {
    let password = b"mock-password";
    let data = sample_bytes(512);
    let mut chunks = vec![make_chunk(1, ChunkType::Data, data.clone())];

    let mut container = Vec::new();
    write_encrypted_container_password(&mut container, &mut chunks, password).expect("encrypt");

    let mut output = Vec::new();
    decrypt_container_v2(
        &mut Cursor::new(container),
        &mut output,
        password,
        WrapType::Password,
    )
    .expect("decrypt");

    assert_eq!(output, data);
}

#[test]
fn wrong_key_rejected() {
    let key = vec![0x33u8; 32];
    let wrong_key = vec![0x44u8; 32];
    let data = sample_bytes(512);
    let mut chunks = vec![make_chunk(1, ChunkType::Data, data)];

    let mut container = Vec::new();
    write_encrypted_container(&mut container, &mut chunks, &key).expect("encrypt");

    let err = decrypt_container_v2(
        &mut Cursor::new(container),
        &mut Vec::new(),
        &wrong_key,
        WrapType::Keyfile,
    )
    .expect_err("wrong key should fail");
    assert!(matches!(err, FormatError::Crypto(_)));
}

#[test]
fn wrong_password_rejected() {
    let password = b"correct-password";
    let wrong_password = b"wrong-password";
    let data = sample_bytes(256);
    let mut chunks = vec![make_chunk(1, ChunkType::Data, data)];

    let mut container = Vec::new();
    write_encrypted_container_password(&mut container, &mut chunks, password).expect("encrypt");

    let err = decrypt_container_v2(
        &mut Cursor::new(container),
        &mut Vec::new(),
        wrong_password,
        WrapType::Password,
    )
    .expect_err("wrong password should fail");
    assert!(matches!(err, FormatError::Crypto(_)));
}

#[test]
fn mixed_mode_rejected() {
    let key = vec![0x55u8; 32];
    let password = b"mixed-mode";
    let data = sample_bytes(256);
    let mut chunks = vec![make_chunk(1, ChunkType::Data, data.clone())];

    let mut container = Vec::new();
    write_encrypted_container_password(&mut container, &mut chunks, password).expect("encrypt");

    let err = decrypt_container_v2(
        &mut Cursor::new(container),
        &mut Vec::new(),
        &key,
        WrapType::Keyfile,
    )
    .expect_err("wrong wrap mode should fail");
    assert!(matches!(err, FormatError::WrapTypeMismatch));
}

#[test]
fn corrupted_ciphertext_rejected() {
    let key = vec![0x66u8; 32];
    let data = sample_bytes(256);
    let mut chunks = vec![make_chunk(1, ChunkType::Data, data)];

    let mut container = Vec::new();
    write_encrypted_container(&mut container, &mut chunks, &key).expect("encrypt");

    let (header, _) = read_header(&mut Cursor::new(&container)).expect("header");
    assert_eq!(header.version, ACF_VERSION_V2);
    let offset = header.header_len as usize + 4;
    flip_byte(&mut container, offset);

    let err = decrypt_container_v2(
        &mut Cursor::new(container),
        &mut Vec::new(),
        &key,
        WrapType::Keyfile,
    )
    .expect_err("corruption should fail");
    assert!(matches!(err, FormatError::Crypto(_)));
}

#[test]
fn header_tampering_rejected() {
    let key = vec![0x77u8; 32];
    let data = sample_bytes(256);
    let mut chunks = vec![make_chunk(1, ChunkType::Data, data)];

    let mut container = Vec::new();
    write_encrypted_container(&mut container, &mut chunks, &key).expect("encrypt");

    let (header, _) = read_header(&mut Cursor::new(&container)).expect("header");
    let salt_offset = HEADER_BASE_LEN + 2 + 2 + 4 + 4 + 4 + 2;
    assert!(salt_offset < header.header_len as usize);
    flip_byte(&mut container, salt_offset);

    let err = decrypt_container_v2(
        &mut Cursor::new(container),
        &mut Vec::new(),
        &key,
        WrapType::Keyfile,
    )
    .expect_err("tampered header should fail");
    assert!(matches!(err, FormatError::Crypto(_)));
}

#[test]
fn truncated_ciphertext_rejected() {
    let key = vec![0x88u8; 32];
    let data = sample_bytes(256);
    let mut chunks = vec![make_chunk(1, ChunkType::Data, data)];

    let mut container = Vec::new();
    write_encrypted_container(&mut container, &mut chunks, &key).expect("encrypt");

    container.truncate(container.len() - 1);

    let err = decrypt_container_v2(
        &mut Cursor::new(container),
        &mut Vec::new(),
        &key,
        WrapType::Keyfile,
    )
    .expect_err("truncated should fail");
    assert!(matches!(
        err,
        FormatError::Crypto(_) | FormatError::Truncated
    ));
}

#[test]
fn nonce_uniqueness() {
    let key = vec![0x99u8; 32];
    let data = sample_bytes(64);

    let mut chunks_a = vec![make_chunk(1, ChunkType::Data, data.clone())];
    let mut chunks_b = vec![make_chunk(1, ChunkType::Data, data)];

    let mut container_a = Vec::new();
    let mut container_b = Vec::new();
    write_encrypted_container(&mut container_a, &mut chunks_a, &key).expect("encrypt a");
    write_encrypted_container(&mut container_b, &mut chunks_b, &key).expect("encrypt b");

    let (header_a, _) = read_header(&mut Cursor::new(&container_a)).expect("header a");
    let (header_b, _) = read_header(&mut Cursor::new(&container_b)).expect("header b");

    let nonce_a = match header_a.crypto.as_ref().expect("crypto a") {
        CryptoHeader::V2 { nonce, .. } => nonce.clone(),
        _ => panic!("expected v2 header"),
    };
    let nonce_b = match header_b.crypto.as_ref().expect("crypto b") {
        CryptoHeader::V2 { nonce, .. } => nonce.clone(),
        _ => panic!("expected v2 header"),
    };

    assert_ne!(nonce_a, nonce_b);
}

#[test]
fn multi_recipient_roundtrip_keyfile_password() {
    let key = vec![0xA1u8; 32];
    let password = b"multi-pass";
    let data = sample_bytes(1024);
    let mut chunks = vec![make_chunk(1, ChunkType::Data, data.clone())];

    let recipients = vec![
        RecipientSpec {
            recipient_id: 1,
            recipient_type: WrapType::Keyfile,
            key_material: Some(&key),
            public_key: None,
        },
        RecipientSpec {
            recipient_id: 2,
            recipient_type: WrapType::Password,
            key_material: Some(password),
            public_key: None,
        },
    ];

    let mut container = Vec::new();
    write_encrypted_container_v3(&mut container, &mut chunks, &recipients).expect("encrypt");

    let mut out_key = Vec::new();
    decrypt_container_v3(
        &mut Cursor::new(container.clone()),
        &mut out_key,
        &key,
        WrapType::Keyfile,
    )
    .expect("decrypt key");
    assert_eq!(out_key, data);

    let mut out_password = Vec::new();
    decrypt_container_v3(
        &mut Cursor::new(container),
        &mut out_password,
        password,
        WrapType::Password,
    )
    .expect("decrypt password");
    assert_eq!(out_password, data);
}

#[test]
fn multi_recipient_wrong_credentials_rejected() {
    let key = vec![0xB2u8; 32];
    let password = b"correct-pass";
    let data = sample_bytes(512);
    let mut chunks = vec![make_chunk(1, ChunkType::Data, data)];

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
            key_material: Some(password),
            public_key: None,
        },
    ];

    let mut container = Vec::new();
    write_encrypted_container_v3(&mut container, &mut chunks, &recipients).expect("encrypt");

    let wrong_key = vec![0xC3u8; 32];
    let err = decrypt_container_v3(
        &mut Cursor::new(container.clone()),
        &mut Vec::new(),
        &wrong_key,
        WrapType::Keyfile,
    )
    .expect_err("wrong key should fail");
    assert!(matches!(err, FormatError::Crypto(_)));

    let wrong_password = b"wrong-pass";
    let err = decrypt_container_v3(
        &mut Cursor::new(container),
        &mut Vec::new(),
        wrong_password,
        WrapType::Password,
    )
    .expect_err("wrong password should fail");
    assert!(matches!(err, FormatError::Crypto(_)));
}

#[test]
fn recipient_removal_invalidates_old_credentials() {
    let key_a = vec![0xD4u8; 32];
    let key_b = vec![0xE5u8; 32];
    let data = sample_bytes(256);
    let mut chunks = vec![make_chunk(1, ChunkType::Data, data.clone())];

    let recipients = vec![
        RecipientSpec {
            recipient_id: 1,
            recipient_type: WrapType::Keyfile,
            key_material: Some(&key_a),
            public_key: None,
        },
        RecipientSpec {
            recipient_id: 2,
            recipient_type: WrapType::Keyfile,
            key_material: Some(&key_b),
            public_key: None,
        },
    ];

    let mut container = Vec::new();
    write_encrypted_container_v3(&mut container, &mut chunks, &recipients).expect("encrypt");

    let mut rotated = Vec::new();
    rotate_container_v3(
        &mut Cursor::new(container),
        &mut rotated,
        &key_b,
        WrapType::Keyfile,
        &[],
        &[1],
    )
    .expect("rotate");

    let err = decrypt_container_v3(
        &mut Cursor::new(rotated.clone()),
        &mut Vec::new(),
        &key_a,
        WrapType::Keyfile,
    )
    .expect_err("removed key should fail");
    assert!(matches!(
        err,
        FormatError::Crypto(_) | FormatError::RecipientTypeNotFound
    ));

    let mut out = Vec::new();
    decrypt_container_v3(
        &mut Cursor::new(rotated),
        &mut out,
        &key_b,
        WrapType::Keyfile,
    )
    .expect("remaining key should work");
    assert_eq!(out, data);
}

#[test]
fn rotation_preserves_payload() {
    let key_a = vec![0xF6u8; 32];
    let key_b = vec![0x17u8; 32];
    let data = sample_bytes(1024);
    let mut chunks = vec![make_chunk(1, ChunkType::Data, data.clone())];

    let recipients = vec![
        RecipientSpec {
            recipient_id: 5,
            recipient_type: WrapType::Keyfile,
            key_material: Some(&key_a),
            public_key: None,
        },
        RecipientSpec {
            recipient_id: 6,
            recipient_type: WrapType::Keyfile,
            key_material: Some(&key_b),
            public_key: None,
        },
    ];

    let mut container = Vec::new();
    write_encrypted_container_v3(&mut container, &mut chunks, &recipients).expect("encrypt");

    let new_key = vec![0x28u8; 32];
    let add_specs = vec![RecipientSpec {
        recipient_id: 7,
        recipient_type: WrapType::Keyfile,
        key_material: Some(&new_key),
        public_key: None,
    }];

    let mut rotated = Vec::new();
    rotate_container_v3(
        &mut Cursor::new(container),
        &mut rotated,
        &key_a,
        WrapType::Keyfile,
        &add_specs,
        &[5],
    )
    .expect("rotate");

    let mut out = Vec::new();
    decrypt_container_v3(
        &mut Cursor::new(rotated),
        &mut out,
        &new_key,
        WrapType::Keyfile,
    )
    .expect("decrypt rotated");
    assert_eq!(out, data);
}

#[test]
fn rotation_v4_add_remove_public_recipient() {
    let keyfile = vec![0x3Au8; 32];
    let (private_a, public_a) = generate_keypair().expect("keypair a");
    let (private_b, public_b) = generate_keypair().expect("keypair b");
    let data = sample_bytes(1024);
    let mut chunks = vec![make_chunk(1, ChunkType::Data, data.clone())];

    let recipients = vec![
        RecipientSpec {
            recipient_id: 1,
            recipient_type: WrapType::Keyfile,
            key_material: Some(&keyfile),
            public_key: None,
        },
        RecipientSpec {
            recipient_id: 2,
            recipient_type: WrapType::PublicKey,
            key_material: None,
            public_key: Some(public_a),
        },
    ];

    let mut container = Vec::new();
    write_encrypted_container_v4(&mut container, &mut chunks, &recipients).expect("encrypt");

    let add_specs = vec![RecipientSpec {
        recipient_id: 3,
        recipient_type: WrapType::PublicKey,
        key_material: None,
        public_key: Some(public_b),
    }];

    let mut rotated = Vec::new();
    rotate_container_v4(
        &mut Cursor::new(container),
        &mut rotated,
        &keyfile,
        WrapType::Keyfile,
        &add_specs,
        &[2],
    )
    .expect("rotate");

    let mut out_key = Vec::new();
    decrypt_container_v4(
        &mut Cursor::new(rotated.clone()),
        &mut out_key,
        &keyfile,
        WrapType::Keyfile,
    )
    .expect("keyfile decrypt");
    assert_eq!(out_key, data);

    let mut out_pub = Vec::new();
    decrypt_container_v4(
        &mut Cursor::new(rotated.clone()),
        &mut out_pub,
        private_b.as_ref(),
        WrapType::PublicKey,
    )
    .expect("public decrypt");
    assert_eq!(out_pub, data);

    let err = decrypt_container_v4(
        &mut Cursor::new(rotated),
        &mut Vec::new(),
        private_a.as_ref(),
        WrapType::PublicKey,
    )
    .expect_err("old public key should fail");
    assert!(matches!(
        err,
        FormatError::Crypto(_) | FormatError::RecipientTypeNotFound
    ));
}

#[test]
fn tampered_recipient_entry_rejected() {
    let key = vec![0x39u8; 32];
    let data = sample_bytes(128);
    let mut chunks = vec![make_chunk(1, ChunkType::Data, data)];

    let recipients = vec![RecipientSpec {
        recipient_id: 1,
        recipient_type: WrapType::Keyfile,
        key_material: Some(&key),
        public_key: None,
    }];

    let mut container = Vec::new();
    write_encrypted_container_v3(&mut container, &mut chunks, &recipients).expect("encrypt");

    let (header, _) = read_header(&mut Cursor::new(&container)).expect("header");
    let offset = header.header_len as usize - 1;
    flip_byte(&mut container, offset);

    let err = decrypt_container_v3(
        &mut Cursor::new(container),
        &mut Vec::new(),
        &key,
        WrapType::Keyfile,
    )
    .expect_err("tampered recipient should fail");
    assert!(matches!(err, FormatError::Crypto(_)));
}

#[test]
fn public_key_roundtrip() {
    let (private_key, public_key) = generate_keypair().expect("keypair");
    let data = sample_bytes(512);
    let mut chunks = vec![make_chunk(1, ChunkType::Data, data.clone())];

    let recipients = vec![RecipientSpec {
        recipient_id: 1,
        recipient_type: WrapType::PublicKey,
        key_material: None,
        public_key: Some(public_key),
    }];

    let mut container = Vec::new();
    write_encrypted_container_v4(&mut container, &mut chunks, &recipients).expect("encrypt");

    let mut output = Vec::new();
    decrypt_container_v4(
        &mut Cursor::new(container),
        &mut output,
        private_key.as_ref(),
        WrapType::PublicKey,
    )
    .expect("decrypt");

    assert_eq!(output, data);
}

#[test]
fn public_key_old_private_rejected() {
    let (private_key, public_key) = generate_keypair().expect("keypair");
    let (old_private_key, _) = generate_keypair().expect("old keypair");
    let data = sample_bytes(256);
    let mut chunks = vec![make_chunk(1, ChunkType::Data, data)];

    let recipients = vec![RecipientSpec {
        recipient_id: 1,
        recipient_type: WrapType::PublicKey,
        key_material: None,
        public_key: Some(public_key),
    }];

    let mut container = Vec::new();
    write_encrypted_container_v4(&mut container, &mut chunks, &recipients).expect("encrypt");

    let err = decrypt_container_v4(
        &mut Cursor::new(container.clone()),
        &mut Vec::new(),
        old_private_key.as_ref(),
        WrapType::PublicKey,
    )
    .expect_err("old key should fail");
    assert!(matches!(err, FormatError::Crypto(_)));

    let mut output = Vec::new();
    decrypt_container_v4(
        &mut Cursor::new(container),
        &mut output,
        private_key.as_ref(),
        WrapType::PublicKey,
    )
    .expect("new key works");
}

#[test]
fn mixed_recipients_v4_roundtrip() {
    let (private_key, public_key) = generate_keypair().expect("keypair");
    let keyfile = vec![0x42u8; 32];
    let password = b"mixed-pass";
    let data = sample_bytes(1024);
    let mut chunks = vec![make_chunk(1, ChunkType::Data, data.clone())];

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
            key_material: Some(password),
            public_key: None,
        },
        RecipientSpec {
            recipient_id: 3,
            recipient_type: WrapType::PublicKey,
            key_material: None,
            public_key: Some(public_key),
        },
    ];

    let mut container = Vec::new();
    write_encrypted_container_v4(&mut container, &mut chunks, &recipients).expect("encrypt");

    let mut out_key = Vec::new();
    decrypt_container_v4(
        &mut Cursor::new(container.clone()),
        &mut out_key,
        &keyfile,
        WrapType::Keyfile,
    )
    .expect("keyfile decrypt");
    assert_eq!(out_key, data);

    let mut out_pw = Vec::new();
    decrypt_container_v4(
        &mut Cursor::new(container.clone()),
        &mut out_pw,
        password,
        WrapType::Password,
    )
    .expect("password decrypt");
    assert_eq!(out_pw, data);

    let mut out_pub = Vec::new();
    decrypt_container_v4(
        &mut Cursor::new(container),
        &mut out_pub,
        private_key.as_ref(),
        WrapType::PublicKey,
    )
    .expect("public decrypt");
    assert_eq!(out_pub, data);
}

#[test]
fn corrupted_ephemeral_pubkey_rejected() {
    let (private_key, public_key) = generate_keypair().expect("keypair");
    let data = sample_bytes(256);
    let mut chunks = vec![make_chunk(1, ChunkType::Data, data)];

    let recipients = vec![RecipientSpec {
        recipient_id: 1,
        recipient_type: WrapType::PublicKey,
        key_material: None,
        public_key: Some(public_key),
    }];

    let mut container = Vec::new();
    write_encrypted_container_v4(&mut container, &mut chunks, &recipients).expect("encrypt");

    let (header, _) = read_header(&mut Cursor::new(&container)).expect("header");
    assert_eq!(header.version, ACF_VERSION_V4);

    let salt_len = match header.crypto.as_ref() {
        Some(CryptoHeader::V4 { salt, .. }) => salt.len(),
        _ => panic!("expected v4 header"),
    };

    let nonce_len = match header.crypto.as_ref() {
        Some(CryptoHeader::V4 { nonce, .. }) => nonce.len(),
        _ => panic!("expected v4 header"),
    };

    let mut offset = HEADER_BASE_LEN + 2 + 2 + 4 + 4 + 4 + 2;
    offset += salt_len;
    offset += 2;
    offset += nonce_len;
    offset += 2;
    offset += 4 + 2 + 2 + RECIPIENT_PUBLIC_KEY_LEN;
    flip_byte(&mut container, offset);

    let err = decrypt_container_v4(
        &mut Cursor::new(container),
        &mut Vec::new(),
        private_key.as_ref(),
        WrapType::PublicKey,
    )
    .expect_err("ephemeral tamper should fail");
    assert!(matches!(err, FormatError::Crypto(_)));
}

use std::io::Cursor;

use aegis_format::{
    decrypt_container, read_header, write_encrypted_container, ChunkType, FormatError,
    WriteChunkSource, ACF_VERSION_V1, HEADER_BASE_LEN,
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
fn encrypted_roundtrip_small() {
    let key = vec![0x11u8; 32];
    let data = sample_bytes(128);
    let mut chunks = vec![make_chunk(1, ChunkType::Data, data.clone())];

    let mut container = Vec::new();
    write_encrypted_container(&mut container, &mut chunks, &key).expect("encrypt");

    let mut output = Vec::new();
    decrypt_container(&mut Cursor::new(container), &mut output, &key).expect("decrypt");

    assert_eq!(output, data);
}

#[test]
fn encrypted_roundtrip_large() {
    let key = vec![0x22u8; 32];
    let data = sample_bytes(2 * 1024 * 1024);
    let mut chunks = vec![make_chunk(1, ChunkType::Data, data.clone())];

    let mut container = Vec::new();
    write_encrypted_container(&mut container, &mut chunks, &key).expect("encrypt");

    let mut output = Vec::new();
    decrypt_container(&mut Cursor::new(container), &mut output, &key).expect("decrypt");

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

    let err = decrypt_container(&mut Cursor::new(container), &mut Vec::new(), &wrong_key)
        .expect_err("wrong key should fail");
    assert!(matches!(err, FormatError::Crypto(_)));
}

#[test]
fn corrupted_ciphertext_rejected() {
    let key = vec![0x55u8; 32];
    let data = sample_bytes(256);
    let mut chunks = vec![make_chunk(1, ChunkType::Data, data)];

    let mut container = Vec::new();
    write_encrypted_container(&mut container, &mut chunks, &key).expect("encrypt");

    let (header, _) = read_header(&mut Cursor::new(&container)).expect("header");
    assert_eq!(header.version, ACF_VERSION_V1);
    let offset = header.header_len as usize + 4;
    flip_byte(&mut container, offset);

    let err = decrypt_container(&mut Cursor::new(container), &mut Vec::new(), &key)
        .expect_err("corruption should fail");
    assert!(matches!(err, FormatError::Crypto(_)));
}

#[test]
fn header_tampering_rejected() {
    let key = vec![0x66u8; 32];
    let data = sample_bytes(256);
    let mut chunks = vec![make_chunk(1, ChunkType::Data, data)];

    let mut container = Vec::new();
    write_encrypted_container(&mut container, &mut chunks, &key).expect("encrypt");

    let (header, _) = read_header(&mut Cursor::new(&container)).expect("header");
    let salt_offset = HEADER_BASE_LEN + 2 + 2 + 2;
    assert!(salt_offset < header.header_len as usize);
    flip_byte(&mut container, salt_offset);

    let err = decrypt_container(&mut Cursor::new(container), &mut Vec::new(), &key)
        .expect_err("tampered header should fail");
    assert!(matches!(err, FormatError::Crypto(_)));
}

#[test]
fn truncated_ciphertext_rejected() {
    let key = vec![0x77u8; 32];
    let data = sample_bytes(256);
    let mut chunks = vec![make_chunk(1, ChunkType::Data, data)];

    let mut container = Vec::new();
    write_encrypted_container(&mut container, &mut chunks, &key).expect("encrypt");

    container.truncate(container.len() - 1);

    let err = decrypt_container(&mut Cursor::new(container), &mut Vec::new(), &key)
        .expect_err("truncated should fail");
    assert!(matches!(
        err,
        FormatError::Crypto(_) | FormatError::Truncated
    ));
}

#[test]
fn nonce_uniqueness() {
    let key = vec![0x88u8; 32];
    let data = sample_bytes(64);

    let mut chunks_a = vec![make_chunk(1, ChunkType::Data, data.clone())];
    let mut chunks_b = vec![make_chunk(1, ChunkType::Data, data)];

    let mut container_a = Vec::new();
    let mut container_b = Vec::new();
    write_encrypted_container(&mut container_a, &mut chunks_a, &key).expect("encrypt a");
    write_encrypted_container(&mut container_b, &mut chunks_b, &key).expect("encrypt b");

    let (header_a, _) = read_header(&mut Cursor::new(&container_a)).expect("header a");
    let (header_b, _) = read_header(&mut Cursor::new(&container_b)).expect("header b");

    let nonce_a = header_a.crypto.as_ref().expect("crypto a").nonce.clone();
    let nonce_b = header_b.crypto.as_ref().expect("crypto b").nonce.clone();

    assert_ne!(nonce_a, nonce_b);
}

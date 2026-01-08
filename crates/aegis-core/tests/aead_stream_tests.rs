use std::io::{Cursor, Read};

use aegis_core::crypto::aead::{
    encrypt_stream, DecryptReader, AEAD_KEY_LEN, AEAD_NONCE_LEN, STREAM_CHUNK_SIZE,
};

fn roundtrip(data: &[u8]) {
    let key = vec![0x11u8; AEAD_KEY_LEN];
    let nonce = vec![0x22u8; AEAD_NONCE_LEN];
    let aad = b"aegis-stream-test";

    let mut ciphertext = Vec::new();
    encrypt_stream(&mut Cursor::new(data), &mut ciphertext, &key, &nonce, aad).expect("encrypt");

    let mut decrypt_reader =
        DecryptReader::new(Cursor::new(ciphertext), &key, &nonce, aad).expect("decrypt reader");
    let mut out = Vec::new();
    decrypt_reader.read_to_end(&mut out).expect("decrypt");
    assert_eq!(out, data);
}

#[test]
fn stream_roundtrip_empty() {
    roundtrip(&[]);
}

#[test]
fn stream_roundtrip_exact_chunk() {
    roundtrip(&vec![0xAB; STREAM_CHUNK_SIZE]);
}

#[test]
fn stream_roundtrip_chunk_plus_one() {
    roundtrip(&vec![0xCD; STREAM_CHUNK_SIZE + 1]);
}

use std::io::{Read, Write};

use chacha20poly1305::aead::stream::{DecryptorLE31, EncryptorLE31, Nonce, StreamLE31};
use chacha20poly1305::aead::{KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305};
use rand_core::{OsRng, RngCore};
use zeroize::Zeroizing;

use crate::crypto::CryptoError;

pub const AEAD_KEY_LEN: usize = 32;
// STREAM LE31 reserves 4 bytes for the counter/last flag.
pub const AEAD_NONCE_LEN: usize = 20;
pub const STREAM_CHUNK_SIZE: usize = 64 * 1024;
pub const AEAD_TAG_LEN: usize = 16;

type StreamNonce = Nonce<XChaCha20Poly1305, StreamLE31<XChaCha20Poly1305>>;

pub fn generate_nonce() -> Result<[u8; AEAD_NONCE_LEN], CryptoError> {
    let mut nonce = [0u8; AEAD_NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    Ok(nonce)
}

pub fn encrypt_stream<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
) -> Result<(), CryptoError> {
    let key = validate_key(key)?;
    let nonce = validate_nonce(nonce)?;

    let aead = XChaCha20Poly1305::new(&key);
    let mut encryptor = EncryptorLE31::from_aead(aead, &nonce);

    let mut buf = vec![0u8; STREAM_CHUNK_SIZE];
    let mut next_buf = vec![0u8; STREAM_CHUNK_SIZE];

    let mut read = read_full(reader, &mut buf)?;
    if read == 0 {
        let ct = encryptor
            .encrypt_last(Payload { msg: &[], aad })
            .map_err(|_| CryptoError::AuthFailed)?;
        writer.write_all(&ct)?;
        return Ok(());
    }

    loop {
        let next_read = read_full(reader, &mut next_buf)?;
        if next_read == 0 {
            let ct = encryptor
                .encrypt_last(Payload {
                    msg: &buf[..read],
                    aad,
                })
                .map_err(|_| CryptoError::AuthFailed)?;
            writer.write_all(&ct)?;
            break;
        } else {
            let ct = encryptor
                .encrypt_next(Payload {
                    msg: &buf[..read],
                    aad,
                })
                .map_err(|_| CryptoError::AuthFailed)?;
            writer.write_all(&ct)?;
            std::mem::swap(&mut buf, &mut next_buf);
            read = next_read;
        }
    }

    Ok(())
}

pub struct DecryptReader<R: Read> {
    reader: R,
    decryptor: Option<DecryptorLE31<XChaCha20Poly1305>>,
    aad: Vec<u8>,
    buffer: Zeroizing<Vec<u8>>,
    position: usize,
    done: bool,
    lookahead: Option<u8>,
}

impl<R: Read> DecryptReader<R> {
    pub fn new(reader: R, key: &[u8], nonce: &[u8], aad: &[u8]) -> Result<Self, CryptoError> {
        let key = validate_key(key)?;
        let nonce = validate_nonce(nonce)?;

        let aead = XChaCha20Poly1305::new(&key);
        let decryptor = DecryptorLE31::from_aead(aead, &nonce);

        Ok(Self {
            reader,
            decryptor: Some(decryptor),
            aad: aad.to_vec(),
            buffer: Zeroizing::new(Vec::new()),
            position: 0,
            done: false,
            lookahead: None,
        })
    }

    pub fn read_plaintext(&mut self, out: &mut [u8]) -> Result<usize, CryptoError> {
        if out.is_empty() {
            return Ok(0);
        }

        if self.position >= self.buffer.len() {
            self.fill_buffer()?;
        }

        if self.buffer.is_empty() {
            return Ok(0);
        }

        let remaining = self.buffer.len() - self.position;
        let to_copy = std::cmp::min(remaining, out.len());
        out[..to_copy].copy_from_slice(&self.buffer[self.position..self.position + to_copy]);
        self.position += to_copy;
        Ok(to_copy)
    }

    fn fill_buffer(&mut self) -> Result<(), CryptoError> {
        if self.done {
            self.buffer.clear();
            self.position = 0;
            return Ok(());
        }

        let mut cipher_buf = vec![0u8; STREAM_CHUNK_SIZE + AEAD_TAG_LEN];
        let mut read = 0usize;

        if let Some(byte) = self.lookahead.take() {
            cipher_buf[0] = byte;
            read = 1;
        }

        while read < cipher_buf.len() {
            let n = self.reader.read(&mut cipher_buf[read..])?;
            if n == 0 {
                break;
            }
            read += n;
            if read == cipher_buf.len() {
                break;
            }
        }

        if read == 0 {
            return Err(CryptoError::Truncated);
        }

        cipher_buf.truncate(read);

        if cipher_buf.len() < AEAD_TAG_LEN {
            return Err(CryptoError::Truncated);
        }

        let mut is_last = cipher_buf.len() < STREAM_CHUNK_SIZE + AEAD_TAG_LEN;
        if !is_last {
            let mut probe = [0u8; 1];
            let n = self.reader.read(&mut probe)?;
            if n == 0 {
                is_last = true;
            } else {
                self.lookahead = Some(probe[0]);
            }
        }
        let plaintext = if is_last {
            self.done = true;
            let decryptor = self.decryptor.take().ok_or(CryptoError::Truncated)?;
            decryptor
                .decrypt_last(Payload {
                    msg: &cipher_buf,
                    aad: &self.aad,
                })
                .map_err(|_| CryptoError::AuthFailed)?
        } else {
            let decryptor = self.decryptor.as_mut().ok_or(CryptoError::Truncated)?;
            decryptor
                .decrypt_next(Payload {
                    msg: &cipher_buf,
                    aad: &self.aad,
                })
                .map_err(|_| CryptoError::AuthFailed)?
        };

        self.buffer = Zeroizing::new(plaintext);
        self.position = 0;
        Ok(())
    }
}

impl<R: Read> Read for DecryptReader<R> {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        self.read_plaintext(out).map_err(std::io::Error::other)
    }
}

fn validate_key(key: &[u8]) -> Result<Key, CryptoError> {
    if key.len() != AEAD_KEY_LEN {
        return Err(CryptoError::InvalidKeyLength {
            expected: AEAD_KEY_LEN,
            found: key.len(),
        });
    }

    Ok(Key::from_slice(key).to_owned())
}

fn validate_nonce(nonce: &[u8]) -> Result<StreamNonce, CryptoError> {
    if nonce.len() != AEAD_NONCE_LEN {
        return Err(CryptoError::InvalidNonceLength {
            expected: AEAD_NONCE_LEN,
            found: nonce.len(),
        });
    }

    Ok(StreamNonce::from_slice(nonce).to_owned())
}

fn read_full<R: Read>(reader: &mut R, buf: &mut [u8]) -> Result<usize, CryptoError> {
    let mut total = 0usize;
    while total < buf.len() {
        let read = reader.read(&mut buf[total..])?;
        if read == 0 {
            break;
        }
        total += read;
    }
    Ok(total)
}

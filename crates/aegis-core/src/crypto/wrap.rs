use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use rand_core::{OsRng, RngCore};
use zeroize::Zeroizing;

use crate::crypto::aead::{AEAD_KEY_LEN, AEAD_TAG_LEN};
use crate::crypto::CryptoError;

pub const WRAP_NONCE_LEN: usize = 24;
pub const WRAP_AAD_V2: &[u8] = b"AEGIS-KW-V2";
pub const WRAP_AAD_V3_PREFIX: &[u8] = b"AEGIS-KW-V3";

pub fn wrap_key(wrapping_key: &[u8], data_key: &[u8]) -> Result<Vec<u8>, CryptoError> {
    wrap_key_with_aad(wrapping_key, data_key, WRAP_AAD_V2)
}

pub fn wrap_key_with_aad(
    wrapping_key: &[u8],
    data_key: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if wrapping_key.len() != AEAD_KEY_LEN {
        return Err(CryptoError::InvalidKeyLength {
            expected: AEAD_KEY_LEN,
            found: wrapping_key.len(),
        });
    }
    if data_key.len() != AEAD_KEY_LEN {
        return Err(CryptoError::InvalidKeyLength {
            expected: AEAD_KEY_LEN,
            found: data_key.len(),
        });
    }

    let mut nonce = [0u8; WRAP_NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);

    let aead = XChaCha20Poly1305::new(Key::from_slice(wrapping_key));
    let ciphertext = aead
        .encrypt(XNonce::from_slice(&nonce), Payload { msg: data_key, aad })
        .map_err(|_| CryptoError::AuthFailed)?;

    let nonce_len = u16::try_from(nonce.len()).map_err(|_| CryptoError::InvalidWrappedKey)?;
    let mut out = Vec::with_capacity(2 + nonce.len() + ciphertext.len());
    out.extend_from_slice(&nonce_len.to_le_bytes());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

pub fn unwrap_key(
    wrapping_key: &[u8],
    wrapped_key: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    unwrap_key_with_aad(wrapping_key, wrapped_key, WRAP_AAD_V2)
}

pub fn unwrap_key_with_aad(
    wrapping_key: &[u8],
    wrapped_key: &[u8],
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if wrapping_key.len() != AEAD_KEY_LEN {
        return Err(CryptoError::InvalidKeyLength {
            expected: AEAD_KEY_LEN,
            found: wrapping_key.len(),
        });
    }

    if wrapped_key.len() < 2 + WRAP_NONCE_LEN + AEAD_TAG_LEN {
        return Err(CryptoError::InvalidWrappedKey);
    }

    let nonce_len = u16::from_le_bytes([wrapped_key[0], wrapped_key[1]]) as usize;
    if nonce_len != WRAP_NONCE_LEN {
        return Err(CryptoError::InvalidWrapNonceLength {
            expected: WRAP_NONCE_LEN,
            found: nonce_len,
        });
    }

    if wrapped_key.len() < 2 + nonce_len + AEAD_TAG_LEN {
        return Err(CryptoError::InvalidWrappedKey);
    }

    let nonce = &wrapped_key[2..2 + nonce_len];
    let ciphertext = &wrapped_key[2 + nonce_len..];

    let aead = XChaCha20Poly1305::new(Key::from_slice(wrapping_key));
    let plaintext = aead
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| CryptoError::AuthFailed)?;

    Ok(Zeroizing::new(plaintext))
}

use thiserror::Error;

#[cfg(not(feature = "zeroize"))]
compile_error!("aegis-core crypto requires the `zeroize` feature");

pub mod aead;
pub mod ids;
pub mod kdf;
pub mod keyfile;
pub mod public_key;
pub mod wrap;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid key length: expected {expected}, found {found}")]
    InvalidKeyLength { expected: usize, found: usize },
    #[error("invalid nonce length: expected {expected}, found {found}")]
    InvalidNonceLength { expected: usize, found: usize },
    #[error("invalid key file magic")]
    InvalidKeyFileMagic { found: [u8; 4] },
    #[error("unsupported key file version: {0}")]
    UnsupportedKeyFileVersion(u16),
    #[error("invalid key file length: {0}")]
    InvalidKeyFileLength(u16),
    #[error("key file length too large: {0}")]
    KeyFileTooLarge(usize),
    #[error("invalid public key file magic")]
    InvalidPublicKeyMagic { found: [u8; 4] },
    #[error("unsupported public key file version: {0}")]
    UnsupportedPublicKeyVersion(u16),
    #[error("invalid public key length: {0}")]
    InvalidPublicKeyLength(u16),
    #[error("invalid private key file magic")]
    InvalidPrivateKeyMagic { found: [u8; 4] },
    #[error("unsupported private key file version: {0}")]
    UnsupportedPrivateKeyVersion(u16),
    #[error("invalid private key length: {0}")]
    InvalidPrivateKeyLength(u16),
    #[error("invalid wrapped key data")]
    InvalidWrappedKey,
    #[error("invalid wrap nonce length: expected {expected}, found {found}")]
    InvalidWrapNonceLength { expected: usize, found: usize },
    #[error("argon2 error: {0}")]
    Argon2(argon2::Error),
    #[error("authentication failed")]
    AuthFailed,
    #[error("hkdf error")]
    Hkdf,
    #[error("truncated input")]
    Truncated,
    #[error("unsupported cipher id: {0}")]
    UnsupportedCipherId(u16),
    #[error("unsupported kdf id: {0}")]
    UnsupportedKdfId(u16),
}

impl From<argon2::Error> for CryptoError {
    fn from(err: argon2::Error) -> Self {
        Self::Argon2(err)
    }
}

use crate::crypto::CryptoError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherId {
    XChaCha20Poly1305 = 0x0001,
}

impl TryFrom<u16> for CipherId {
    type Error = CryptoError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0x0001 => Ok(CipherId::XChaCha20Poly1305),
            other => Err(CryptoError::UnsupportedCipherId(other)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KdfId {
    Argon2id = 0x0001,
}

impl TryFrom<u16> for KdfId {
    type Error = CryptoError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0x0001 => Ok(KdfId::Argon2id),
            other => Err(CryptoError::UnsupportedKdfId(other)),
        }
    }
}

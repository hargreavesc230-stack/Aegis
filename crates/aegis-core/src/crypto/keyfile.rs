use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;

use rand_core::{OsRng, RngCore};
use zeroize::Zeroizing;

use crate::crypto::CryptoError;

pub const KEYFILE_MAGIC: [u8; 4] = *b"AEGK";
pub const KEYFILE_VERSION: u16 = 1;

#[derive(Debug)]
pub struct KeyFile {
    pub version: u16,
    pub key: Zeroizing<Vec<u8>>,
}

pub fn generate_key(len: usize) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let mut key = Zeroizing::new(vec![0u8; len]);
    OsRng.fill_bytes(key.as_mut_slice());
    Ok(key)
}

pub fn write_keyfile<P: AsRef<Path>>(
    path: P,
    key_bytes: &[u8],
    force: bool,
) -> Result<(), CryptoError> {
    let key_len = u16::try_from(key_bytes.len())
        .map_err(|_| CryptoError::KeyFileTooLarge(key_bytes.len()))?;

    let mut options = OpenOptions::new();
    options.write(true).create(true);
    if force {
        options.truncate(true);
    } else {
        options.create_new(true);
    }

    let mut file = options.open(path)?;
    file.write_all(&KEYFILE_MAGIC)?;
    file.write_all(&KEYFILE_VERSION.to_le_bytes())?;
    file.write_all(&key_len.to_le_bytes())?;
    file.write_all(key_bytes)?;
    file.flush()?;
    Ok(())
}

pub fn read_keyfile<P: AsRef<Path>>(path: P) -> Result<KeyFile, CryptoError> {
    let mut file = File::open(path)?;
    let mut magic = [0u8; 4];
    file.read_exact(&mut magic)?;
    if magic != KEYFILE_MAGIC {
        return Err(CryptoError::InvalidKeyFileMagic { found: magic });
    }

    let mut version_bytes = [0u8; 2];
    file.read_exact(&mut version_bytes)?;
    let version = u16::from_le_bytes(version_bytes);
    if version != KEYFILE_VERSION {
        return Err(CryptoError::UnsupportedKeyFileVersion(version));
    }

    let mut len_bytes = [0u8; 2];
    file.read_exact(&mut len_bytes)?;
    let key_len = u16::from_le_bytes(len_bytes) as usize;
    if key_len == 0 {
        return Err(CryptoError::InvalidKeyFileLength(0));
    }

    let mut key = Zeroizing::new(vec![0u8; key_len]);
    file.read_exact(key.as_mut_slice())?;

    let mut trailing = [0u8; 1];
    match file.read(&mut trailing) {
        Ok(0) => Ok(KeyFile { version, key }),
        Ok(_) => Err(CryptoError::InvalidKeyFileLength(key_len as u16)),
        Err(err) => Err(CryptoError::Io(err)),
    }
}

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;

use hkdf::Hkdf;
use rand_core::OsRng;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::crypto::aead::AEAD_KEY_LEN;
use crate::crypto::CryptoError;

pub const PUBLIC_KEY_MAGIC: [u8; 4] = *b"AEGP";
pub const PRIVATE_KEY_MAGIC: [u8; 4] = *b"AEGS";
pub const PUBLIC_KEY_VERSION: u16 = 1;
pub const PRIVATE_KEY_VERSION: u16 = 1;
pub const X25519_KEY_LEN: usize = 32;
pub const HKDF_INFO: &[u8] = b"AEGIS-X25519-HKDF-V1";

#[derive(Debug)]
pub struct PublicKeyFile {
    pub version: u16,
    pub key: [u8; X25519_KEY_LEN],
}

#[derive(Debug)]
pub struct PrivateKeyFile {
    pub version: u16,
    pub key: Zeroizing<[u8; X25519_KEY_LEN]>,
}

pub fn generate_keypair(
) -> Result<(Zeroizing<[u8; X25519_KEY_LEN]>, [u8; X25519_KEY_LEN]), CryptoError> {
    let static_secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&static_secret);
    // Keep the private key in a zeroizing buffer for best-effort cleanup.
    let private = Zeroizing::new(static_secret.to_bytes());
    Ok((private, public.to_bytes()))
}

pub fn public_key_from_private(private_key: &[u8; X25519_KEY_LEN]) -> [u8; X25519_KEY_LEN] {
    let secret = StaticSecret::from(*private_key);
    PublicKey::from(&secret).to_bytes()
}

pub fn derive_wrapping_key(
    private_key: &[u8; X25519_KEY_LEN],
    recipient_pubkey: &[u8; X25519_KEY_LEN],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let secret = StaticSecret::from(*private_key);
    let peer = PublicKey::from(*recipient_pubkey);
    let shared = secret.diffie_hellman(&peer);

    // Zeroize the shared secret as soon as HKDF output is derived.
    let shared_bytes = Zeroizing::new(shared.as_bytes().to_vec());
    let hkdf = Hkdf::<Sha256>::new(None, shared_bytes.as_slice());
    let mut okm = Zeroizing::new(vec![0u8; AEAD_KEY_LEN]);
    hkdf.expand(HKDF_INFO, okm.as_mut_slice())
        .map_err(|_| CryptoError::Hkdf)?;
    Ok(okm)
}

pub fn write_public_keyfile<P: AsRef<Path>>(
    path: P,
    public_key: &[u8; X25519_KEY_LEN],
    force: bool,
) -> Result<(), CryptoError> {
    let key_len =
        u16::try_from(public_key.len()).map_err(|_| CryptoError::InvalidPublicKeyLength(0))?;

    let mut options = OpenOptions::new();
    options.write(true).create(true);
    if force {
        options.truncate(true);
    } else {
        options.create_new(true);
    }

    let mut file = options.open(path)?;
    file.write_all(&PUBLIC_KEY_MAGIC)?;
    file.write_all(&PUBLIC_KEY_VERSION.to_le_bytes())?;
    file.write_all(&key_len.to_le_bytes())?;
    file.write_all(public_key)?;
    file.flush()?;
    Ok(())
}

pub fn write_private_keyfile<P: AsRef<Path>>(
    path: P,
    private_key: &[u8; X25519_KEY_LEN],
    force: bool,
) -> Result<(), CryptoError> {
    let key_len =
        u16::try_from(private_key.len()).map_err(|_| CryptoError::InvalidPrivateKeyLength(0))?;

    let mut options = OpenOptions::new();
    options.write(true).create(true);
    if force {
        options.truncate(true);
    } else {
        options.create_new(true);
    }

    let mut file = options.open(path)?;
    file.write_all(&PRIVATE_KEY_MAGIC)?;
    file.write_all(&PRIVATE_KEY_VERSION.to_le_bytes())?;
    file.write_all(&key_len.to_le_bytes())?;
    file.write_all(private_key)?;
    file.flush()?;
    Ok(())
}

pub fn read_public_keyfile<P: AsRef<Path>>(path: P) -> Result<PublicKeyFile, CryptoError> {
    let mut file = File::open(path)?;
    let mut magic = [0u8; 4];
    file.read_exact(&mut magic)?;
    if magic != PUBLIC_KEY_MAGIC {
        return Err(CryptoError::InvalidPublicKeyMagic { found: magic });
    }

    let mut version_bytes = [0u8; 2];
    file.read_exact(&mut version_bytes)?;
    let version = u16::from_le_bytes(version_bytes);
    if version != PUBLIC_KEY_VERSION {
        return Err(CryptoError::UnsupportedPublicKeyVersion(version));
    }

    let mut len_bytes = [0u8; 2];
    file.read_exact(&mut len_bytes)?;
    let key_len = u16::from_le_bytes(len_bytes) as usize;
    if key_len != X25519_KEY_LEN {
        return Err(CryptoError::InvalidPublicKeyLength(key_len as u16));
    }

    let mut key = [0u8; X25519_KEY_LEN];
    file.read_exact(&mut key)?;

    let mut trailing = [0u8; 1];
    match file.read(&mut trailing) {
        Ok(0) => Ok(PublicKeyFile { version, key }),
        Ok(_) => Err(CryptoError::InvalidPublicKeyLength(key_len as u16)),
        Err(err) => Err(CryptoError::Io(err)),
    }
}

pub fn read_private_keyfile<P: AsRef<Path>>(path: P) -> Result<PrivateKeyFile, CryptoError> {
    let mut file = File::open(path)?;
    let mut magic = [0u8; 4];
    file.read_exact(&mut magic)?;
    if magic != PRIVATE_KEY_MAGIC {
        return Err(CryptoError::InvalidPrivateKeyMagic { found: magic });
    }

    let mut version_bytes = [0u8; 2];
    file.read_exact(&mut version_bytes)?;
    let version = u16::from_le_bytes(version_bytes);
    if version != PRIVATE_KEY_VERSION {
        return Err(CryptoError::UnsupportedPrivateKeyVersion(version));
    }

    let mut len_bytes = [0u8; 2];
    file.read_exact(&mut len_bytes)?;
    let key_len = u16::from_le_bytes(len_bytes) as usize;
    if key_len != X25519_KEY_LEN {
        return Err(CryptoError::InvalidPrivateKeyLength(key_len as u16));
    }

    let mut key = Zeroizing::new([0u8; X25519_KEY_LEN]);
    file.read_exact(key.as_mut())?;

    let mut trailing = [0u8; 1];
    match file.read(&mut trailing) {
        Ok(0) => Ok(PrivateKeyFile { version, key }),
        Ok(_) => Err(CryptoError::InvalidPrivateKeyLength(key_len as u16)),
        Err(err) => Err(CryptoError::Io(err)),
    }
}

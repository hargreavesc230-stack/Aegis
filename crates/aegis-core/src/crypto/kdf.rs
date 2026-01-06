use argon2::{Algorithm, Argon2, Params, Version};
use rand_core::{OsRng, RngCore};
use zeroize::Zeroizing;

use crate::crypto::CryptoError;

#[derive(Debug, Clone, Copy)]
pub struct KdfParams {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
    pub output_len: usize,
}

pub const DEFAULT_SALT_LEN: usize = 16;
pub const KDF_MEMORY_KIB_MIN: u32 = 64 * 1024;
pub const KDF_MEMORY_KIB_MAX: u32 = 1024 * 1024;
pub const KDF_ITERATIONS_MIN: u32 = 3;
pub const KDF_ITERATIONS_MAX: u32 = 10;
pub const KDF_PARALLELISM_MIN: u32 = 1;
pub const KDF_PARALLELISM_MAX: u32 = 8;

pub const DEFAULT_KEYFILE_PARAMS: KdfParams = KdfParams {
    memory_kib: KDF_MEMORY_KIB_MIN,
    iterations: KDF_ITERATIONS_MIN,
    parallelism: 1,
    output_len: 32,
};

pub const DEFAULT_PASSWORD_PARAMS: KdfParams = KdfParams {
    memory_kib: 128 * 1024,
    iterations: 4,
    parallelism: 1,
    output_len: 32,
};

impl Default for KdfParams {
    fn default() -> Self {
        DEFAULT_KEYFILE_PARAMS
    }
}

pub fn derive_key(
    key_material: &[u8],
    salt: &[u8],
    params: KdfParams,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let argon2_params = Params::new(
        params.memory_kib,
        params.iterations,
        params.parallelism,
        Some(params.output_len),
    )?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params);

    let mut output = Zeroizing::new(vec![0u8; params.output_len]);
    argon2.hash_password_into(key_material, salt, output.as_mut_slice())?;

    Ok(output)
}

pub fn generate_salt(len: usize) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let mut salt = Zeroizing::new(vec![0u8; len]);
    OsRng.fill_bytes(salt.as_mut_slice());
    Ok(salt)
}

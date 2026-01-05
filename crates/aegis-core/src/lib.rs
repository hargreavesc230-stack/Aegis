#![deny(warnings)]
#![deny(clippy::all)]

pub mod checksum;
pub mod crypto;
pub mod error;
pub mod io_ext;
pub mod util;
pub mod version;

pub use checksum::{crc32, Crc32};
pub use crypto::{aead, ids, kdf, keyfile, CryptoError};
pub use error::AegisError;
pub use io_ext::{copy_exact, read_exact_or_err, skip_exact};
pub use util::{ct_eq, zeroize_bytes};

pub type Result<T> = std::result::Result<T, AegisError>;

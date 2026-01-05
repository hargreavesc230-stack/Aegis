#![deny(warnings)]
#![deny(clippy::all)]

pub mod error;
pub mod util;
pub mod version;

pub use error::AegisError;
pub use util::{ct_eq, zeroize_bytes};

pub type Result<T> = std::result::Result<T, AegisError>;

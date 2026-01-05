use std::io;

use thiserror::Error;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum AegisError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("invalid input: {0}")]
    InvalidInput(String),
    #[error("unsupported feature: {0}")]
    Unsupported(String),
    #[error("operation unavailable: {0}")]
    Unavailable(String),
}

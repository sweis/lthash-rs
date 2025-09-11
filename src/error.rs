use thiserror::Error;

#[derive(Error, Debug)]
pub enum LtHashError {
    #[error("Invalid key size: expected {expected}, got {actual}")]
    InvalidKeySize { expected: String, actual: usize },

    #[error("Invalid salt length: expected 16 bytes, got {0}")]
    InvalidSaltLength(usize),

    #[error("Invalid personalization length: expected 16 bytes, got {0}")]
    InvalidPersonalizationLength(usize),

    #[error("Output length too large: max {max}, got {actual}")]
    OutputLengthTooLarge { max: usize, actual: usize },

    #[error("Output buffer size mismatch: expected {expected}, got {actual}")]
    OutputSizeMismatch { expected: usize, actual: usize },

    #[error("Invalid checksum size: expected {expected}, got {actual}")]
    InvalidChecksumSize { expected: usize, actual: usize },

    #[error("Invalid checksum: non-zero padding bits")]
    InvalidChecksumPadding,

    #[error("Must call init() before calling {method}")]
    NotInitialized { method: String },

    #[error("Cannot call {method} after finish()")]
    AlreadyFinished { method: String },

    #[error("{0} already called")]
    AlreadyCalled(String),

    #[error("Blake2b operation failed: {0}")]
    Blake2Error(String),
}

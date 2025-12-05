use thiserror::Error;

#[derive(Error, Debug)]
pub enum LtHashError {
    #[error("Invalid key size: expected {expected}, got {actual}")]
    InvalidKeySize {
        expected: &'static str,
        actual: usize,
    },

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
    NotInitialized { method: &'static str },

    #[error("Cannot call {method} after finish()")]
    AlreadyFinished { method: &'static str },

    #[error("{0} already called")]
    AlreadyCalled(&'static str),

    #[error("Blake2b operation failed: {0}")]
    Blake2Error(&'static str),

    #[error("Key mismatch: cannot combine LtHashes with different keys")]
    KeyMismatch,

    #[error("Unsupported element size: {actual} bits (must be 16, 20, or 32)")]
    UnsupportedElementSize { actual: usize },

    #[error("Element count too small: minimum {minimum}, got {actual}")]
    ElementCountTooSmall { minimum: usize, actual: usize },

    #[error(
        "Element count {element_count} not divisible by elements per u64 ({elements_per_u64})"
    )]
    ElementCountNotDivisible {
        element_count: usize,
        elements_per_u64: usize,
    },
}

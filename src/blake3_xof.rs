//! BLAKE3 XOF - Extendable Output Function using BLAKE3
//!
//! This module provides a BLAKE3-based XOF that can be used as an alternative
//! to Blake2xb for LtHash. BLAKE3 offers better performance (especially with
//! SIMD) and is a pure Rust implementation with no C dependencies.
//!
//! ## Security Properties
//!
//! BLAKE3 provides:
//! - 256-bit security level
//! - Collision resistance
//! - Preimage resistance
//! - Pseudorandom output (XOF mode)
//! - No length extension attacks
//!
//! These properties satisfy the requirements for LtHash's underlying hash function
//! as specified in the academic papers.
//!
//! ## Differences from Blake2xb
//!
//! - Keys must be exactly 32 bytes (Blake2xb accepts 16-64 bytes)
//! - No salt or personalization parameters (not needed for LtHash)
//! - Generally faster, especially on modern CPUs with SIMD support
//!
//! ## Compatibility
//!
//! Note: This backend produces DIFFERENT output than Blake2xb/Folly.
//! Use only if you don't need compatibility with Facebook's C++ implementation.

use crate::error::LtHashError;

/// BLAKE3 XOF hasher
///
/// Provides the same interface as Blake2xb but uses BLAKE3 internally.
pub struct Blake3Xof {
    hasher: Option<blake3::Hasher>,
    output_length: usize,
    finished: bool,
}

impl Blake3Xof {
    /// Maximum supported output length (effectively unlimited for BLAKE3)
    pub const MAX_OUTPUT_LENGTH: usize = usize::MAX;

    /// Create a new BLAKE3 XOF hasher
    pub fn new() -> Self {
        Blake3Xof {
            hasher: None,
            output_length: 0,
            finished: false,
        }
    }

    /// Initialize the hasher
    ///
    /// # Arguments
    /// * `output_length` - Desired output length in bytes
    /// * `key` - Optional key (must be exactly 32 bytes if provided, or empty)
    /// * `_salt` - Ignored (BLAKE3 doesn't support salt)
    /// * `_personalization` - Ignored (BLAKE3 doesn't support personalization)
    pub fn init(
        &mut self,
        output_length: usize,
        key: &[u8],
        _salt: &[u8],
        _personalization: &[u8],
    ) -> Result<(), LtHashError> {
        // Note: For BLAKE3, MAX_OUTPUT_LENGTH is usize::MAX, so this check
        // is effectively a no-op but kept for API consistency with Blake2xb
        #[allow(clippy::absurd_extreme_comparisons)]
        if output_length > Self::MAX_OUTPUT_LENGTH {
            return Err(LtHashError::OutputLengthTooLarge {
                max: Self::MAX_OUTPUT_LENGTH,
                actual: output_length,
            });
        }

        let hasher = if key.is_empty() {
            blake3::Hasher::new()
        } else if key.len() == 32 {
            // Key should already be derived to 32 bytes by LtHash::set_key()
            let key_array: [u8; 32] = key.try_into().unwrap();
            blake3::Hasher::new_keyed(&key_array)
        } else {
            // Fallback for direct Blake3Xof usage with non-32-byte keys
            let derived_key = blake3::derive_key("lthash-rs blake3xof key", key);
            blake3::Hasher::new_keyed(&derived_key)
        };

        self.hasher = Some(hasher);
        self.output_length = output_length;
        self.finished = false;
        Ok(())
    }

    /// Update the hasher with input data
    pub fn update(&mut self, data: &[u8]) -> Result<(), LtHashError> {
        let hasher = self
            .hasher
            .as_mut()
            .ok_or(LtHashError::NotInitialized { method: "update" })?;

        if self.finished {
            return Err(LtHashError::AlreadyFinished { method: "update" });
        }

        hasher.update(data);
        Ok(())
    }

    /// Update the hasher by streaming data from a reader.
    ///
    /// Reads data in chunks to avoid loading the entire input into memory.
    /// Returns the total number of bytes read.
    pub fn update_reader<R: std::io::Read>(&mut self, mut reader: R) -> Result<u64, LtHashError> {
        let hasher = self.hasher.as_mut().ok_or(LtHashError::NotInitialized {
            method: "update_reader",
        })?;

        if self.finished {
            return Err(LtHashError::AlreadyFinished {
                method: "update_reader",
            });
        }

        // Use 8KB buffer - good balance for I/O and cache efficiency
        let mut buffer = [0u8; 8192];
        let mut total_bytes = 0u64;

        loop {
            let bytes_read = reader
                .read(&mut buffer)
                .map_err(|_| LtHashError::IoError("error reading from stream"))?;

            if bytes_read == 0 {
                break;
            }

            hasher.update(&buffer[..bytes_read]);
            total_bytes += bytes_read as u64;
        }

        Ok(total_bytes)
    }

    /// Finalize and write output
    pub fn finish(&mut self, out: &mut [u8]) -> Result<(), LtHashError> {
        let hasher = self
            .hasher
            .as_ref()
            .ok_or(LtHashError::NotInitialized { method: "finish" })?;

        if self.finished {
            return Err(LtHashError::AlreadyCalled("finish"));
        }

        if self.output_length != 0 && out.len() != self.output_length {
            return Err(LtHashError::OutputSizeMismatch {
                expected: self.output_length,
                actual: out.len(),
            });
        }

        // Use XOF mode to generate arbitrary-length output
        let mut output_reader = hasher.finalize_xof();
        output_reader.fill(out);

        self.finished = true;
        Ok(())
    }

    /// One-shot hash function
    ///
    /// # Arguments
    /// * `out` - Output buffer (length determines XOF output size)
    /// * `data` - Input data to hash
    /// * `key` - Optional key (32 bytes, or empty for unkeyed)
    /// * `_salt` - Ignored (BLAKE3 doesn't support salt)
    /// * `_personalization` - Ignored (BLAKE3 doesn't support personalization)
    #[must_use = "this returns a Result that must be checked"]
    pub fn hash(
        out: &mut [u8],
        data: &[u8],
        key: &[u8],
        _salt: &[u8],
        _personalization: &[u8],
    ) -> Result<(), LtHashError> {
        let mut hasher = if key.is_empty() {
            blake3::Hasher::new()
        } else if key.len() == 32 {
            let key_array: [u8; 32] = key.try_into().unwrap();
            blake3::Hasher::new_keyed(&key_array)
        } else {
            let derived_key = blake3::derive_key("lthash-rs blake3xof key", key);
            blake3::Hasher::new_keyed(&derived_key)
        };

        hasher.update(data).finalize_xof().fill(out);
        Ok(())
    }
}

impl Default for Blake3Xof {
    fn default() -> Self {
        Self::new()
    }
}

// Note: We don't implement Drop for Blake3Xof because:
// 1. blake3::Hasher doesn't implement Zeroize, so we can't guarantee its
//    internal state is zeroed before deallocation anyway
// 2. Setting primitive fields to 0/false before drop has no security benefit
// 3. The default drop behavior is sufficient

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_hash() {
        let mut output = [0u8; 64];
        Blake3Xof::hash(&mut output, b"hello world", &[], &[], &[]).unwrap();
        assert_ne!(output, [0u8; 64]);
    }

    #[test]
    fn test_xof_different_lengths() {
        let mut out_64 = [0u8; 64];
        let mut out_2048 = [0u8; 2048];

        Blake3Xof::hash(&mut out_64, b"test", &[], &[], &[]).unwrap();
        Blake3Xof::hash(&mut out_2048, b"test", &[], &[], &[]).unwrap();

        // First 64 bytes should match
        assert_eq!(&out_64[..], &out_2048[..64]);
    }

    #[test]
    fn test_keyed_hash_32_bytes() {
        let key = [42u8; 32];
        let mut out1 = [0u8; 64];
        let mut out2 = [0u8; 64];

        Blake3Xof::hash(&mut out1, b"test", &key, &[], &[]).unwrap();
        Blake3Xof::hash(&mut out2, b"test", &[], &[], &[]).unwrap();

        // Keyed and unkeyed should differ
        assert_ne!(out1, out2);
    }

    #[test]
    fn test_keyed_hash_variable_length() {
        // Test that non-32-byte keys work via derivation
        let key_16 = [42u8; 16];
        let key_64 = [42u8; 64];
        let mut out1 = [0u8; 64];
        let mut out2 = [0u8; 64];

        Blake3Xof::hash(&mut out1, b"test", &key_16, &[], &[]).unwrap();
        Blake3Xof::hash(&mut out2, b"test", &key_64, &[], &[]).unwrap();

        // Different keys should produce different outputs
        assert_ne!(out1, out2);
    }

    #[test]
    fn test_deterministic() {
        let mut out1 = [0u8; 2048];
        let mut out2 = [0u8; 2048];

        Blake3Xof::hash(&mut out1, b"same input", &[], &[], &[]).unwrap();
        Blake3Xof::hash(&mut out2, b"same input", &[], &[], &[]).unwrap();

        assert_eq!(out1, out2);
    }

    #[test]
    fn test_streaming() {
        let mut xof = Blake3Xof::new();
        xof.init(64, &[], &[], &[]).unwrap();
        xof.update(b"hello ").unwrap();
        xof.update(b"world").unwrap();
        let mut out_streaming = [0u8; 64];
        xof.finish(&mut out_streaming).unwrap();

        let mut out_oneshot = [0u8; 64];
        Blake3Xof::hash(&mut out_oneshot, b"hello world", &[], &[], &[]).unwrap();

        assert_eq!(out_streaming, out_oneshot);
    }
}

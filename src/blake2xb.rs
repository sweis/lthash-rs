//! Blake2xb - Extendable Output Function (XOF) based on Blake2b
//!
//! This module implements Blake2xb, an extendable output variant of the Blake2b
//! cryptographic hash function. Blake2xb is used as the underlying primitive
//! for LtHash homomorphic hashing operations.
//!
//! ## Algorithm Overview
//!
//! Blake2xb extends Blake2b to support arbitrary output lengths (up to 2^32-2 bytes)
//! using a tree-mode construction. The algorithm works in two phases:
//!
//! 1. **Root Phase**: Compute h0 = Blake2b(input) with maximum output length (64 bytes)
//! 2. **Expansion Phase**: Generate additional output by computing Blake2b(h0) with
//!    different node parameters for each 64-byte block of output
//!
//! This implementation is fully compatible with Facebook's Folly Blake2xb implementation
//! (folly/crypto/Blake2xb.h) and follows the same parameter encoding and expansion logic.
//!
//! ## Compatibility
//!
//! This Blake2xb implementation is designed to be binary-compatible with:
//! - Facebook's Folly library implementation
//! - The C++ reference implementation used in Facebook's homomorphic hashing system
//! - The Blake2xb specification for tree-mode operations
//!
//! ## Security Properties
//!
//! Blake2xb inherits the security properties of Blake2b:
//! - Collision resistance
//! - Preimage resistance  
//! - Second preimage resistance
//! - Pseudorandom output for arbitrary lengths

use crate::error::LtHashError;
use std::mem;
use std::ptr;
use zeroize::Zeroize;

#[cfg(feature = "sodium")]
use libsodium_sys::*;

/// Blake2xb parameter block - matches the C++ Folly implementation layout
///
/// This structure defines the Blake2xb-specific parameters used for tree-mode
/// hashing and XOF expansion. The layout is binary-compatible with Facebook's
/// Folly implementation.
#[repr(C)]
#[derive(Copy, Clone)]
struct Blake2xbParam {
    digest_length: u8,  // Output length for this node (1-64 bytes)
    key_length: u8,     // Key length (0-64 bytes)
    fanout: u8,         // Fanout parameter for tree mode
    depth: u8,          // Depth parameter for tree mode
    leaf_length: u32,   // Leaf length for tree mode
    node_offset: u32,   // Node offset for parallel tree construction
    xof_length: u32,    // Total XOF output length (little-endian)
    node_depth: u8,     // Current node depth in tree
    inner_length: u8,   // Inner hash length for tree mode
    reserved: [u8; 14], // Reserved bytes (must be zero)
    salt: [u8; 16],     // Optional salt (16 bytes)
    personal: [u8; 16], // Optional personalization (16 bytes)
}

/// Blake2xb hasher state
///
/// This structure maintains the state for Blake2xb hashing operations,
/// including the underlying Blake2b state and XOF expansion parameters.
/// The implementation supports both streaming and one-shot hashing modes.
pub struct Blake2xb {
    param: Blake2xbParam,
    state: crypto_generichash_blake2b_state,
    output_length_known: bool,
    initialized: bool,
    finished: bool,
}

impl Blake2xb {
    /// Minimum supported output length for Blake2xb
    pub const MIN_OUTPUT_LENGTH: usize = 1;

    /// Maximum supported output length for Blake2xb (2^32-2 bytes ≈ 4GB)
    /// This limit matches the Facebook Folly implementation
    pub const MAX_OUTPUT_LENGTH: usize = 0xfffffffe;

    /// Special value indicating unknown output length for streaming mode
    pub const UNKNOWN_OUTPUT_LENGTH: usize = 0;

    pub fn new() -> Self {
        Blake2xb {
            param: Blake2xbParam {
                digest_length: 0,
                key_length: 0,
                fanout: 0,
                depth: 0,
                leaf_length: 0,
                node_offset: 0,
                xof_length: 0,
                node_depth: 0,
                inner_length: 0,
                reserved: [0; 14],
                salt: [0; 16],
                personal: [0; 16],
            },
            state: unsafe { mem::zeroed() },
            output_length_known: false,
            initialized: false,
            finished: false,
        }
    }

    pub fn with_params(
        output_length: usize,
        key: &[u8],
        salt: &[u8],
        personalization: &[u8],
    ) -> Result<Self, LtHashError> {
        let mut blake2xb = Self::new();
        blake2xb.init(output_length, key, salt, personalization)?;
        Ok(blake2xb)
    }

    pub fn init(
        &mut self,
        output_length: usize,
        key: &[u8],
        salt: &[u8],
        personalization: &[u8],
    ) -> Result<(), LtHashError> {
        if output_length != Self::UNKNOWN_OUTPUT_LENGTH && output_length > Self::MAX_OUTPUT_LENGTH {
            return Err(LtHashError::OutputLengthTooLarge {
                max: Self::MAX_OUTPUT_LENGTH,
                actual: output_length,
            });
        }

        if !key.is_empty() && key.len() > 64 {
            return Err(LtHashError::InvalidKeySize {
                expected: "0-64 bytes".to_string(),
                actual: key.len(),
            });
        }

        if !salt.is_empty() && salt.len() != 16 {
            return Err(LtHashError::InvalidSaltLength(salt.len()));
        }

        if !personalization.is_empty() && personalization.len() != 16 {
            return Err(LtHashError::InvalidPersonalizationLength(
                personalization.len(),
            ));
        }

        // Initialize Blake2xb parameters
        let actual_output_length = if output_length == Self::UNKNOWN_OUTPUT_LENGTH {
            self.output_length_known = false;
            0xffffffffu32
        } else {
            self.output_length_known = true;
            output_length as u32
        };

        self.param = Blake2xbParam {
            digest_length: crypto_generichash_blake2b_BYTES_MAX as u8,
            key_length: key.len() as u8,
            fanout: 1,
            depth: 1,
            leaf_length: 0,
            node_offset: 0,
            xof_length: actual_output_length.to_le(),
            node_depth: 0,
            inner_length: 0,
            reserved: [0; 14],
            salt: [0; 16],
            personal: [0; 16],
        };

        // Copy salt and personalization
        if !salt.is_empty() {
            self.param.salt.copy_from_slice(salt);
        }
        if !personalization.is_empty() {
            self.param.personal.copy_from_slice(personalization);
        }

        // Initialize the Blake2b state with our parameters
        self.init_state_from_params(key)?;

        self.initialized = true;
        self.finished = false;
        Ok(())
    }

    pub fn update(&mut self, data: &[u8]) -> Result<(), LtHashError> {
        if !self.initialized {
            return Err(LtHashError::NotInitialized {
                method: "update".to_string(),
            });
        }
        if self.finished {
            return Err(LtHashError::AlreadyFinished {
                method: "update".to_string(),
            });
        }

        let result = unsafe {
            crypto_generichash_blake2b_update(&mut self.state, data.as_ptr(), data.len() as u64)
        };

        if result != 0 {
            return Err(LtHashError::Blake2Error(
                "crypto_generichash_blake2b_update failed".to_string(),
            ));
        }

        Ok(())
    }

    pub fn finish(&mut self, out: &mut [u8]) -> Result<(), LtHashError> {
        if !self.initialized {
            return Err(LtHashError::NotInitialized {
                method: "finish".to_string(),
            });
        }
        if self.finished {
            return Err(LtHashError::AlreadyCalled("finish".to_string()));
        }

        if self.output_length_known {
            let expected_len = u32::from_le(self.param.xof_length) as usize;
            if expected_len != 0xffffffff && out.len() != expected_len {
                return Err(LtHashError::Blake2Error(format!(
                    "Output length mismatch: expected {}, got {}",
                    expected_len,
                    out.len()
                )));
            }
        }

        // Step 1: Compute h0 (finalize the current state)
        let mut h0 = [0u8; 64];
        let result =
            unsafe { crypto_generichash_blake2b_final(&mut self.state, h0.as_mut_ptr(), h0.len()) };

        if result != 0 {
            h0.zeroize(); // Securely clear h0 on error
            return Err(LtHashError::Blake2Error(
                "crypto_generichash_blake2b_final failed".to_string(),
            ));
        }

        // Step 2: Blake2xb XOF expansion
        //
        // For outputs longer than 64 bytes, we use the tree-mode expansion:
        // Each 64-byte block of output is computed as Blake2b(h0) with unique
        // node parameters. This follows the Blake2xb specification and ensures
        // compatibility with Facebook's Folly implementation.
        let mut pos = 0;
        let mut remaining = out.len();

        while remaining > 0 {
            let len = std::cmp::min(crypto_generichash_blake2b_BYTES_MAX as usize, remaining);

            // Setup parameters for expansion node
            // Each expansion node has a unique node_offset to ensure different outputs
            let mut expansion_param = self.param;
            expansion_param.key_length = 0; // No key for expansion nodes
            expansion_param.fanout = 0; // Sequential mode
            expansion_param.depth = 0; // Leaf nodes
            expansion_param.leaf_length = crypto_generichash_blake2b_BYTES_MAX.to_le();
            expansion_param.node_offset =
                ((pos / crypto_generichash_blake2b_BYTES_MAX as usize) as u32).to_le();
            expansion_param.inner_length = crypto_generichash_blake2b_BYTES_MAX as u8;
            expansion_param.digest_length = len as u8;

            // Initialize new state for this expansion node
            let mut expansion_state: crypto_generichash_blake2b_state = unsafe { mem::zeroed() };
            Self::init_state_from_params_raw(&mut expansion_state, &expansion_param, &[])?;

            // Update with h0
            let result = unsafe {
                crypto_generichash_blake2b_update(
                    &mut expansion_state,
                    h0.as_ptr(),
                    h0.len() as u64,
                )
            };

            if result != 0 {
                h0.zeroize(); // Securely clear h0 on error
                return Err(LtHashError::Blake2Error(
                    "crypto_generichash_blake2b_update failed in expansion".to_string(),
                ));
            }

            // Finalize this expansion node
            let result = unsafe {
                crypto_generichash_blake2b_final(
                    &mut expansion_state,
                    out.as_mut_ptr().add(pos),
                    len,
                )
            };

            if result != 0 {
                h0.zeroize(); // Securely clear h0 on error
                return Err(LtHashError::Blake2Error(
                    "crypto_generichash_blake2b_final failed in expansion".to_string(),
                ));
            }

            pos += len;
            remaining -= len;
        }

        // Securely clear the intermediate hash value
        h0.zeroize();

        self.finished = true;
        Ok(())
    }

    /// One-shot Blake2xb hashing function
    ///
    /// Computes Blake2xb hash of the input data with the specified parameters.
    /// This is a convenience function that internally creates a hasher instance,
    /// initializes it, processes the data, and finalizes the output.
    ///
    /// # Arguments
    /// * `out` - Output buffer (length determines XOF output size)
    /// * `data` - Input data to hash
    /// * `key` - Optional key (0-64 bytes, empty slice for no key)
    /// * `salt` - Optional salt (must be exactly 16 bytes or empty)
    /// * `personalization` - Optional personalization (must be exactly 16 bytes or empty)
    ///
    /// # Example
    /// ```no_run
    /// use lthash::Blake2xb;
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut output = vec![0u8; 128];
    /// Blake2xb::hash(&mut output, b"hello world", &[], &[], &[])?;
    /// # Ok(())
    /// # }
    /// ```
    #[must_use = "this returns a Result that must be checked"]
    pub fn hash(
        out: &mut [u8],
        data: &[u8],
        key: &[u8],
        salt: &[u8],
        personalization: &[u8],
    ) -> Result<(), LtHashError> {
        let mut blake2xb = Self::new();
        blake2xb.init(out.len(), key, salt, personalization)?;
        blake2xb.update(data)?;
        blake2xb.finish(out)?;
        Ok(())
    }

    fn init_state_from_params(&mut self, key: &[u8]) -> Result<(), LtHashError> {
        let param_copy = self.param;
        Self::init_state_from_params_raw(&mut self.state, &param_copy, key)
    }

    /// Initialize Blake2b state with Blake2xb parameters
    ///
    /// This function manually initializes the Blake2b state by XORing the
    /// initialization vector with the Blake2xb parameter block. This is
    /// necessary because libsodium doesn't directly support Blake2xb parameters.
    ///
    /// The parameter encoding follows the Blake2b specification and ensures
    /// compatibility with Facebook's Folly implementation.
    fn init_state_from_params_raw(
        state: &mut crypto_generichash_blake2b_state,
        param: &Blake2xbParam,
        key: &[u8],
    ) -> Result<(), LtHashError> {
        // Blake2b initialization vector constants (from Blake2b specification)
        const BLAKE2B_IV: [u64; 8] = [
            0x6a09e667f3bcc908,
            0xbb67ae8584caa73b,
            0x3c6ef372fe94f82b,
            0xa54ff53a5f1d36f1,
            0x510e527fade682d1,
            0x9b05688c2b3e6c1f,
            0x1f83d9abfb41bd6b,
            0x5be0cd19137e2179,
        ];

        // Initialize state manually following Blake2b parameter block specification
        // This mirrors the initialization logic in Facebook's Folly implementation
        unsafe {
            // Zero out the entire state structure
            ptr::write_bytes(
                state as *mut _ as *mut u8,
                0,
                mem::size_of::<crypto_generichash_blake2b_state>(),
            );

            // Cast parameter block to u64 array for XORing with IV
            let param_u64 = param as *const Blake2xbParam as *const u64;

            // Access the hash state vector (h[0..7]) within the Blake2b state
            // This is required for proper Blake2xb parameter integration
            let state_h = state as *mut crypto_generichash_blake2b_state as *mut u64;

            // Initialize h[0..7] = IV[0..7] XOR param[0..7]
            // This encodes the Blake2xb parameters into the Blake2b state
            for (i, &iv_val) in BLAKE2B_IV.iter().enumerate() {
                let param_val = if i < mem::size_of::<Blake2xbParam>() / 8 {
                    u64::from_le(ptr::read(param_u64.add(i)))
                } else {
                    0
                };
                ptr::write(state_h.add(i), iv_val ^ param_val);
            }
        }

        // If we have a key, process it
        if !key.is_empty() {
            if key.len() > 64 {
                return Err(LtHashError::InvalidKeySize {
                    expected: "0-64 bytes".to_string(),
                    actual: key.len(),
                });
            }

            // Create 128-byte padded key block
            let mut key_block = [0u8; 128];
            key_block[..key.len()].copy_from_slice(key);

            let result = unsafe {
                crypto_generichash_blake2b_update(state, key_block.as_ptr(), key_block.len() as u64)
            };

            // Securely clear the key block after use
            key_block.zeroize();

            if result != 0 {
                return Err(LtHashError::Blake2Error(
                    "crypto_generichash_blake2b_update failed for key".to_string(),
                ));
            }
        }

        Ok(())
    }
}

impl Default for Blake2xb {
    fn default() -> Self {
        Self::new()
    }
}

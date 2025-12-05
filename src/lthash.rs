//! LtHash - Lattice-based Homomorphic Hash Function
//!
//! This module implements LtHash (Lattice Hash), a cryptographic hash function that supports
//! homomorphic operations, allowing efficient combining and updating of hash values without
//! recomputing from scratch.
//!
//! ## Background and Theory
//!
//! LtHash was originally proposed by Bellare and Micciancio in their paper "A Concrete Security
//! Treatment of Symmetric Encryption" and later refined for practical use by Facebook.
//! The algorithm provides several key properties:
//!
//! ### Homomorphic Properties
//!
//! LtHash supports **set homomorphism**, meaning:
//! - **Commutative**: `H(a + b) = H(b + a)` - order doesn't matter
//! - **Additive**: `H(S ∪ T) = H(S) + H(T)` for disjoint sets S and T
//! - **Subtractive**: `H(S \ T) = H(S) - H(T)` for T ⊆ S
//!
//! This allows efficient operations like:
//! ```no_run
//! use lthash::LtHash16_1024;
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Chain multiple operations
//! let mut hash = LtHash16_1024::new()?;
//! hash.add(b"file1")?.add(b"file2")?.add(b"file3")?;
//!
//! // Or combine separate hashes homomorphically
//! let mut hash1 = LtHash16_1024::new()?;
//! hash1.add(b"file1")?;
//!
//! let mut hash2 = LtHash16_1024::new()?;
//! hash2.add(b"file2")?;
//!
//! let combined = hash1 + hash2; // Equivalent to hashing both files together
//! # Ok(())
//! # }
//! ```
//!
//! ### Security Properties
//!
//! - **Collision Resistance**: Computationally infeasible to find two distinct sets with the same hash
//! - **At least 200 bits of security** (as per Facebook's implementation)
//! - **Secure in the random oracle model**
//! - **Lattice-based security**: Relies on well-studied lattice cryptography assumptions
//!
//! ### Algorithm Overview
//!
//! 1. **Element Representation**: Objects are hashed into fixed-size arrays of B-bit elements
//! 2. **Modular Arithmetic**: Operations are performed element-wise modulo 2^B
//! 3. **Packed Storage**: Multiple elements are packed into 64-bit words for efficiency
//! 4. **Blake2xb Backend**: Uses Blake2xb as the underlying hash function for individual objects
//!
//! ### Supported Configurations
//!
//! This implementation supports three configurations compatible with Facebook's Folly library:
//! - `LtHash<16, 1024>`: 16-bit elements, 1024 elements (2048 bytes output)
//! - `LtHash<20, 1008>`: 20-bit elements, 1008 elements (2688 bytes output)
//! - `LtHash<32, 1024>`: 32-bit elements, 1024 elements (4096 bytes output)
//!
//! ### Production Use at Facebook
//!
//! Facebook deployed LtHash in their Location Aware Distribution (LAD) system for:
//! - Efficient database update verification across untrusted networks
//! - Secure propagation of configuration changes
//! - Distributed system integrity checking
//!
//! ## References
//!
//! - [Facebook Engineering Blog: Homomorphic Hashing](https://engineering.fb.com/2019/03/01/security/homomorphic-hashing/)
//! - [IACR ePrint 2019/227: Lattice Cryptography for Updates](https://eprint.iacr.org/2019/227)
//! - [Bellare-Micciancio: Original Paper](https://cseweb.ucsd.edu/~mihir/papers/inc1.pdf)
//! - [Facebook Folly Implementation](https://github.com/facebook/folly/tree/main/folly/crypto)

#[cfg(feature = "folly-compat")]
use crate::blake2xb::Blake2xb;
#[cfg(all(feature = "blake3-backend", not(feature = "folly-compat")))]
use crate::blake3_xof::Blake3Xof;
use crate::error::LtHashError;
use zeroize::Zeroize;

/// Constant-time comparison of two byte slices.
/// Returns true if slices are equal, preventing timing attacks.
#[inline]
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

#[cfg(feature = "parallel")]
use rayon::prelude::*;

/// LtHash instance with compile-time element size and count parameters
///
/// This structure represents a homomorphic hash function with:
/// - `B`: Element size in bits (16, 20, or 32)
/// - `N`: Number of elements (must be ≥ 1000 and divisible by elements_per_u64())
///
/// The checksum is stored as a packed array of B-bit elements, with multiple
/// elements stored in each u64 word for efficiency. Optional cryptographic
/// keys provide authentication when set.
pub struct LtHash<const B: usize, const N: usize> {
    /// Packed checksum data as raw bytes (multiple B-bit elements per u64)
    checksum: Vec<u8>,
    /// Optional cryptographic key for authenticated hashing (derived to 32 bytes)
    key: Option<Vec<u8>>,
    /// Pre-allocated scratch buffer to avoid allocations in add/remove
    scratch: Vec<u8>,
}

// Manual Clone implementation to avoid cloning the scratch buffer unnecessarily
impl<const B: usize, const N: usize> Clone for LtHash<B, N> {
    fn clone(&self) -> Self {
        LtHash {
            checksum: self.checksum.clone(),
            key: self.key.clone(),
            scratch: vec![0u8; Self::checksum_size_bytes()], // Fresh scratch buffer
        }
    }
}

impl<const B: usize, const N: usize> std::fmt::Debug for LtHash<B, N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LtHash")
            .field("checksum_len", &self.checksum.len())
            .field("has_key", &self.key.is_some())
            .finish()
    }
}

impl<const B: usize, const N: usize> LtHash<B, N> {
    #[must_use = "this returns a Result that must be checked"]
    pub fn new() -> Result<Self, LtHashError> {
        Self::compile_time_checks()?;

        let checksum_size = Self::checksum_size_bytes();

        Ok(LtHash {
            checksum: vec![0u8; checksum_size],
            key: None,
            scratch: vec![0u8; checksum_size],
        })
    }

    #[must_use = "this returns a Result that must be checked"]
    pub fn with_checksum(initial_checksum: &[u8]) -> Result<Self, LtHashError> {
        Self::compile_time_checks()?;

        let checksum_size = Self::checksum_size_bytes();

        if initial_checksum.len() != checksum_size {
            return Err(LtHashError::InvalidChecksumSize {
                expected: checksum_size,
                actual: initial_checksum.len(),
            });
        }

        if Self::has_padding_bits() {
            Self::check_padding_bits(initial_checksum)?;
        }

        Ok(LtHash {
            checksum: initial_checksum.to_vec(),
            key: None,
            scratch: vec![0u8; checksum_size],
        })
    }

    fn compile_time_checks() -> Result<(), LtHashError> {
        if N <= 999 {
            return Err(LtHashError::ElementCountTooSmall {
                minimum: 1000,
                actual: N,
            });
        }

        if !matches!(B, 16 | 20 | 32) {
            return Err(LtHashError::UnsupportedElementSize { actual: B });
        }

        let elements_per_u64 = Self::elements_per_u64();
        // Using modulo instead of is_multiple_of() for clarity and compatibility
        #[allow(clippy::manual_is_multiple_of)]
        if N % elements_per_u64 != 0 {
            return Err(LtHashError::ElementCountNotDivisible {
                element_count: N,
                elements_per_u64,
            });
        }

        Ok(())
    }

    /// Set the authentication key for keyed hashing.
    ///
    /// The key material is run through a KDF (BLAKE3 derive_key) to produce
    /// a fixed 32-byte derived key. This allows accepting arbitrary-length
    /// key material while ensuring uniform key distribution.
    ///
    /// For folly-compat mode, the key is used directly (16-64 bytes required)
    /// to maintain compatibility with Facebook's implementation.
    #[must_use = "this returns a Result that must be checked"]
    #[cfg(all(feature = "blake3-backend", not(feature = "folly-compat")))]
    pub fn set_key(&mut self, key: &[u8]) -> Result<(), LtHashError> {
        if key.is_empty() {
            return Err(LtHashError::InvalidKeySize {
                expected: "non-empty",
                actual: 0,
            });
        }

        self.clear_key();
        // Derive a 32-byte key using BLAKE3's KDF
        let derived = blake3::derive_key("lthash-rs v1 keyed hash", key);
        self.key = Some(derived.to_vec());
        Ok(())
    }

    /// Set the authentication key for keyed hashing (folly-compat mode).
    ///
    /// In folly-compat mode, the key is used directly without derivation
    /// to maintain byte-for-byte compatibility with Facebook's implementation.
    #[must_use = "this returns a Result that must be checked"]
    #[cfg(feature = "folly-compat")]
    pub fn set_key(&mut self, key: &[u8]) -> Result<(), LtHashError> {
        if key.len() < 16 || key.len() > 64 {
            return Err(LtHashError::InvalidKeySize {
                expected: "16-64 bytes",
                actual: key.len(),
            });
        }

        self.clear_key();
        self.key = Some(key.to_vec());
        Ok(())
    }

    pub fn clear_key(&mut self) {
        if let Some(ref mut key) = self.key {
            // Securely zero the key using zeroize (won't be optimized away)
            key.zeroize();
        }
        self.key = None;
    }

    pub fn reset(&mut self) {
        self.checksum.fill(0);
    }

    /// Check if the hash state is all zeros (empty/identity state).
    ///
    /// Returns true if no objects have been added, or if all added objects
    /// have been subsequently removed.
    #[must_use]
    pub fn is_zero(&self) -> bool {
        self.checksum.iter().all(|&b| b == 0)
    }

    /// Add data to this hash.
    ///
    /// Accepts any type that can be converted to a byte slice, including:
    /// - `&[u8]` - byte slices
    /// - `&str` and `String` - strings
    /// - `Vec<u8>` - byte vectors
    ///
    /// # Example
    /// ```no_run
    /// use lthash::LtHash16_1024;
    ///
    /// let mut hash = LtHash16_1024::new().unwrap();
    /// hash.add(b"bytes").unwrap();
    /// hash.add("string").unwrap();
    /// hash.add(&vec![1u8, 2, 3]).unwrap();
    /// ```
    #[must_use = "this returns a Result that must be checked"]
    pub fn add<T: AsRef<[u8]>>(&mut self, data: T) -> Result<&mut Self, LtHashError> {
        self.hash_into_scratch(data.as_ref())?;
        Self::math_add(&mut self.checksum, &self.scratch)?;
        Ok(self)
    }

    /// Remove data from this hash.
    ///
    /// Accepts any type that can be converted to a byte slice.
    /// The data must have been previously added for the result to be meaningful.
    #[must_use = "this returns a Result that must be checked"]
    pub fn remove<T: AsRef<[u8]>>(&mut self, data: T) -> Result<&mut Self, LtHashError> {
        self.hash_into_scratch(data.as_ref())?;
        Self::math_subtract(&mut self.checksum, &self.scratch)?;
        Ok(self)
    }

    /// Add data to the hash by streaming from a reader.
    ///
    /// This is the preferred method for large files as it processes data in
    /// chunks without loading the entire file into memory.
    ///
    /// # Example
    /// ```no_run
    /// use lthash::LtHash16_1024;
    /// use std::fs::File;
    ///
    /// let mut hash = LtHash16_1024::new().unwrap();
    /// let file = File::open("large_file.bin").unwrap();
    /// hash.add_stream(file).unwrap();
    /// ```
    #[must_use = "this returns a Result that must be checked"]
    pub fn add_stream<R: std::io::Read>(&mut self, reader: R) -> Result<&mut Self, LtHashError> {
        self.hash_reader_into_scratch(reader)?;
        Self::math_add(&mut self.checksum, &self.scratch)?;
        Ok(self)
    }

    /// Remove data from the hash by streaming from a reader.
    ///
    /// This is the preferred method for large files as it processes data in
    /// chunks without loading the entire file into memory.
    #[must_use = "this returns a Result that must be checked"]
    pub fn remove_stream<R: std::io::Read>(&mut self, reader: R) -> Result<&mut Self, LtHashError> {
        self.hash_reader_into_scratch(reader)?;
        Self::math_subtract(&mut self.checksum, &self.scratch)?;
        Ok(self)
    }

    /// Hash multiple items in parallel and add them to this hash.
    ///
    /// This method uses rayon to hash each item in a separate thread,
    /// then combines results using parallel tree reduction. Since LtHash is
    /// homomorphic, the order of addition doesn't matter, making this safe
    /// for parallel execution.
    ///
    /// # Example
    /// ```no_run
    /// use lthash::LtHash16_1024;
    ///
    /// let mut hash = LtHash16_1024::new().unwrap();
    /// let items: Vec<&[u8]> = vec![b"file1", b"file2", b"file3"];
    /// hash.add_parallel(&items).unwrap();
    /// ```
    #[cfg(feature = "parallel")]
    #[must_use = "this returns a Result that must be checked"]
    pub fn add_parallel(&mut self, items: &[&[u8]]) -> Result<&mut Self, LtHashError> {
        let key = self.key.clone();

        let combined: Result<Self, LtHashError> = items
            .par_iter()
            .map(|data| {
                let mut h = Self::new()?;
                if let Some(ref k) = key {
                    h.key = Some(k.clone());
                }
                h.add(data)?;
                Ok(h)
            })
            .try_reduce(
                || Self::new().expect("Failed to create empty LtHash"),
                |mut a, b| {
                    Self::math_add(&mut a.checksum, &b.checksum)?;
                    Ok(a)
                },
            );

        Self::math_add(&mut self.checksum, &combined?.checksum)?;
        Ok(self)
    }

    /// Hash multiple readers in parallel and add them to this hash.
    ///
    /// Each reader is processed in a separate thread using streaming,
    /// so this is efficient for large files. Results are combined using
    /// parallel tree reduction. The readers must implement `Read + Send`
    /// to be safely shared across threads.
    ///
    /// # Example
    /// ```no_run
    /// use lthash::LtHash16_1024;
    /// use std::fs::File;
    ///
    /// let mut hash = LtHash16_1024::new().unwrap();
    /// let files: Vec<File> = vec![
    ///     File::open("file1.bin").unwrap(),
    ///     File::open("file2.bin").unwrap(),
    ///     File::open("file3.bin").unwrap(),
    /// ];
    /// hash.add_streams_parallel(files).unwrap();
    /// ```
    #[cfg(feature = "parallel")]
    #[must_use = "this returns a Result that must be checked"]
    pub fn add_streams_parallel<R: std::io::Read + Send>(
        &mut self,
        readers: Vec<R>,
    ) -> Result<&mut Self, LtHashError> {
        let key = self.key.clone();

        let combined: Result<Self, LtHashError> = readers
            .into_par_iter()
            .map(|reader| {
                let mut h = Self::new()?;
                if let Some(ref k) = key {
                    h.key = Some(k.clone());
                }
                h.add_stream(reader)?;
                Ok(h)
            })
            .try_reduce(
                || Self::new().expect("Failed to create empty LtHash"),
                |mut a, b| {
                    Self::math_add(&mut a.checksum, &b.checksum)?;
                    Ok(a)
                },
            );

        Self::math_add(&mut self.checksum, &combined?.checksum)?;
        Ok(self)
    }

    /// Create a new LtHash by hashing multiple items in parallel.
    ///
    /// This is a convenience method equivalent to creating a new hash
    /// and calling `add_parallel`.
    #[cfg(feature = "parallel")]
    #[must_use = "this returns a Result that must be checked"]
    pub fn from_parallel(items: &[&[u8]]) -> Result<Self, LtHashError> {
        let mut hash = Self::new()?;
        hash.add_parallel(items)?;
        Ok(hash)
    }

    /// Create a new LtHash by hashing multiple readers in parallel.
    ///
    /// This is a convenience method equivalent to creating a new hash
    /// and calling `add_streams_parallel`.
    #[cfg(feature = "parallel")]
    #[must_use = "this returns a Result that must be checked"]
    pub fn from_streams_parallel<R: std::io::Read + Send>(
        readers: Vec<R>,
    ) -> Result<Self, LtHashError> {
        let mut hash = Self::new()?;
        hash.add_streams_parallel(readers)?;
        Ok(hash)
    }

    /// Add multiple items to this hash using map-reduce.
    ///
    /// Each item is hashed independently (map), then all hashes are combined
    /// by addition (reduce). When the `parallel` feature is enabled, this
    /// uses parallel processing for better performance.
    ///
    /// Accepts a slice of any type that can be converted to bytes.
    ///
    /// # Example
    /// ```no_run
    /// use lthash::LtHash16_1024;
    ///
    /// let mut hash = LtHash16_1024::new().unwrap();
    /// hash.add_all(&[b"file1", b"file2", b"file3"]).unwrap();
    /// hash.add_all(&["string1", "string2"]).unwrap();
    /// ```
    #[cfg(feature = "parallel")]
    #[must_use = "this returns a Result that must be checked"]
    pub fn add_all<T: AsRef<[u8]> + Sync>(
        &mut self,
        items: &[T],
    ) -> Result<&mut Self, LtHashError> {
        let key = self.key.clone();

        let combined: Result<Self, LtHashError> = items
            .par_iter()
            .map(|data| {
                let mut h = Self::new()?;
                if let Some(ref k) = key {
                    h.key = Some(k.clone());
                }
                h.add(data.as_ref())?;
                Ok(h)
            })
            .try_reduce(
                || Self::new().expect("Failed to create empty LtHash"),
                |mut a, b| {
                    Self::math_add(&mut a.checksum, &b.checksum)?;
                    Ok(a)
                },
            );

        Self::math_add(&mut self.checksum, &combined?.checksum)?;
        Ok(self)
    }

    /// Add multiple items to this hash sequentially.
    ///
    /// Each item is hashed and added in order. For parallel processing,
    /// enable the `parallel` feature.
    #[cfg(not(feature = "parallel"))]
    #[must_use = "this returns a Result that must be checked"]
    pub fn add_all<T: AsRef<[u8]>>(&mut self, items: &[T]) -> Result<&mut Self, LtHashError> {
        for item in items {
            self.add(item.as_ref())?;
        }
        Ok(self)
    }

    /// Remove multiple items from this hash using map-reduce.
    ///
    /// Each item is hashed independently (map), then all hashes are combined
    /// and subtracted from this hash (reduce). When the `parallel` feature
    /// is enabled, this uses parallel processing for better performance.
    ///
    /// Accepts a slice of any type that can be converted to bytes.
    ///
    /// # Example
    /// ```no_run
    /// use lthash::LtHash16_1024;
    ///
    /// let mut hash = LtHash16_1024::new().unwrap();
    /// hash.add_all(&["a", "b", "c"]).unwrap();
    /// hash.remove_all(&["a", "b"]).unwrap();  // Now contains only "c"
    /// ```
    #[cfg(feature = "parallel")]
    #[must_use = "this returns a Result that must be checked"]
    pub fn remove_all<T: AsRef<[u8]> + Sync>(
        &mut self,
        items: &[T],
    ) -> Result<&mut Self, LtHashError> {
        let key = self.key.clone();

        let combined: Result<Self, LtHashError> = items
            .par_iter()
            .map(|data| {
                let mut h = Self::new()?;
                if let Some(ref k) = key {
                    h.key = Some(k.clone());
                }
                h.add(data.as_ref())?;
                Ok(h)
            })
            .try_reduce(
                || Self::new().expect("Failed to create empty LtHash"),
                |mut a, b| {
                    Self::math_add(&mut a.checksum, &b.checksum)?;
                    Ok(a)
                },
            );

        Self::math_subtract(&mut self.checksum, &combined?.checksum)?;
        Ok(self)
    }

    /// Remove multiple items from this hash sequentially.
    ///
    /// Each item is hashed and removed in order. For parallel processing,
    /// enable the `parallel` feature.
    #[cfg(not(feature = "parallel"))]
    #[must_use = "this returns a Result that must be checked"]
    pub fn remove_all<T: AsRef<[u8]>>(&mut self, items: &[T]) -> Result<&mut Self, LtHashError> {
        for item in items {
            self.remove(item.as_ref())?;
        }
        Ok(self)
    }

    /// Returns the internal checksum state as a byte slice.
    #[must_use]
    pub fn checksum(&self) -> &[u8] {
        &self.checksum
    }

    /// Returns a compact 32-byte BLAKE3 digest of the full checksum state.
    ///
    /// This is useful when you need a fixed-size hash for storage or comparison,
    /// rather than the full 2KB+ checksum. Note that this digest cannot be used
    /// for homomorphic operations - use `checksum()` for that.
    #[cfg(all(feature = "blake3-backend", not(feature = "folly-compat")))]
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        blake3::hash(&self.checksum).into()
    }

    /// Compare this hash's checksum with a raw byte slice using constant-time comparison.
    ///
    /// Returns `Ok(true)` if equal, `Ok(false)` if not equal, or an error if
    /// the provided slice has the wrong length.
    #[must_use = "this returns a Result that must be checked"]
    pub fn checksum_eq(&self, other: &[u8]) -> Result<bool, LtHashError> {
        if other.len() != Self::checksum_size_bytes() {
            return Err(LtHashError::InvalidChecksumSize {
                expected: Self::checksum_size_bytes(),
                actual: other.len(),
            });
        }
        Ok(constant_time_eq(&self.checksum, other))
    }

    #[cfg(all(feature = "blake3-backend", not(feature = "folly-compat")))]
    fn hash_into_scratch(&mut self, data: &[u8]) -> Result<(), LtHashError> {
        let key = self.key.as_deref().unwrap_or(&[]);
        Blake3Xof::hash(&mut self.scratch, data, key, &[], &[])?;
        if Self::has_padding_bits() {
            Self::clear_padding_bits(&mut self.scratch);
        }
        Ok(())
    }

    #[cfg(feature = "folly-compat")]
    fn hash_into_scratch(&mut self, data: &[u8]) -> Result<(), LtHashError> {
        let key = self.key.as_deref().unwrap_or(&[]);
        Blake2xb::hash(&mut self.scratch, data, key, &[], &[])?;
        if Self::has_padding_bits() {
            Self::clear_padding_bits(&mut self.scratch);
        }
        Ok(())
    }

    #[cfg(all(feature = "blake3-backend", not(feature = "folly-compat")))]
    fn hash_reader_into_scratch<R: std::io::Read>(&mut self, reader: R) -> Result<(), LtHashError> {
        let mut xof = Blake3Xof::new();
        let key = self.key.as_deref().unwrap_or(&[]);
        xof.init(self.scratch.len(), key, &[], &[])?;
        xof.update_reader(reader)?;
        xof.finish(&mut self.scratch)?;
        if Self::has_padding_bits() {
            Self::clear_padding_bits(&mut self.scratch);
        }
        Ok(())
    }

    #[cfg(feature = "folly-compat")]
    fn hash_reader_into_scratch<R: std::io::Read>(&mut self, reader: R) -> Result<(), LtHashError> {
        let mut xof = Blake2xb::new();
        let key = self.key.as_deref().unwrap_or(&[]);
        xof.init(self.scratch.len(), key, &[], &[])?;
        xof.update_reader(reader)?;
        xof.finish(&mut self.scratch)?;
        if Self::has_padding_bits() {
            Self::clear_padding_bits(&mut self.scratch);
        }
        Ok(())
    }

    /// Core homomorphic addition operation
    ///
    /// Performs element-wise modular addition of two hash arrays. This implements
    /// the fundamental homomorphic property: H(A ∪ B) = H(A) + H(B).
    ///
    /// The addition is performed on packed B-bit elements within u64 words,
    /// using specialized logic for different element sizes to match Facebook's
    /// Folly implementation exactly.
    #[inline]
    fn math_add(checksum: &mut [u8], hash: &[u8]) -> Result<(), LtHashError> {
        if checksum.len() != hash.len() {
            return Err(LtHashError::InvalidChecksumSize {
                expected: checksum.len(),
                actual: hash.len(),
            });
        }

        let data_mask = Self::data_mask();
        let checksum_u64 = Self::as_u64_slice_mut(checksum);
        let hash_u64 = Self::as_u64_slice(hash);

        for (c, h) in checksum_u64.iter_mut().zip(hash_u64.iter()) {
            *c = Self::add_with_mask(*c, *h, data_mask);
        }

        Ok(())
    }

    #[inline]
    fn math_subtract(checksum: &mut [u8], hash: &[u8]) -> Result<(), LtHashError> {
        if checksum.len() != hash.len() {
            return Err(LtHashError::InvalidChecksumSize {
                expected: checksum.len(),
                actual: hash.len(),
            });
        }

        let data_mask = Self::data_mask();
        let checksum_u64 = Self::as_u64_slice_mut(checksum);
        let hash_u64 = Self::as_u64_slice(hash);

        for (c, h) in checksum_u64.iter_mut().zip(hash_u64.iter()) {
            *c = Self::subtract_with_mask(*c, *h, data_mask);
        }

        Ok(())
    }

    /// Optimized element-wise addition with masking for different element sizes
    ///
    /// This function implements specialized addition logic for each supported
    /// element size to maximize performance and ensure compatibility with
    /// Facebook's Folly implementation:
    ///
    /// - **16-bit elements**: Uses split-lane arithmetic to process 4 elements per u64
    /// - **32-bit elements**: Uses high/low word splitting for 2 elements per u64
    /// - **20-bit elements**: Uses general masking with padding bit handling
    #[inline(always)]
    fn add_with_mask(a: u64, b: u64, mask: u64) -> u64 {
        match B {
            16 => {
                // Special handling for 16-bit elements (4 per u64)
                // Split into alternating groups: A = W,0,Y,0 and B = 0,X,0,Z
                // This allows parallel processing of all 4 elements
                let mask_a = 0xffff0000ffff0000u64;
                let mask_b = 0x0000ffff0000ffffu64;
                let a_a = a & mask_a;
                let a_b = a & mask_b;
                let b_a = b & mask_a;
                let b_b = b & mask_b;
                let result_a = a_a.wrapping_add(b_a) & mask_a;
                let result_b = a_b.wrapping_add(b_b) & mask_b;
                result_a | result_b
            }
            32 => {
                // Special handling for 32-bit elements (2 per u64)
                // Split into high and low 32-bit halves
                let mask_a = 0xffffffff00000000u64;
                let mask_b = 0x00000000ffffffffu64;
                let a_a = a & mask_a;
                let a_b = a & mask_b;
                let b_a = b & mask_a;
                let b_b = b & mask_b;
                let result_a = a_a.wrapping_add(b_a) & mask_a;
                let result_b = a_b.wrapping_add(b_b) & mask_b;
                result_a | result_b
            }
            _ => {
                // General case for other bit sizes (like 20-bit with padding)
                // Uses simple masking to clear padding bits after addition
                a.wrapping_add(b) & mask
            }
        }
    }

    #[inline(always)]
    fn subtract_with_mask(a: u64, b: u64, mask: u64) -> u64 {
        match B {
            16 => {
                // Special handling for 16-bit elements like C++
                let mask_a = 0xffff0000ffff0000u64;
                let mask_b = 0x0000ffff0000ffffu64;
                let a_a = a & mask_a;
                let a_b = a & mask_b;
                let b_a = b & mask_a;
                let b_b = b & mask_b;
                let result_a = a_a.wrapping_add(mask_b.wrapping_sub(b_a)) & mask_a;
                let result_b = a_b.wrapping_add(mask_a.wrapping_sub(b_b)) & mask_b;
                result_a | result_b
            }
            32 => {
                // Special handling for 32-bit elements like C++
                let mask_a = 0xffffffff00000000u64;
                let mask_b = 0x00000000ffffffffu64;
                let a_a = a & mask_a;
                let a_b = a & mask_b;
                let b_a = b & mask_a;
                let b_b = b & mask_b;
                let result_a = a_a.wrapping_add(mask_b.wrapping_sub(b_a)) & mask_a;
                let result_b = a_b.wrapping_add(mask_a.wrapping_sub(b_b)) & mask_b;
                result_a | result_b
            }
            _ => {
                // General case: (a + ((~mask - b) & mask)) & mask
                a.wrapping_add((!mask).wrapping_sub(b) & mask) & mask
            }
        }
    }

    /// Calculate the total checksum size in bytes
    ///
    /// Returns the number of bytes required to store N elements of B bits each,
    /// packed into u64 words. This must be consistent with Facebook's Folly
    /// implementation for binary compatibility.
    pub const fn checksum_size_bytes() -> usize {
        let elements_per_u64 = Self::elements_per_u64();
        (N / elements_per_u64) * 8 // 8 bytes per u64
    }

    pub const fn element_size_in_bits() -> usize {
        B
    }

    /// Number of B-bit elements that fit in a single u64 word
    ///
    /// This packing scheme must match Facebook's Folly implementation:
    /// - 16-bit: 4 elements per u64 (perfect fit)
    /// - 20-bit: 3 elements per u64 (4 padding bits)
    /// - 32-bit: 2 elements per u64 (perfect fit)
    pub const fn elements_per_u64() -> usize {
        match B {
            16 => 4, // 4 * 16 = 64, no padding
            20 => 3, // 3 * 20 = 60, with 4 padding bits at specific positions
            32 => 2, // 2 * 32 = 64, no padding
            _ => panic!("Unsupported element size"),
        }
    }

    pub const fn element_count() -> usize {
        N
    }

    pub const fn has_padding_bits() -> bool {
        B == 20
    }

    /// Bit mask for valid data bits in packed u64 words
    ///
    /// For element sizes that don't perfectly fit in u64, padding bits must be
    /// masked out to ensure correct arithmetic and compatibility with Facebook's
    /// Folly implementation.
    ///
    /// - 16-bit: No padding needed (4 * 16 = 64 bits exactly)
    /// - 20-bit: Padding bits at specific positions (3 * 20 = 60 bits, 4 padding)
    /// - 32-bit: No padding needed (2 * 32 = 64 bits exactly)
    const fn data_mask() -> u64 {
        match B {
            16 => 0xffffffffffffffff,  // No padding
            20 => !0xC000020000100000, // Padding bits at specific positions
            32 => 0xffffffffffffffff,  // No padding
            _ => panic!("Unsupported element size"),
        }
    }

    #[inline]
    fn as_u64_slice(bytes: &[u8]) -> &[u64] {
        debug_assert_eq!(bytes.len() % 8, 0);
        // SAFETY: We use align_to which handles alignment properly.
        // The prefix/suffix being empty is asserted to catch any alignment issues.
        let (prefix, aligned, suffix) = unsafe { bytes.align_to::<u64>() };
        debug_assert!(
            prefix.is_empty() && suffix.is_empty(),
            "Buffer is not properly aligned for u64 access"
        );
        aligned
    }

    #[inline]
    fn as_u64_slice_mut(bytes: &mut [u8]) -> &mut [u64] {
        debug_assert_eq!(bytes.len() % 8, 0);
        // SAFETY: We use align_to_mut which handles alignment properly.
        // The prefix/suffix being empty is asserted to catch any alignment issues.
        let (prefix, aligned, suffix) = unsafe { bytes.align_to_mut::<u64>() };
        debug_assert!(
            prefix.is_empty() && suffix.is_empty(),
            "Buffer is not properly aligned for u64 access"
        );
        aligned
    }

    fn check_padding_bits(data: &[u8]) -> Result<(), LtHashError> {
        if !Self::has_padding_bits() {
            return Ok(());
        }

        let data_mask = Self::data_mask();
        let u64_slice = Self::as_u64_slice(data);

        for &value in u64_slice {
            if value & !data_mask != 0 {
                return Err(LtHashError::InvalidChecksumPadding);
            }
        }

        Ok(())
    }

    fn clear_padding_bits(data: &mut [u8]) {
        if !Self::has_padding_bits() {
            return;
        }

        let data_mask = Self::data_mask();
        let u64_slice = Self::as_u64_slice_mut(data);

        for value in u64_slice {
            *value &= data_mask;
        }
    }

    /// Try to add another LtHash to this one, returning an error if keys don't match.
    ///
    /// This is a non-panicking alternative to the `+` and `+=` operators.
    ///
    /// # Errors
    /// Returns `LtHashError::KeyMismatch` if the two hashes have different keys.
    #[must_use = "this returns a Result that must be checked"]
    pub fn try_add(&mut self, rhs: &Self) -> Result<(), LtHashError> {
        if !self.keys_equal(rhs) {
            return Err(LtHashError::KeyMismatch);
        }
        Self::math_add(&mut self.checksum, &rhs.checksum)
    }

    /// Try to subtract another LtHash from this one, returning an error if keys don't match.
    ///
    /// This is a non-panicking alternative to the `-` and `-=` operators.
    ///
    /// # Errors
    /// Returns `LtHashError::KeyMismatch` if the two hashes have different keys.
    #[must_use = "this returns a Result that must be checked"]
    pub fn try_sub(&mut self, rhs: &Self) -> Result<(), LtHashError> {
        if !self.keys_equal(rhs) {
            return Err(LtHashError::KeyMismatch);
        }
        Self::math_subtract(&mut self.checksum, &rhs.checksum)
    }

    fn keys_equal(&self, other: &Self) -> bool {
        match (&self.key, &other.key) {
            (None, None) => true,
            (Some(a), Some(b)) => constant_time_eq(a, b),
            _ => false,
        }
    }
}

/// Default implementation for LtHash.
///
/// # Panics
/// Panics if the compile-time const generic parameters `B` and `N` are invalid.
/// This will only happen if using unsupported configurations. The standard
/// type aliases (`LtHash16_1024`, `LtHash20_1008`, `LtHash32_1024`) are guaranteed
/// to succeed.
///
/// If you need a fallible constructor, use `LtHash::new()` instead.
impl<const B: usize, const N: usize> Default for LtHash<B, N> {
    fn default() -> Self {
        Self::new().expect("Failed to create default LtHash: invalid B or N parameters")
    }
}

impl<const B: usize, const N: usize> PartialEq for LtHash<B, N> {
    fn eq(&self, other: &Self) -> bool {
        constant_time_eq(&self.checksum, &other.checksum)
    }
}

impl<const B: usize, const N: usize> std::ops::AddAssign for LtHash<B, N> {
    fn add_assign(&mut self, rhs: Self) {
        if !self.keys_equal(&rhs) {
            panic!("Cannot add LtHashes with different keys");
        }
        Self::math_add(&mut self.checksum, &rhs.checksum).expect("Failed to add LtHash checksums");
    }
}

impl<const B: usize, const N: usize> std::ops::Add for LtHash<B, N> {
    type Output = Self;

    fn add(mut self, rhs: Self) -> Self::Output {
        self += rhs;
        self
    }
}

impl<const B: usize, const N: usize> std::ops::SubAssign for LtHash<B, N> {
    fn sub_assign(&mut self, rhs: Self) {
        if !self.keys_equal(&rhs) {
            panic!("Cannot subtract LtHashes with different keys");
        }
        Self::math_subtract(&mut self.checksum, &rhs.checksum)
            .expect("Failed to subtract LtHash checksums");
    }
}

impl<const B: usize, const N: usize> std::ops::Sub for LtHash<B, N> {
    type Output = Self;

    fn sub(mut self, rhs: Self) -> Self::Output {
        self -= rhs;
        self
    }
}

impl<const B: usize, const N: usize> Drop for LtHash<B, N> {
    fn drop(&mut self) {
        // Securely clear all potentially sensitive data
        self.checksum.zeroize();
        self.scratch.zeroize();
        self.clear_key();
    }
}

/// Type aliases for Facebook Folly-compatible configurations
///
/// These type aliases match the configurations used in Facebook's production
/// deployment and provide the same security and performance characteristics.
/// 16-bit elements, 1024 elements total (2048 bytes output)
///
/// Fast and compact configuration suitable for most use cases.
/// Provides good performance with minimal memory usage.
pub type LtHash16_1024 = LtHash<16, 1024>;

/// 20-bit elements, 1008 elements total (2688 bytes output)  
///
/// Balanced configuration with higher element resolution.
/// Uses padding bits which are automatically managed.
pub type LtHash20_1008 = LtHash<20, 1008>;

/// 32-bit elements, 1024 elements total (4096 bytes output)
///
/// High-resolution configuration for applications requiring
/// maximum collision resistance and security margin.
pub type LtHash32_1024 = LtHash<32, 1024>;

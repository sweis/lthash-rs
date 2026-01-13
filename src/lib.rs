//! LtHash-rs: Lattice-based Homomorphic Hashing for Rust
//!
//! This crate provides a Rust implementation of LtHash (Lattice Hash), a cryptographic
//! hash function that supports homomorphic operations, enabling efficient verification
//! and updating of hash values without recomputing from scratch.
//!
//! ## Overview
//!
//! LtHash was originally developed by Bellare and Micciancio and later refined by Facebook
//! for production use in their distributed systems. This implementation is fully compatible
//! with Facebook's C++ reference implementation in the Folly library.
//!
//! ### Key Features
//!
//! - **Homomorphic Properties**: Support for set union, intersection, and difference operations
//! - **High Performance**: Optimized arithmetic for different element sizes (16, 20, 32 bits)
//! - **Production Ready**: Used by Facebook in their Location Aware Distribution system
//! - **Cross-Compatible**: Binary compatibility with Facebook's Folly C++ implementation
//! - **Secure**: At least 200 bits of security based on lattice cryptography
//!
//! ### Use Cases
//!
//! - **Distributed Database Verification**: Efficiently validate database updates across untrusted networks
//! - **Secure Update Propagation**: Enable subscribers to verify data integrity without direct communication
//! - **Incremental Hashing**: Update hash values by adding/removing elements rather than rehashing entire datasets
//! - **Set Reconciliation**: Compare and synchronize distributed datasets using compact representations
//!
//! ## Quick Start
//!
//! ```rust
//! use lthash::{LtHash16_1024, LtHashError};
//!
//! # fn main() -> Result<(), LtHashError> {
//! // Create a new hash instance
//! let mut hash = LtHash16_1024::new()?;
//!
//! // Add some objects (order doesn't matter - commutative)
//! hash.add_object(b"document1")?;
//! hash.add_object(b"document2")?;
//!
//! // Remove an object
//! hash.remove_object(b"document1")?;
//!
//! // Get the final checksum
//! let checksum = hash.get_checksum();
//!
//! // Combine hashes from different sources (homomorphic)
//! let mut hash1 = LtHash16_1024::new()?;
//! hash1.add_object(b"file1")?;
//!
//! let mut hash2 = LtHash16_1024::new()?;
//! hash2.add_object(b"file2")?;
//!
//! let combined = hash1 + hash2; // Same as hashing both files together
//! # Ok(())
//! # }
//! ```
//!
//! ## Module Organization
//!
//! - [`blake2xb`]: Blake2xb Extendable Output Function implementation
//! - [`LtHash`]: Core LtHash implementation with const generic parameters
//! - [`LtHashError`]: Error types for the library
//!
//! ## References
//!
//! - [Facebook Engineering Blog: Homomorphic Hashing](https://engineering.fb.com/2019/03/01/security/homomorphic-hashing/)
//! - [IACR ePrint 2019/227: Lattice Cryptography for Updates](https://eprint.iacr.org/2019/227)
//! - [Bellare-Micciancio: Original Paper](https://cseweb.ucsd.edu/~mihir/papers/inc1.pdf)
//! - [Facebook Folly Implementation](https://github.com/facebook/folly/tree/main/folly/crypto)

// Ensure at least one backend is enabled
#[cfg(not(any(feature = "blake3-backend", feature = "folly-compat")))]
compile_error!(
    "At least one hash backend must be enabled. \
     Use `blake3-backend` (default) for pure Rust, or `folly-compat` for Facebook Folly compatibility."
);

#[cfg(feature = "blake3-backend")]
pub mod blake3_xof;
#[cfg(feature = "folly-compat")]
pub mod blake2xb;
mod error;
mod lthash;

#[cfg(feature = "blake3-backend")]
pub use blake3_xof::Blake3Xof;
#[cfg(feature = "folly-compat")]
pub use blake2xb::Blake2xb;
pub use error::LtHashError;
pub use lthash::{LtHash, LtHash16_1024, LtHash20_1008, LtHash32_1024};

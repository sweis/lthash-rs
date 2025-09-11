# LtHash-rs

A Rust implementation of LtHash (Lattice-based Hash) with Blake2xb, providing cryptographically secure homomorphic hashing capabilities.

# Warning

This is vibe coded by Claude Code. A human has not really even looked at it. But it passes the tests and generates the same bytes as the Facebook Folly C++ implementation. Don't trust it or use it for anything as is. It was just done for fun.

## Overview

LtHash is a lattice-based cryptographic hash function that supports homomorphic operations, enabling efficient verification and updating of hash values without recomputing from scratch. Originally developed by Bellare and Micciancio and refined by Facebook for production use, this implementation is supposed to be compatible with the reference C++ implementation in Facebook's Folly library.

### Background and Applications

This implementation is based on Facebook's homomorphic hashing work, as described in their [2019 engineering blog post](https://engineering.fb.com/2019/03/01/security/homomorphic-hashing/) and detailed in the [IACR ePrint paper 2019/227](https://eprint.iacr.org/2019/227). The algorithm builds upon the foundational work in [Bellare and Micciancio's original paper](https://cseweb.ucsd.edu/~mihir/papers/inc1.pdf).

**Primary Use Cases:**
- **Distributed Database Verification**: Efficiently validate database updates across untrusted networks
- **Secure Update Propagation**: Enable subscribers to verify data integrity without direct distributor communication  
- **Incremental Hashing**: Update hash values by adding/removing individual elements rather than rehashing entire datasets
- **Set Reconciliation**: Compare and synchronize distributed datasets using compact hash representations

Facebook deployed this technology in their Location Aware Distribution (LAD) configuration management system to securely propagate database updates across their global infrastructure.

### Features

- **Blake2xb**: Extendable Output Function (XOF) based on Blake2b
- **LtHash**: Homomorphic hash with three variants:
  - `LtHash<16, 1024>` - 16-bit elements, 1024 elements (2048 bytes output)
  - `LtHash<20, 1008>` - 20-bit elements, 1008 elements (2688 bytes output) 
  - `LtHash<32, 1024>` - 32-bit elements, 1024 elements (4096 bytes output)
- **Homomorphic Properties**: 
  - Commutative: `H(a + b) = H(b + a)`
  - Additive: `H(a) + H(b) = H(a + b)`
  - Subtractive: `H(a) - H(b) = H(a - b)`

## Requirements

- Rust 1.70+ 
- libsodium (automatically installed via `libsodium-sys`)

### Installing libsodium (if needed)

**macOS:**
```bash
brew install libsodium
```

**Ubuntu/Debian:**
```bash
sudo apt-get install libsodium-dev
```

**Windows:**
The `libsodium-sys` crate will automatically download and build libsodium.

## Building

```bash
# Build the library
cargo build --release

# Build with debug symbols
cargo build
```

## Testing

```bash
# Run all tests
cargo test

# Run cross-compatibility tests with C++ implementation
cargo run --bin test_cross_compat

# Run example usage
cargo run --bin lthash_example
```

## Usage

### Blake2xb (Extendable Output Function)

```rust
use lthash::Blake2xb;

// Create hash with any output length (1 to 4GB)
let mut output = vec![0u8; 128];
Blake2xb::hash(&mut output, b"hello world", &[], &[], &[])?;

// With key, salt, and personalization
let key = b"secret key";
let salt = [1u8; 16];
let personal = [2u8; 16];
Blake2xb::hash(&mut output, b"data", key, &salt, &personal)?;
```

### LtHash (Homomorphic Hash)

```rust
use lthash::{LtHash16_1024, LtHashError};

// Create empty hash
let mut hash = LtHash16_1024::new()?;

// Add objects (order doesn't matter - commutative)
hash.add_object(b"document1")?;
hash.add_object(b"document2")?;

// Remove objects
hash.remove_object(b"document1")?;

// Get final checksum
let checksum = hash.get_checksum();

// Combine hashes from different sources
let mut hash1 = LtHash16_1024::new()?;
hash1.add_object(b"file1")?;

let mut hash2 = LtHash16_1024::new()?;
hash2.add_object(b"file2")?;

let combined = hash1 + hash2; // Homomorphic addition
```

### Keyed LtHash

```rust
use lthash::LtHash16_1024;

let mut hash = LtHash16_1024::new()?;

// Set secret key (16-64 bytes)
let key = b"my-secret-key-for-authentication";
hash.set_key(key)?;

hash.add_object(b"sensitive data")?;
let authenticated_checksum = hash.get_checksum();

// Clear key securely
hash.clear_key();
```

## API Reference

### Blake2xb

```rust
impl Blake2xb {
    // Output length constraints
    const MIN_OUTPUT_LENGTH: usize = 1;
    const MAX_OUTPUT_LENGTH: usize = 0xfffffffe; // ~4GB
    const UNKNOWN_OUTPUT_LENGTH: usize = 0;
    
    // One-shot hashing
    fn hash(
        out: &mut [u8],
        data: &[u8], 
        key: &[u8],
        salt: &[u8],
        personalization: &[u8],
    ) -> Result<(), LtHashError>;
    
    // Streaming interface
    fn new() -> Self;
    fn init(&mut self, output_length: usize, key: &[u8], salt: &[u8], personalization: &[u8]) -> Result<(), LtHashError>;
    fn update(&mut self, data: &[u8]) -> Result<(), LtHashError>;
    fn finish(&mut self, out: &mut [u8]) -> Result<(), LtHashError>;
}
```

### LtHash

```rust
impl<const B: usize, const N: usize> LtHash<B, N> {
    // Creation
    fn new() -> Result<Self, LtHashError>;
    fn with_checksum(initial_checksum: &[u8]) -> Result<Self, LtHashError>;
    
    // Key management
    fn set_key(&mut self, key: &[u8]) -> Result<(), LtHashError>;
    fn clear_key(&mut self);
    
    // Operations
    fn add_object(&mut self, data: &[u8]) -> Result<&mut Self, LtHashError>;
    fn remove_object(&mut self, data: &[u8]) -> Result<&mut Self, LtHashError>;
    fn reset(&mut self);
    
    // Checksum access
    fn get_checksum(&self) -> &[u8];
    fn checksum_equals(&self, other_checksum: &[u8]) -> Result<bool, LtHashError>;
    
    // Constants
    fn checksum_size_bytes() -> usize;
    fn element_size_in_bits() -> usize;
    fn elements_per_u64() -> usize;
    fn element_count() -> usize;
    fn has_padding_bits() -> bool;
}

// Homomorphic operations
impl Add<LtHash<B, N>> for LtHash<B, N>;
impl Sub<LtHash<B, N>> for LtHash<B, N>;
impl AddAssign<LtHash<B, N>> for LtHash<B, N>;
impl SubAssign<LtHash<B, N>> for LtHash<B, N>;

// Type aliases
type LtHash16_1024 = LtHash<16, 1024>;
type LtHash20_1008 = LtHash<20, 1008>; 
type LtHash32_1024 = LtHash<32, 1024>;
```

## Error Handling

```rust
#[derive(Debug, thiserror::Error)]
pub enum LtHashError {
    #[error("Blake2 error: {0}")]
    Blake2Error(String),
    
    #[error("Invalid checksum size: expected {expected}, got {actual}")]
    InvalidChecksumSize { expected: usize, actual: usize },
    
    #[error("Output size mismatch: expected {expected}, got {actual}")]
    OutputSizeMismatch { expected: usize, actual: usize },
    
    #[error("Invalid key size: expected {expected}, got {actual}")]
    InvalidKeySize { expected: String, actual: usize },
    
    #[error("Invalid salt length: {0} (must be 16 bytes)")]
    InvalidSaltLength(usize),
    
    #[error("Invalid personalization length: {0} (must be 16 bytes)")]
    InvalidPersonalizationLength(usize),
    
    #[error("Output length too large: max {max}, got {actual}")]
    OutputLengthTooLarge { max: usize, actual: usize },
    
    #[error("Method {method} called before initialization")]
    NotInitialized { method: String },
    
    #[error("Method {method} called after finish")]
    AlreadyFinished { method: String },
    
    #[error("Method {0} already called")]
    AlreadyCalled(String),
    
    #[error("Invalid checksum padding bits")]
    InvalidChecksumPadding,
}
```

## Security Considerations

LtHash provides **at least 200 bits of security** and is designed to be secure in the random oracle model:

1. **Collision Resistance**: Computationally infeasible to find two distinct sets with the same hash
2. **Keys**: Always use cryptographically secure random keys (16-64 bytes)
3. **Constant-time**: All comparison operations use constant-time algorithms
4. **Key clearing**: Keys are securely zeroed when `clear_key()` is called or when dropped
5. **Padding validation**: Padding bits are validated and cleared automatically
6. **Lattice-based Security**: Built on well-studied lattice cryptography foundations

## Implementation References

This Rust implementation is fully compatible with Facebook's C++ reference implementation:

- **Facebook Folly Library**: [`folly/crypto/LtHash.h`](https://github.com/facebook/folly/tree/main/folly/crypto) and [`folly/experimental/crypto/`](https://github.com/facebook/folly/tree/main/folly/experimental/crypto)
- **Blake2xb Implementation**: Compatible with [`folly/crypto/Blake2xb.h`](https://github.com/facebook/folly/tree/main/folly/crypto)

### Cross-Compatibility

This Rust implementation produces identical output to the C++ reference implementation:

- All Blake2xb test vectors match exactly
- All LtHash operations produce identical checksums
- Homomorphic properties are preserved
- Binary layout is compatible

Run `cargo run --bin test_cross_compat` to verify compatibility.

## Performance

The implementation includes optimized arithmetic for different element sizes:

- **16-bit elements**: Uses split-lane SIMD-style arithmetic
- **20-bit elements**: Handles padding bits correctly  
- **32-bit elements**: Optimized for 32-bit operations

## License

Licensed under the Apache License, Version 2.0. See the parent directory for the full license text.
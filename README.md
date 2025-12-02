# LtHash-rs

A Rust implementation of Facebook's LtHash (Lattice-based Homomorphic Hash) with Blake2xb, compatible with the [Folly C++ implementation](https://github.com/facebook/folly/tree/main/folly/crypto).

> **Warning**: This was vibe-coded by Claude. It passes tests and matches the C++ implementation byte-for-byte, but use at your own risk.

## Features

- **Homomorphic hashing**: `H(A ∪ B) = H(A) + H(B)` — add/remove elements without rehashing
- **Three variants**: LtHash16 (2KB), LtHash20 (2.6KB), LtHash32 (4KB) checksums
- **CLI tool** with Unix piping support
- **C++ compatible**: Identical output to Facebook Folly

## Installation

Requires libsodium:

```bash
# macOS
brew install libsodium

# Ubuntu/Debian
sudo apt-get install libsodium-dev
```

## CLI Usage

```bash
# Build the CLI
cargo build --release

# Hash a file (outputs URL-safe base64)
lthash myfile.txt

# Hash stdin
cat myfile.txt | lthash -

# Add files to a hash (piping)
lthash file1.txt | lthash add - file2.txt | lthash add - file3.txt

# Subtract a file's contribution
lthash sub "$HASH" removed_file.txt

# Verify homomorphic property: hash(a) + hash(b) - hash(b) == hash(a)
lthash a.txt | lthash add - b.txt | lthash sub - b.txt
```

## Library Usage

```rust
use lthash::{LtHash16_1024, LtHashError};

fn main() -> Result<(), LtHashError> {
    // Create and populate hash
    let mut hash = LtHash16_1024::new()?;
    hash.add_object(b"document1")?;
    hash.add_object(b"document2")?;
    hash.remove_object(b"document1")?;

    // Combine hashes (homomorphic addition)
    let mut hash1 = LtHash16_1024::new()?;
    hash1.add_object(b"file1")?;

    let mut hash2 = LtHash16_1024::new()?;
    hash2.add_object(b"file2")?;

    // Using operators (panics on key mismatch)
    let combined = hash1.clone() + hash2.clone();

    // Using fallible methods (returns Result)
    hash1.try_add(&hash2)?;

    Ok(())
}
```

### With Authentication Key

```rust
let mut hash = LtHash16_1024::new()?;
hash.set_key(b"my-secret-key-here")?;  // 16-64 bytes
hash.add_object(b"sensitive data")?;
// Key is securely zeroed on drop or clear_key()
```

## API

```rust
// Type aliases
type LtHash16_1024 = LtHash<16, 1024>;  // 2048 bytes
type LtHash20_1008 = LtHash<20, 1008>;  // 2688 bytes
type LtHash32_1024 = LtHash<32, 1024>;  // 4096 bytes

impl LtHash<B, N> {
    fn new() -> Result<Self, LtHashError>;
    fn with_checksum(checksum: &[u8]) -> Result<Self, LtHashError>;

    fn add_object(&mut self, data: &[u8]) -> Result<&mut Self, LtHashError>;
    fn remove_object(&mut self, data: &[u8]) -> Result<&mut Self, LtHashError>;

    fn try_add(&mut self, other: &Self) -> Result<(), LtHashError>;  // Non-panicking
    fn try_sub(&mut self, other: &Self) -> Result<(), LtHashError>;  // Non-panicking

    fn get_checksum(&self) -> &[u8];
    fn checksum_size_bytes() -> usize;

    fn set_key(&mut self, key: &[u8]) -> Result<(), LtHashError>;  // 16-64 bytes
    fn clear_key(&mut self);
}

// Operators: +, -, +=, -= (panic on key mismatch)
```

## Testing

```bash
cargo test
cargo run --bin test_cross_compat  # Verify C++ compatibility
```

## References

- [Facebook Engineering Blog](https://engineering.fb.com/2019/03/01/security/homomorphic-hashing/)
- [IACR ePrint 2019/227](https://eprint.iacr.org/2019/227)
- [Bellare-Micciancio Paper](https://cseweb.ucsd.edu/~mihir/papers/inc1.pdf)

## License

Apache 2.0

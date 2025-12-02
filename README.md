# LtHash-rs

A Rust implementation of Facebook's LtHash (Lattice-based Homomorphic Hash). Uses BLAKE3 by default for high performance, with optional Blake2xb backend for [Folly C++ compatibility](https://github.com/facebook/folly/tree/main/folly/crypto).

## Features

- **Homomorphic hashing**: `H(A ∪ B) = H(A) + H(B)` — add/remove elements without rehashing
- **Three variants**: LtHash16 (2KB), LtHash20 (2.6KB), LtHash32 (4KB) checksums
- **Pure Rust**: No C dependencies by default (BLAKE3 backend)
- **Fast**: BLAKE3 is 6-16x faster than Blake2xb
- **CLI tool** with Unix piping support

## Installation

```bash
cargo add lthash
```

No system dependencies required. Just works.

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

## Folly Compatibility Mode

If you need byte-for-byte compatibility with Facebook's Folly C++ implementation, use the `folly-compat` feature. This switches to Blake2xb (requires libsodium):

```bash
# Install libsodium
brew install libsodium        # macOS
sudo apt install libsodium-dev # Ubuntu/Debian

# Build with Folly compatibility
cargo build --features folly-compat

# Run compatibility tests
cargo test --features folly-compat
cargo run --bin test_cross_compat --features folly-compat
```

Note: The default BLAKE3 backend produces different output than Folly. Use `folly-compat` only if you need to interoperate with existing Folly-based systems.

## Testing

```bash
cargo test                    # Test with BLAKE3 (default)
cargo test --features folly-compat  # Test with Blake2xb
```

## References

- [Facebook Engineering Blog](https://engineering.fb.com/2019/03/01/security/homomorphic-hashing/)
- [IACR ePrint 2019/227](https://eprint.iacr.org/2019/227)
- [Bellare-Micciancio Paper](https://cseweb.ucsd.edu/~mihir/papers/inc1.pdf)

## License

Apache 2.0

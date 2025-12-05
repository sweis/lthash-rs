# LtHash-rs

A Rust implementation of Facebook's LtHash (Lattice-based Homomorphic Hash). Uses BLAKE3 by default for high performance, with optional Blake2xb backend for [Folly C++ compatibility](https://github.com/facebook/folly/tree/main/folly/crypto).

## Warning

This is vibe coded by Claude Code. A human has not really even looked at it. But it passes the tests and generates the same bytes as the Facebook Folly C++ implementation. Don't trust it or use it for anything as is. It was just done for fun.

## Features

- **Homomorphic hashing**: `H(A ∪ B) = H(A) + H(B)` — add/remove elements without rehashing
- **Three variants**: LtHash16 (2KB), LtHash20 (2.6KB), LtHash32 (4KB) checksums
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

# Remove a file's contribution
lthash remove "$HASH" removed_file.txt

# Verify homomorphic property: hash(a) + hash(b) - hash(b) == hash(a)
lthash a.txt | lthash add - b.txt | lthash remove - b.txt
```

### Directory Hashing Example

The `lthash_dir` tool demonstrates LtHash's power for incremental directory hashing:

```bash
# Build the directory hashing tool
cargo build --release --features parallel

# Create a test directory with some files
mkdir -p test_dir
echo "file one" > test_dir/file1.txt
echo "file two" > test_dir/file2.txt

# Get the initial directory hash
HASH1=$(./target/release/lthash_dir test_dir 2>/dev/null)
echo "Initial hash: $HASH1"

# Create a new file
echo "file three" > test_dir/file3.txt

# Option A: Rehash the entire directory (slow for large directories)
HASH2=$(./target/release/lthash_dir test_dir 2>/dev/null)

# Option B: Incrementally update the hash with just the new file (fast!)
HASH2_INCREMENTAL=$(./target/release/lthash add "$HASH1" test_dir/file3.txt)

# Both methods produce identical results
[ "$HASH2" = "$HASH2_INCREMENTAL" ] && echo "Hashes match!"

# Clean up
rm -rf test_dir
```

This is the key benefit of homomorphic hashing: when files are added or removed, you only need to process the changed files rather than re-reading the entire directory.

## Library Usage

```rust
use lthash::{LtHash16_1024, LtHashError};

fn main() -> Result<(), LtHashError> {
    // Homomorphic property: order of operations doesn't matter
    // H({a,b}) = H({b,a}) = H(a) + H(b) = H(b) + H(a)
    let mut hash_ab = LtHash16_1024::new()?;
    hash_ab.add(b"a")?.add(b"b")?;

    let mut hash_ba = LtHash16_1024::new()?;
    hash_ba.add(b"b")?.add(b"a")?;

    assert_eq!(hash_ab, hash_ba);  // Same result regardless of order

    // Combining separate hashes gives the same result
    let mut hash_a = LtHash16_1024::new()?;
    hash_a.add(b"a")?;

    let mut hash_b = LtHash16_1024::new()?;
    hash_b.add(b"b")?;

    let combined = hash_a.clone() + hash_b.clone();
    assert_eq!(combined, hash_ab);  // H(a) + H(b) = H({a,b})

    // Subtraction reverses addition
    let back_to_a = combined - hash_b;
    assert_eq!(back_to_a, hash_a);  // H({a,b}) - H(b) = H(a)

    // Fallible methods for error handling (no panic on key mismatch)
    let mut hash1 = LtHash16_1024::new()?;
    hash1.add(b"data")?;
    hash1.try_add(&hash_a)?;
    hash1.try_sub(&hash_a)?;

    Ok(())
}
```

### With Authentication Key

```rust
let mut hash = LtHash16_1024::new()?;
// Key material is run through BLAKE3 KDF to derive a 32-byte key
hash.set_key(b"any-length-key-material")?;
hash.add(b"sensitive data")?;
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

    // In-memory operations (chainable)
    fn add(&mut self, data: &[u8]) -> Result<&mut Self, LtHashError>;
    fn remove(&mut self, data: &[u8]) -> Result<&mut Self, LtHashError>;

    // Batch operations (map-reduce, parallel when feature enabled)
    fn add_all(&mut self, items: &[&[u8]]) -> Result<&mut Self, LtHashError>;
    fn remove_all(&mut self, items: &[&[u8]]) -> Result<&mut Self, LtHashError>;

    // Streaming operations (for large files)
    fn add_stream<R: Read>(&mut self, reader: R) -> Result<&mut Self, LtHashError>;
    fn remove_stream<R: Read>(&mut self, reader: R) -> Result<&mut Self, LtHashError>;

    // Parallel operations (requires "parallel" feature)
    fn add_parallel(&mut self, items: &[&[u8]]) -> Result<&mut Self, LtHashError>;
    fn add_streams_parallel<R: Read + Send>(&mut self, readers: Vec<R>) -> Result<&mut Self, LtHashError>;

    fn try_add(&mut self, other: &Self) -> Result<(), LtHashError>;  // Non-panicking
    fn try_sub(&mut self, other: &Self) -> Result<(), LtHashError>;  // Non-panicking

    fn get_checksum(&self) -> &[u8];
    fn checksum_size_bytes() -> usize;

    fn set_key(&mut self, key: &[u8]) -> Result<(), LtHashError>;  // Any length, KDF-derived
    fn clear_key(&mut self);
}

// Operators: +, -, +=, -= (panic on key mismatch)
```

## Security

LtHash is designed to be collision resistant in the random oracle model, with security based on the hardness of the [Short Integer Solutions (SIS)](https://en.wikipedia.org/wiki/Short_integer_solution_problem) lattice problem.

| Variant | Checksum Size | Security Level |
|---------|---------------|----------------|
| LtHash16_1024 | 2 KB | **≥200 bits** (recommended) |
| LtHash20_1008 | 2.6 KB | >200 bits |
| LtHash32_1024 | 4 KB | >200 bits |

LtHash16 is the fastest and smallest variant, providing over 200 bits of collision resistance which is sufficient for most use cases. LtHash20 and LtHash32 offer higher security margins at the cost of larger checksums.

See: [Facebook's security analysis (IACR 2019/227)](https://eprint.iacr.org/2019/227)

## Parallel Processing

For hashing multiple files concurrently, enable the `parallel` feature:

```toml
[dependencies]
lthash = { version = "0.1", features = ["parallel"] }
```

```rust
use lthash::LtHash16_1024;
use std::fs::File;

// Hash multiple files in parallel
let files: Vec<File> = vec![
    File::open("file1.bin")?,
    File::open("file2.bin")?,
    File::open("file3.bin")?,
];
let hash = LtHash16_1024::from_streams_parallel(files)?;
```

Since LtHash is homomorphic, the order of operations doesn't matter, making parallel hashing safe. Speedup depends on object size - larger objects (>64KB) benefit most from parallelization.

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

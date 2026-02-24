# LtHash-rs: Lattice-Based Homomorphic Hash in Rust

A Rust implementation of [LtHash](https://engineering.fb.com/2019/03/01/security/homomorphic-hashing/) (Lattice-based Homomorphic Hash). Uses BLAKE3 by default, with optional Blake2xb for [Folly C++ compatibility](https://github.com/facebook/folly/tree/main/folly/crypto). Includes `lthash_dir` tool for homomorphic filesystem digests.

**Status:** Experimental. Not yet reviewed for production use.

## What is LtHash?

LtHash is a **homomorphic hash function**: `H(A ∪ B) = H(A) + H(B)`. This means you can add or remove elements from a hash without re-processing everything.

```
hash({file1, file2, file3}) = hash(file1) + hash(file2) + hash(file3)
```

## Quick Start

```bash
cargo install --path .

# Hash a single file
lthash myfile.txt
# Output: VTvPKXvZuft8iY...  (URL-safe base64, 2732 chars for LtHash16_1024)

# Hash stdin
echo -n "hello" | lthash -

# Hash multiple files (combined homomorphically)
lthash file1.txt file2.txt file3.txt

# Incremental update: add a new file to existing hash
HASH=$(lthash file1.txt)
lthash add "$HASH" new_file.txt

# Remove a file from the hash
lthash remove "$HASH" old_file.txt

# Piping: chain operations
lthash file1.txt | lthash add - file2.txt | lthash add - file3.txt
```

## Library Usage

Add to your `Cargo.toml`:

```toml
[dependencies]
lthash = { path = "." }
```

### Basic Operations

```rust
use lthash::{LtHash16_1024, LtHashError};

fn main() -> Result<(), LtHashError> {
    // Create and add data
    let mut hash = LtHash16_1024::new()?;
    hash.add(b"apple")?.add(b"banana")?;

    // Order doesn't matter (commutative)
    let mut h2 = LtHash16_1024::new()?;
    h2.add(b"banana")?.add(b"apple")?;
    assert_eq!(hash, h2);

    // Remove an element
    hash.remove(b"apple")?;

    // Get the checksum (2048 bytes for LtHash16_1024)
    let checksum = hash.checksum();
    println!("checksum length: {} bytes", checksum.len());
    // Output: checksum length: 2048 bytes

    // Combine separate hashes homomorphically
    let mut h_a = LtHash16_1024::new()?;
    h_a.add(b"x")?;
    let mut h_b = LtHash16_1024::new()?;
    h_b.add(b"y")?;
    let combined = h_a + h_b; // Same as hashing x and y together

    Ok(())
}
```

### Streaming Large Files

```rust
use lthash::LtHash16_1024;
use std::fs::File;

let mut hash = LtHash16_1024::new().unwrap();
let file = File::open("large_file.bin").unwrap();
hash.add_stream(file).unwrap();
```

### Parallel Processing

Requires the `parallel` feature (enabled by default).

```rust
use lthash::LtHash16_1024;
use std::fs::File;

let mut hash = LtHash16_1024::new().unwrap();
let items: Vec<&[u8]> = vec![b"file1", b"file2", b"file3"];
hash.add_parallel(&items).unwrap();

// Or hash multiple file readers in parallel
let files: Vec<File> = vec![
    File::open("a.bin").unwrap(),
    File::open("b.bin").unwrap(),
];
let hash = LtHash16_1024::from_streams_parallel(files).unwrap();
```

## lthash_dir: Fast Directory Hashing

`lthash_dir` computes a single hash for an entire directory tree. Unlike regular hashes, it supports **incremental updates** -- add or remove files without rehashing everything.

```bash
# Hash a directory (non-recursive by default)
lthash_dir /path/to/dir

# Recursive with progress indicator
lthash_dir -r -p /large/directory

# Include hidden files
lthash_dir -r --hidden /path
```

**Progress output example:**
```
Processing: 1000 files, 50 dirs, 5.2 MB @ 3500 MB/s | 75% | ETA: 2s
```

### Why Use lthash_dir?

- **Incremental updates**: When files change, update the hash without re-reading everything
- **Order-independent**: No need to sort file lists for reproducible results
- **Parallel by default**: Uses all CPU cores automatically

## Variants

| Type | Checksum Size | Elements | Security |
|------|---------------|----------|----------|
| `LtHash16_1024` | 2048 bytes | 1024 x 16-bit | >= 200 bits |
| `LtHash20_1008` | 2688 bytes | 1008 x 20-bit | > 200 bits |
| `LtHash32_1024` | 4096 bytes | 1024 x 32-bit | > 200 bits |

`LtHash16_1024` is the recommended default: fastest and most compact.

## Backends

| Backend | Feature Flag | Output Compatible With | Dependencies |
|---------|-------------|----------------------|--------------|
| **BLAKE3** (default) | `blake3-backend` | Solana/Agave | None (pure Rust) |
| Blake2xb | `folly-compat` | Facebook Folly C++ | libsodium |

The two backends produce **different outputs** and are not interchangeable.
Use `folly-compat` only if you need byte-for-byte compatibility with Facebook's C++ implementation.

## Folly Compatibility

For byte-compatible output with Facebook's C++ implementation:

```bash
# Install libsodium
sudo apt install libsodium-dev  # Debian/Ubuntu
brew install libsodium          # macOS

# Build with Folly-compatible backend
cargo build --features folly-compat
cargo test --features folly-compat
```

## Building

```bash
# Default (BLAKE3 + parallel, pure Rust)
cargo build
cargo test

# Without parallel processing
cargo build --no-default-features --features blake3-backend

# Run benchmarks
cargo bench
```

## Security

LtHash provides collision resistance based on the [Short Integer Solutions (SIS)](https://en.wikipedia.org/wiki/Short_integer_solution_problem) lattice problem. Key security measures in this implementation:

- Constant-time comparison to prevent timing attacks
- Secure key clearing using `zeroize` (won't be optimized away)
- Padding bit validation for the 20-bit variant
- Key derivation via BLAKE3 KDF for arbitrary-length key material

See the [security analysis](https://eprint.iacr.org/2019/227) for theoretical background.

## References

- [Facebook Engineering Blog](https://engineering.fb.com/2019/03/01/security/homomorphic-hashing/)
- [IACR ePrint 2019/227](https://eprint.iacr.org/2019/227)
- [Folly LtHash](https://github.com/facebook/folly/tree/main/folly/crypto)
- [Solana/Agave lattice-hash](https://github.com/anza-xyz/agave/blob/master/lattice-hash/src/lt_hash.rs)

## License

Apache 2.0

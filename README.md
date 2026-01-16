# LtHash-rs

A Rust implementation of [LtHash](https://engineering.fb.com/2019/03/01/security/homomorphic-hashing/) (Lattice-based Homomorphic Hash). Uses BLAKE3 by default, with optional Blake2xb for [Folly C++ compatibility](https://github.com/facebook/folly/tree/main/folly/crypto).

## What is LtHash?

LtHash is a **homomorphic hash function**: `H(A ∪ B) = H(A) + H(B)`. This means you can add or remove elements from a hash without re-processing everything.

```
hash({file1, file2, file3}) = hash(file1) + hash(file2) + hash(file3)
```

## Quick Start

```bash
cargo install --path .

# Hash files
lthash file1.txt file2.txt

# Hash a directory (recursively)
lthash_dir -r /path/to/dir

# Incremental update: add a new file to existing hash
lthash add "$OLD_HASH" new_file.txt
```

## lthash_dir: Fast Directory Hashing

`lthash_dir` computes a single hash for an entire directory tree. Unlike regular hashes, it supports **incremental updates** - add or remove files without rehashing everything.

```bash
# Hash a directory
lthash_dir /path/to/dir

# Recursive with progress indicator
lthash_dir -r -p /large/directory

# Include hidden files
lthash_dir -r --hidden /path
```

**Output:**
```
Processing: 1000 files, 50 dirs, 5.2 GB @ 3500 MB/s | 75% | ETA: 2s
```

### Performance Comparison (1 GB dataset)

| Tool | Time | Throughput |
|------|------|------------|
| sha256sum | 1.4 s | 710 MB/s |
| b3sum | 93 ms | 10,700 MB/s |
| **lthash_dir** | **95 ms** | **10,500 MB/s** |

### Why Use lthash_dir?

- **Incremental updates**: When files change, update the hash without re-reading everything
- **Order-independent**: No need to sort file lists for reproducible results
- **Parallel by default**: Uses all CPU cores automatically
- **Comparable to b3sum**: Similar throughput while supporting homomorphic operations

## Library Usage

```rust
use lthash::LtHash16_1024;

// Create and combine hashes
let mut hash = LtHash16_1024::new()?;
hash.add(b"data1")?.add(b"data2")?;

// Homomorphic: order doesn't matter
let mut h1 = LtHash16_1024::new()?;
let mut h2 = LtHash16_1024::new()?;
h1.add(b"a")?.add(b"b")?;
h2.add(b"b")?.add(b"a")?;
assert_eq!(h1, h2);

// Combine separate hashes
let combined = hash_a + hash_b;  // Same as hashing both together

// Remove an element
hash.remove(b"data1")?;
```

### Streaming Large Files

```rust
use std::fs::File;

let mut hash = LtHash16_1024::new()?;
hash.add_stream(File::open("large_file.bin")?)?;
```

### Parallel Processing

```rust
// Hash multiple files in parallel
let files: Vec<File> = paths.iter().map(File::open).collect::<Result<_,_>>()?;
let hash = LtHash16_1024::from_streams_parallel(files)?;
```

## CLI Reference

```bash
# Hash files (outputs URL-safe base64)
lthash file1.txt file2.txt

# Hash stdin
echo "data" | lthash -

# Add to existing hash
lthash add "$HASH" newfile.txt

# Remove from existing hash
lthash remove "$HASH" oldfile.txt

# Piping
lthash file1.txt | lthash add - file2.txt | lthash add - file3.txt
```

## Installation

```bash
# As a library
cargo add lthash

# Build CLI tools
cargo build --release
```

## Variants

| Type | Checksum Size | Security |
|------|---------------|----------|
| `LtHash16_1024` | 2 KB | ≥200 bits (recommended) |
| `LtHash20_1008` | 2.6 KB | >200 bits |
| `LtHash32_1024` | 4 KB | >200 bits |

## Folly Compatibility

For byte-compatible output with Facebook's C++ implementation:

```bash
# Requires libsodium
sudo apt install libsodium-dev  # Debian/Ubuntu
brew install libsodium          # macOS

cargo build --features folly-compat
```

## Security

LtHash provides collision resistance based on the [Short Integer Solutions (SIS)](https://en.wikipedia.org/wiki/Short_integer_solution_problem) lattice problem. See the [security analysis](https://eprint.iacr.org/2019/227).

## References

- [Facebook Engineering Blog](https://engineering.fb.com/2019/03/01/security/homomorphic-hashing/)
- [IACR ePrint 2019/227](https://eprint.iacr.org/2019/227)
- [Folly LtHash](https://github.com/facebook/folly/tree/main/folly/crypto)

## License

Apache 2.0

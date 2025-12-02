# Claude.md - LtHash-rs Analysis Notes

## Project Overview

This is a Rust implementation of Facebook's LtHash (Lattice-based Homomorphic Hash) with Blake2xb. The project aims for binary compatibility with Facebook's Folly C++ implementation.

### Key Components

1. **blake2xb.rs** - Blake2xb XOF (Extendable Output Function) implementation using libsodium
2. **blake3_xof.rs** - BLAKE3 XOF wrapper for pure Rust, high-performance hashing
3. **lthash.rs** - Core LtHash homomorphic hash with const generics for different configurations
4. **error.rs** - Error types using thiserror
5. **lthash_cli.rs** - Unix-friendly command-line tool for hashing and combining checksums

### Supported Configurations
- `LtHash<16, 1024>` - 16-bit elements, 1024 elements (2048 bytes)
- `LtHash<20, 1008>` - 20-bit elements, 1008 elements (2688 bytes)
- `LtHash<32, 1024>` - 32-bit elements, 1024 elements (4096 bytes)

---

## Applied Changes

### Security Fixes

1. **Added `zeroize` crate for secure memory clearing**
   - Key material uses `zeroize()` instead of `fill(0)` - won't be optimized away
   - Intermediate hash `h0` and key blocks are securely zeroed on all exit paths

2. **Fixed unsafe alignment in `as_u64_slice` functions**
   - Changed from direct pointer casts to using `align_to()` with assertions

3. **Added `#[must_use]` attributes** to key methods to prevent ignored errors

### Reliability Fixes

4. **Added `try_add()` and `try_sub()` methods**
   - Non-panicking alternatives to `+` and `-` operators
   - Return `Result<(), LtHashError>` with `KeyMismatch` error

5. **Changed error types from `String` to `&'static str`**
   - Eliminates allocations on error paths
   - `InvalidKeySize`, `NotInitialized`, `AlreadyFinished`, `AlreadyCalled`, `Blake2Error` now use static strings

6. **Documented panic behavior in `Default` impl**
   - Added doc comment explaining when/why it might panic
   - Standard type aliases are guaranteed to succeed

### Performance Improvements

7. **Pre-allocated scratch buffer**
   - Added `scratch: Vec<u8>` field to `LtHash` struct
   - `add_object()` and `remove_object()` now reuse this buffer
   - Eliminates allocation per operation

8. **Benchmark infrastructure**
   - Added `criterion` dev-dependency
   - Benchmarks in `benches/lthash_bench.rs` for Blake2xb, add/sub, combine operations

### CLI Tool

9. **Added Unix-friendly `lthash` binary**
   - `lthash FILE` - hash a file, output URL-safe base64
   - `lthash add HASH FILE` - add file to existing hash
   - `lthash sub HASH FILE` - subtract file from hash
   - Supports `-` for stdin in both file and hash positions
   - Piping: `lthash file1 | lthash add - file2 | lthash add - file3`

---

## Current Security Measures

1. Constant-time comparison in `checksum_equals()` and `PartialEq`
2. Secure key clearing using `zeroize` crate
3. Secure clearing of intermediate hash values (`h0`, `key_block`)
4. Padding bit validation for 20-bit variant
5. Key size validation (16-64 bytes)
6. Safe alignment handling using `align_to()`

---

## Remaining Issues

### MEDIUM PRIORITY

1. **Blake2xb state not cleared on finish**
   - The internal state structure may contain sensitive material after hashing completes
   - Consider implementing `Zeroize` on `Drop` for `Blake2xb`

2. **Checksum Vec<u8> not securely cleared on drop for LtHash**
   - Only the key is cleared, not the checksum
   - Could add `ZeroizeOnDrop` if checksums are considered sensitive

### LOW PRIORITY

3. **Operator overloads still panic**
   - `+=` and `-=` panic on key mismatch (use `try_add`/`try_sub` instead)
   - This is intentional - operators should be fast, Results for safety

---

## Dependencies

- `libsodium-sys` (0.2) - C bindings to libsodium (optional via `sodium` feature)
- `blake3` (1.5) - Pure Rust BLAKE3 implementation (optional via `blake3-backend` feature)
- `thiserror` (1.0) - Error derive macro
- `zeroize` (1.x) - Secure memory zeroing
- `base64` (0.22) - URL-safe base64 encoding for CLI
- `criterion` (0.5) - Benchmarking (dev-dependency)

---

## Hash Backend Selection

The crate supports two XOF backends:

### Blake2xb (default, `sodium` feature)
- **Pros**: Binary-compatible with Facebook's Folly C++ implementation
- **Cons**: Requires libsodium C library, slower performance
- **Use when**: You need interoperability with existing Folly-based systems

### BLAKE3 (`blake3-backend` feature)
- **Pros**: Pure Rust, no C dependencies, 6-16x faster than Blake2xb
- **Cons**: Not compatible with Folly output
- **Use when**: Performance is critical and you don't need Folly compatibility

### Performance Comparison

| Operation | Blake2xb | BLAKE3 | Speedup |
|-----------|----------|--------|---------|
| 64B → 2048B XOF | 6.2 µs | 374 ns | **16x** |
| 1024B → 2048B XOF | 7.5 µs | 1.2 µs | **6x** |
| 4096B → 2048B XOF | 11.3 µs | 1.4 µs | **8x** |
| LtHash add_object (32B) | 6.4 µs | 530 ns | **12x** |

### Usage

```bash
# Build with Blake2xb (default, Folly-compatible)
cargo build

# Build with BLAKE3 (faster, pure Rust)
cargo build --no-default-features --features blake3-backend

# Run benchmarks for each backend
cargo bench                                              # Blake2xb
cargo bench --no-default-features --features blake3-backend  # BLAKE3
```

### Security Equivalence

Both backends provide equivalent security for LtHash:
- **Collision resistance**: Both are cryptographically secure
- **Pseudorandom XOF output**: Both generate high-quality pseudorandom bytes
- **Keyed mode**: Both support authenticated hashing with keys

BLAKE3 keys must be 32 bytes; the wrapper derives a 32-byte key from variable-length inputs.

---

## CLI Usage

```bash
# Hash a file
lthash myfile.txt

# Hash stdin
cat myfile.txt | lthash -

# Add files to a hash (piping)
lthash file1.txt | lthash add - file2.txt | lthash add - file3.txt

# Subtract a file's contribution
lthash sub $COMBINED_HASH removed_file.txt

# Round-trip test (hash(a) + hash(b) - hash(b) == hash(a))
lthash a.txt | lthash add - b.txt | lthash sub - b.txt
```

Output is URL-safe base64 (no padding), safe for command-line arguments.

---

## Summary

The implementation is fully functional with:

- **Security** - Alignment safety, secure memory clearing, `#[must_use]`
- **Reliability** - Non-panicking APIs (`try_add`, `try_sub`), static error strings
- **Performance** - Pre-allocated scratch buffer eliminates per-operation allocations
- **Usability** - Unix-friendly CLI with piping support

All tests pass including cross-compatibility with C++ reference implementation.

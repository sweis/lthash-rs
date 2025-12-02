# Claude.md - LtHash-rs Analysis Notes

## Project Overview

Rust implementation of Facebook's LtHash (Lattice-based Homomorphic Hash). Uses BLAKE3 by default for pure-Rust high performance, with optional Blake2xb backend for binary compatibility with Facebook's Folly C++ implementation.

### Supported Configurations
- `LtHash<16, 1024>` - 16-bit elements, 1024 elements (2048 bytes)
- `LtHash<20, 1008>` - 20-bit elements, 1008 elements (2688 bytes)
- `LtHash<32, 1024>` - 32-bit elements, 1024 elements (4096 bytes)

---

## File Structure

| File | Lines | Purpose |
|------|-------|---------|
| `src/lib.rs` | 85 | Module exports with feature-gated backends |
| `src/error.rs` | 41 | Error types using thiserror |
| `src/blake3_xof.rs` | 257 | BLAKE3 XOF wrapper (default backend) |
| `src/blake2xb.rs` | 447 | Blake2xb XOF using libsodium (Folly-compat) |
| `src/lthash.rs` | 666 | Core LtHash with const generics |
| `src/bin/lthash_cli.rs` | 192 | Unix-friendly CLI tool |

---

## Security Measures (Implemented)

1. **Constant-time comparison** in `checksum_equals()` and `PartialEq`
2. **Secure key clearing** using `zeroize` crate (won't be optimized away)
3. **Secure clearing of intermediate hash** (`h0`, `key_block` in Blake2xb)
4. **Padding bit validation** for 20-bit variant
5. **Key size validation** (16-64 bytes)
6. **Safe alignment handling** using `align_to()` with assertions
7. **`#[must_use]` attributes** on key methods to prevent ignored errors

---

## Remaining Issues

### MEDIUM PRIORITY

1. **Blake2xb/Blake3Xof state not cleared on drop**
   - Internal hasher state may contain sensitive material after use
   - Consider implementing `Drop` with `Zeroize` for these structs

2. **Checksum not securely cleared on drop for LtHash**
   - Only the key is cleared, not the checksum vector
   - Add `ZeroizeOnDrop` if checksums are considered sensitive

### LOW PRIORITY

3. **Operator overloads still panic**
   - `+=` and `-=` panic on key mismatch
   - Use `try_add`/`try_sub` for fallible operations
   - This is intentional: operators are fast, Results are safe

4. **MSRV not specified**
   - Uses `is_multiple_of` (stabilized Rust 1.79, June 2024)
   - Consider adding `rust-version = "1.79"` to Cargo.toml

---

## Performance

### Backend Comparison

| Operation | Blake2xb | BLAKE3 | Speedup |
|-----------|----------|--------|---------|
| 64B → 2048B XOF | 6.2 µs | 374 ns | **16x** |
| 1024B → 2048B XOF | 7.5 µs | 1.2 µs | **6x** |
| 4096B → 2048B XOF | 11.3 µs | 1.4 µs | **8x** |
| LtHash add_object (32B) | 6.4 µs | 530 ns | **12x** |

### Optimizations

- Pre-allocated scratch buffer eliminates per-operation allocations
- Split-lane arithmetic for 16-bit and 32-bit element packing
- Manual Clone impl avoids unnecessary scratch buffer cloning

---

## Feature Flags

```toml
[features]
default = ["blake3-backend"]
blake3-backend = ["blake3"]      # Pure Rust, fast, no deps
folly-compat = ["libsodium-sys"] # For Facebook Folly C++ compatibility
```

### Build Commands

```bash
cargo build                      # BLAKE3 (default)
cargo build --features folly-compat  # Blake2xb (Folly-compatible)
cargo test                       # Test with BLAKE3
cargo test --features folly-compat   # Test with Blake2xb
cargo bench                      # Benchmark BLAKE3
cargo bench --features folly-compat  # Benchmark Blake2xb
```

---

## Code Style Review (2025-12-02)

### Findings

- **Formatting**: Consistent, follows Rust conventions
- **Comments**: Appropriate level, explains complex bit manipulation
- **Error handling**: Uses thiserror with static strings (no allocations)
- **Dead code**: Test vectors have `#[allow(dead_code)]` for unused variants
- **Unsafe code**: Minimal, well-documented (`align_to` with assertions)

### No Changes Needed

The codebase is clean and well-organized. No extraneous comments found.
All doc comments are appropriate for public API documentation.

---

## Dependencies

| Crate | Version | Feature | Purpose |
|-------|---------|---------|---------|
| `blake3` | 1.5 | blake3-backend | Pure Rust XOF (default) |
| `libsodium-sys` | 0.2 | folly-compat | C bindings for Blake2xb |
| `thiserror` | 1.0 | always | Error derive macro |
| `zeroize` | 1.x | always | Secure memory zeroing |
| `base64` | 0.22 | always | URL-safe encoding for CLI |
| `criterion` | 0.5 | dev | Benchmarking |

---

## Summary

The implementation is production-ready with:

- **Security**: Constant-time ops, secure key clearing, alignment safety
- **Performance**: BLAKE3 default (6-16x faster), pre-allocated buffers
- **Reliability**: `try_add`/`try_sub` for non-panicking ops, static error strings
- **Compatibility**: `folly-compat` feature for Facebook Folly interop
- **Usability**: Unix-friendly CLI with piping support

All tests pass with both backends.

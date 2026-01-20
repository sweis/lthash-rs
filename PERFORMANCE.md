# Performance Tracking

This document tracks performance benchmarks for lthash-rs across different platforms and configurations.

## System Information

### macOS (Development Machine)
- **Date**: 2026-01-20
- **Platform**: macOS 15.7.3 (Darwin 24.6.0)
- **CPU**: Apple M4 Pro
- **RAM**: 48 GB
- **Disk**: Internal SSD (APFS)

---

## Criterion Micro-Benchmarks

| Date | Platform | Commit | Benchmark | Value | Unit | Notes |
|------|----------|--------|-----------|-------|------|-------|
| 2026-01-20 | macOS M4 Pro | 8c666ca | blake3/hash_64B_to_2048B | 1.35 | µs | XOF expansion baseline |
| 2026-01-20 | macOS M4 Pro | 8c666ca | blake3/hash_1024B_to_2048B | 2.04 | µs | XOF expansion baseline |
| 2026-01-20 | macOS M4 Pro | 8c666ca | blake3/hash_4096B_to_2048B | 2.90 | µs | 1.3 GiB/s throughput |
| 2026-01-20 | macOS M4 Pro | 8c666ca | lthash_add/16_1024_add_32B | 1.44 | µs | Small object add |
| 2026-01-20 | macOS M4 Pro | 8c666ca | lthash_add/16_1024_add_1024B | 2.15 | µs | 454 MiB/s throughput |
| 2026-01-20 | macOS M4 Pro | 8c666ca | parallel/100x1024B_parallel | 78.5 | µs | 1.21 GiB/s parallel |
| 2026-01-20 | macOS M4 Pro | 8c666ca | parallel_streaming/16x65536B_parallel | 127.6 | µs | 7.65 GiB/s parallel |

---

## Real-World lthash_dir Throughput

| Date | Platform | Commit | Test Directory | Files | Size (MB) | Time | Throughput (MB/s) | Notes |
|------|----------|--------|----------------|-------|-----------|------|-------------------|-------|
| 2026-01-20 | macOS M4 Pro | WIP | /Library/Developer/CommandLineTools | 132,618 | 6,056 | 8.38s | 722 | Many small files, warm cache |
| 2026-01-20 | macOS M4 Pro | WIP | /Users/saw/Downloads | 1,477 | 11,759 | 5.93s | 1,982 | Larger files, warm cache |
| 2026-01-20 | macOS M4 Pro | WIP | /Users/saw/repos/lthash-rs | 6,329 | 650 | 0.27s | 2,386 | Git repo, warm cache |

---

## Optimization History

### 2026-01-20: macOS Build Fix
- **Commit**: 8c666ca
- **Change**: Restricted `posix_fadvise` calls to Linux only
- **Impact**: Enabled macOS compilation (no performance change on macOS)

### 2026-01-20: macOS I/O Optimizations (WIP)
- **Change**: Added macOS-specific `fcntl` hints and larger read buffer
  - `F_RDAHEAD`: Enable aggressive read-ahead prefetching for sequential access
  - `F_NOCACHE`: Bypass page cache to prevent cache pollution
  - 128KB read buffer (up from 64KB, Apple-recommended for sequential I/O)
- **Impact**: Enables kernel-level I/O optimizations on macOS
- **Files Modified**: `src/bin/lthash_dir.rs`

---

## Notes

- Throughput measurements should be taken with cold cache (`sudo purge` on macOS)
- Multiple runs should be averaged for more reliable results
- Criterion benchmarks provide micro-level performance data
- lthash_dir throughput shows real-world I/O-bound performance

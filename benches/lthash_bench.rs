//! Benchmarks for LtHash operations
//!
//! Run with:
//!   cargo bench                                    # BLAKE3 (default)
//!   cargo bench --features folly-compat            # Blake2xb (Folly-compatible)

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use lthash::{LtHash16_1024, LtHash20_1008, LtHash32_1024};

#[cfg(feature = "folly-compat")]
use lthash::Blake2xb;
#[cfg(feature = "blake3-backend")]
use lthash::Blake3Xof;

/// Benchmark BLAKE3 XOF at various output sizes (default)
#[cfg(feature = "blake3-backend")]
fn bench_blake3(c: &mut Criterion) {
    let mut group = c.benchmark_group("blake3");

    let input_sizes = [64, 256, 1024, 4096];

    for input_size in input_sizes {
        let input = vec![0xABu8; input_size];

        group.throughput(Throughput::Bytes(input_size as u64));
        group.bench_function(format!("hash_{input_size}B_to_64B"), |b| {
            let mut output = vec![0u8; 64];
            b.iter(|| {
                Blake3Xof::hash(black_box(&mut output), black_box(&input), &[], &[], &[]).unwrap();
            });
        });

        group.bench_function(format!("hash_{input_size}B_to_2048B"), |b| {
            let mut output = vec![0u8; 2048];
            b.iter(|| {
                Blake3Xof::hash(black_box(&mut output), black_box(&input), &[], &[], &[]).unwrap();
            });
        });
    }

    group.finish();
}

/// Benchmark Blake2xb XOF at various output sizes (Folly-compatible)
#[cfg(feature = "folly-compat")]
fn bench_blake2xb(c: &mut Criterion) {
    let mut group = c.benchmark_group("blake2xb");

    let input_sizes = [64, 256, 1024, 4096];

    for input_size in input_sizes {
        let input = vec![0xABu8; input_size];

        group.throughput(Throughput::Bytes(input_size as u64));
        group.bench_function(format!("hash_{input_size}B_to_64B"), |b| {
            let mut output = vec![0u8; 64];
            b.iter(|| {
                Blake2xb::hash(black_box(&mut output), black_box(&input), &[], &[], &[]).unwrap();
            });
        });

        group.bench_function(format!("hash_{input_size}B_to_2048B"), |b| {
            let mut output = vec![0u8; 2048];
            b.iter(|| {
                Blake2xb::hash(black_box(&mut output), black_box(&input), &[], &[], &[]).unwrap();
            });
        });
    }

    group.finish();
}

/// Benchmark LtHash add operations
fn bench_lthash_add(c: &mut Criterion) {
    let mut group = c.benchmark_group("lthash_add");

    let object_sizes = [32, 128, 512, 1024];

    for size in object_sizes {
        let object = vec![0xCDu8; size];

        // LtHash16_1024
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_function(format!("16_1024_add_{size}B"), |b| {
            let mut hash = LtHash16_1024::new().unwrap();
            b.iter(|| {
                hash.add(black_box(&object)).unwrap();
            });
        });

        // LtHash20_1008
        group.bench_function(format!("20_1008_add_{size}B"), |b| {
            let mut hash = LtHash20_1008::new().unwrap();
            b.iter(|| {
                hash.add(black_box(&object)).unwrap();
            });
        });

        // LtHash32_1024
        group.bench_function(format!("32_1024_add_{size}B"), |b| {
            let mut hash = LtHash32_1024::new().unwrap();
            b.iter(|| {
                hash.add(black_box(&object)).unwrap();
            });
        });
    }

    group.finish();
}

/// Benchmark LtHash homomorphic operations (combining hashes)
fn bench_lthash_combine(c: &mut Criterion) {
    let mut group = c.benchmark_group("lthash_combine");

    let mut hash1 = LtHash16_1024::new().unwrap();
    let mut hash2 = LtHash16_1024::new().unwrap();
    hash1.add(b"test data 1").unwrap();
    hash2.add(b"test data 2").unwrap();

    group.bench_function("16_1024_try_add", |b| {
        let mut hash_a = hash1.clone();
        b.iter(|| {
            hash_a.try_add(black_box(&hash2)).unwrap();
        });
    });

    group.bench_function("16_1024_try_sub", |b| {
        let mut hash_a = hash1.clone();
        b.iter(|| {
            hash_a.try_sub(black_box(&hash2)).unwrap();
        });
    });

    let mut hash1_32 = LtHash32_1024::new().unwrap();
    let mut hash2_32 = LtHash32_1024::new().unwrap();
    hash1_32.add(b"test data 1").unwrap();
    hash2_32.add(b"test data 2").unwrap();

    group.bench_function("32_1024_try_add", |b| {
        let mut hash_a = hash1_32.clone();
        b.iter(|| {
            hash_a.try_add(black_box(&hash2_32)).unwrap();
        });
    });

    group.finish();
}

/// Benchmark checksum comparison (constant-time)
fn bench_checksum_compare(c: &mut Criterion) {
    let mut group = c.benchmark_group("checksum_compare");

    let mut hash1 = LtHash16_1024::new().unwrap();
    let mut hash2 = LtHash16_1024::new().unwrap();
    hash1.add(b"same data").unwrap();
    hash2.add(b"same data").unwrap();

    let checksum = hash1.checksum().to_vec();

    group.bench_function("16_1024_checksum_eq", |b| {
        b.iter(|| hash1.checksum_eq(black_box(&checksum)).unwrap());
    });

    group.bench_function("16_1024_eq", |b| {
        b.iter(|| black_box(&hash1) == black_box(&hash2));
    });

    group.finish();
}

/// Benchmark hash creation
fn bench_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("creation");

    group.bench_function("16_1024_new", |b| {
        b.iter(|| LtHash16_1024::new().unwrap());
    });

    group.bench_function("20_1008_new", |b| {
        b.iter(|| LtHash20_1008::new().unwrap());
    });

    group.bench_function("32_1024_new", |b| {
        b.iter(|| LtHash32_1024::new().unwrap());
    });

    let checksum = vec![0u8; LtHash16_1024::checksum_size_bytes()];
    group.bench_function("16_1024_with_checksum", |b| {
        b.iter(|| LtHash16_1024::with_checksum(black_box(&checksum)).unwrap());
    });

    group.finish();
}

/// Benchmark sequential vs parallel hashing of multiple objects
fn bench_parallel(c: &mut Criterion) {
    use rayon::prelude::*;
    use std::io::Cursor;

    let mut group = c.benchmark_group("parallel");

    // Create test data: multiple 1KB objects
    let object_count = 100;
    let object_size = 1024;
    let objects: Vec<Vec<u8>> = (0..object_count)
        .map(|i| vec![(i % 256) as u8; object_size])
        .collect();
    let object_refs: Vec<&[u8]> = objects.iter().map(|o| o.as_slice()).collect();

    let total_bytes = (object_count * object_size) as u64;
    group.throughput(Throughput::Bytes(total_bytes));

    // Sequential: hash objects one at a time
    group.bench_function(format!("{object_count}x{object_size}B_sequential"), |b| {
        b.iter(|| {
            let mut hash = LtHash16_1024::new().unwrap();
            for obj in &object_refs {
                hash.add(black_box(obj)).unwrap();
            }
            hash
        });
    });

    // Parallel: use library's optimized add_parallel method
    group.bench_function(format!("{object_count}x{object_size}B_parallel"), |b| {
        b.iter(|| {
            let mut hash = LtHash16_1024::new().unwrap();
            hash.add_parallel(black_box(&object_refs)).unwrap();
            hash
        });
    });

    group.finish();

    // Benchmark with larger objects to test streaming
    let mut group2 = c.benchmark_group("parallel_streaming");

    let large_object_count = 16;
    let large_object_size = 64 * 1024; // 64KB each
    let large_objects: Vec<Vec<u8>> = (0..large_object_count)
        .map(|i| vec![(i % 256) as u8; large_object_size])
        .collect();

    let total_large_bytes = (large_object_count * large_object_size) as u64;
    group2.throughput(Throughput::Bytes(total_large_bytes));

    // Sequential streaming
    group2.bench_function(
        format!("{large_object_count}x{large_object_size}B_sequential_stream"),
        |b| {
            b.iter(|| {
                let mut hash = LtHash16_1024::new().unwrap();
                for obj in &large_objects {
                    hash.add_stream(Cursor::new(black_box(obj))).unwrap();
                }
                hash
            });
        },
    );

    // Parallel streaming: use library's optimized add_streams_parallel method
    // Note: We clone data outside the timing loop to avoid measuring clone overhead
    group2.bench_function(
        format!("{large_object_count}x{large_object_size}B_parallel_stream"),
        |b| {
            b.iter_batched(
                || {
                    large_objects
                        .iter()
                        .map(|obj| Cursor::new(obj.clone()))
                        .collect::<Vec<_>>()
                },
                |readers| {
                    let mut hash = LtHash16_1024::new().unwrap();
                    hash.add_streams_parallel(black_box(readers)).unwrap();
                    hash
                },
                criterion::BatchSize::SmallInput,
            );
        },
    );

    group2.finish();
}

// Default: BLAKE3 backend
#[cfg(all(feature = "blake3-backend", not(feature = "folly-compat")))]
criterion_group!(
    benches,
    bench_blake3,
    bench_lthash_add,
    bench_lthash_combine,
    bench_checksum_compare,
    bench_creation,
    bench_parallel,
);

// Folly-compatible: Blake2xb backend
#[cfg(feature = "folly-compat")]
criterion_group!(
    benches,
    bench_blake2xb,
    bench_lthash_add,
    bench_lthash_combine,
    bench_checksum_compare,
    bench_creation,
    bench_parallel,
);

criterion_main!(benches);

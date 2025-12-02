//! Benchmarks for LtHash operations
//!
//! Run with: cargo bench

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use lthash::{Blake2xb, LtHash16_1024, LtHash20_1008, LtHash32_1024};

/// Benchmark Blake2xb hash at various output sizes
fn bench_blake2xb(c: &mut Criterion) {
    let mut group = c.benchmark_group("blake2xb");

    // Test data sizes
    let input_sizes = [64, 256, 1024, 4096];

    for input_size in input_sizes {
        let input = vec![0xABu8; input_size];

        // Benchmark 64-byte output (single block)
        group.throughput(Throughput::Bytes(input_size as u64));
        group.bench_function(format!("hash_{input_size}B_to_64B"), |b| {
            let mut output = vec![0u8; 64];
            b.iter(|| {
                Blake2xb::hash(black_box(&mut output), black_box(&input), &[], &[], &[]).unwrap();
            });
        });

        // Benchmark 2048-byte output (LtHash16_1024 size)
        group.bench_function(format!("hash_{input_size}B_to_2048B"), |b| {
            let mut output = vec![0u8; 2048];
            b.iter(|| {
                Blake2xb::hash(black_box(&mut output), black_box(&input), &[], &[], &[]).unwrap();
            });
        });
    }

    group.finish();
}

/// Benchmark LtHash add_object operations
fn bench_lthash_add(c: &mut Criterion) {
    let mut group = c.benchmark_group("lthash_add");

    // Test various object sizes
    let object_sizes = [32, 128, 512, 1024];

    for size in object_sizes {
        let object = vec![0xCDu8; size];

        // LtHash16_1024
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_function(format!("16_1024_add_{size}B"), |b| {
            let mut hash = LtHash16_1024::new().unwrap();
            b.iter(|| {
                hash.add_object(black_box(&object)).unwrap();
            });
        });

        // LtHash20_1008
        group.bench_function(format!("20_1008_add_{size}B"), |b| {
            let mut hash = LtHash20_1008::new().unwrap();
            b.iter(|| {
                hash.add_object(black_box(&object)).unwrap();
            });
        });

        // LtHash32_1024
        group.bench_function(format!("32_1024_add_{size}B"), |b| {
            let mut hash = LtHash32_1024::new().unwrap();
            b.iter(|| {
                hash.add_object(black_box(&object)).unwrap();
            });
        });
    }

    group.finish();
}

/// Benchmark LtHash homomorphic operations (combining hashes)
fn bench_lthash_combine(c: &mut Criterion) {
    let mut group = c.benchmark_group("lthash_combine");

    // Setup: create two hashes with some data
    let mut hash1 = LtHash16_1024::new().unwrap();
    let mut hash2 = LtHash16_1024::new().unwrap();
    hash1.add_object(b"test data 1").unwrap();
    hash2.add_object(b"test data 2").unwrap();

    // Benchmark try_add (non-panicking)
    group.bench_function("16_1024_try_add", |b| {
        let mut hash_a = hash1.clone();
        b.iter(|| {
            hash_a.try_add(black_box(&hash2)).unwrap();
        });
    });

    // Benchmark try_sub (non-panicking)
    group.bench_function("16_1024_try_sub", |b| {
        let mut hash_a = hash1.clone();
        b.iter(|| {
            hash_a.try_sub(black_box(&hash2)).unwrap();
        });
    });

    // Setup for LtHash32_1024
    let mut hash1_32 = LtHash32_1024::new().unwrap();
    let mut hash2_32 = LtHash32_1024::new().unwrap();
    hash1_32.add_object(b"test data 1").unwrap();
    hash2_32.add_object(b"test data 2").unwrap();

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
    hash1.add_object(b"same data").unwrap();
    hash2.add_object(b"same data").unwrap();

    let checksum = hash1.get_checksum().to_vec();

    group.bench_function("16_1024_checksum_equals", |b| {
        b.iter(|| {
            hash1.checksum_equals(black_box(&checksum)).unwrap()
        });
    });

    group.bench_function("16_1024_eq", |b| {
        b.iter(|| {
            black_box(&hash1) == black_box(&hash2)
        });
    });

    group.finish();
}

/// Benchmark hash creation
fn bench_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("creation");

    group.bench_function("16_1024_new", |b| {
        b.iter(|| {
            LtHash16_1024::new().unwrap()
        });
    });

    group.bench_function("20_1008_new", |b| {
        b.iter(|| {
            LtHash20_1008::new().unwrap()
        });
    });

    group.bench_function("32_1024_new", |b| {
        b.iter(|| {
            LtHash32_1024::new().unwrap()
        });
    });

    // With initial checksum
    let checksum = vec![0u8; LtHash16_1024::checksum_size_bytes()];
    group.bench_function("16_1024_with_checksum", |b| {
        b.iter(|| {
            LtHash16_1024::with_checksum(black_box(&checksum)).unwrap()
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_blake2xb,
    bench_lthash_add,
    bench_lthash_combine,
    bench_checksum_compare,
    bench_creation,
);

criterion_main!(benches);

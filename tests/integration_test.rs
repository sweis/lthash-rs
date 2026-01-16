use lthash::{LtHash16_1024, LtHashError};

#[cfg(feature = "folly-compat")]
use lthash::Blake2xb;
#[cfg(feature = "blake3-backend")]
use lthash::Blake3Xof;

mod test_vectors;

#[cfg(feature = "blake3-backend")]
#[test]
fn test_blake3_basic() -> Result<(), LtHashError> {
    // Test basic Blake3Xof functionality
    let mut output = vec![0u8; 32];
    Blake3Xof::hash(&mut output, b"hello world", &[], &[], &[])?;

    // Should produce consistent output
    assert_eq!(output.len(), 32);
    assert_ne!(output, vec![0u8; 32]); // Should not be all zeros
    Ok(())
}

#[cfg(feature = "folly-compat")]
#[test]
fn test_blake2xb_basic() -> Result<(), LtHashError> {
    // Test basic Blake2xb functionality
    let mut output = vec![0u8; 32];
    Blake2xb::hash(&mut output, b"hello world", &[], &[], &[])?;

    // Should produce consistent output
    assert_eq!(output.len(), 32);
    assert_ne!(output, vec![0u8; 32]); // Should not be all zeros
    Ok(())
}

#[test]
fn test_lthash_basic() -> Result<(), LtHashError> {
    // Test basic LtHash functionality
    let mut hash = LtHash16_1024::new()?;
    hash.add(b"test")?;

    let checksum = hash.checksum();
    assert_eq!(checksum.len(), LtHash16_1024::checksum_size_bytes());
    assert_ne!(checksum, vec![0u8; checksum.len()]); // Should not be all zeros
    Ok(())
}

#[test]
fn test_is_zero() -> Result<(), LtHashError> {
    let mut hash = LtHash16_1024::new()?;
    assert!(hash.is_zero(), "New hash should be zero");

    hash.add(b"test")?;
    assert!(!hash.is_zero(), "Hash with data should not be zero");

    hash.remove(b"test")?;
    assert!(
        hash.is_zero(),
        "Hash after removing all data should be zero"
    );

    hash.reset();
    assert!(hash.is_zero(), "Hash after reset should be zero");
    Ok(())
}

#[cfg(all(feature = "blake3-backend", not(feature = "folly-compat")))]
#[test]
fn test_digest() -> Result<(), LtHashError> {
    let mut hash1 = LtHash16_1024::new()?;
    hash1.add(b"test")?;

    let mut hash2 = LtHash16_1024::new()?;
    hash2.add(b"test")?;

    // Same content should produce same digest
    assert_eq!(hash1.digest(), hash2.digest());

    // Different content should produce different digest
    hash2.add(b"more")?;
    assert_ne!(hash1.digest(), hash2.digest());

    // Digest should be 32 bytes
    assert_eq!(hash1.digest().len(), 32);
    Ok(())
}

#[cfg(feature = "folly-compat")]
#[test]
fn test_blake2xb_vectors() -> Result<(), LtHashError> {
    // Test against static vectors (only for Blake2xb/Folly compatibility)
    for vector in test_vectors::blake2xb::NON_KEYED_VECTORS.iter().take(3) {
        let mut output = vec![0u8; vector.output_length];
        Blake2xb::hash(
            &mut output,
            vector.input,
            vector.key,
            vector.salt,
            vector.personalization,
        )?;

        let result_hex: String = output.iter().map(|b| format!("{:02x}", b)).collect();
        assert_eq!(
            result_hex, vector.expected,
            "Failed for output length {}",
            vector.output_length
        );
    }
    Ok(())
}

#[cfg(feature = "folly-compat")]
#[test]
fn test_lthash_vectors() -> Result<(), LtHashError> {
    // Test LtHash against static vectors (only valid for Blake2xb backend)
    for vector in test_vectors::lthash::LTHASH_16_1024_VECTORS.iter().take(3) {
        let mut hash = LtHash16_1024::new()?;

        if !vector.input.is_empty() {
            hash.add(vector.input)?;
        }

        let result: String = hash.checksum()[..16]
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();
        assert_eq!(
            result, vector.expected_first_16_bytes,
            "Failed for input {:?}",
            vector.name
        );
    }
    Ok(())
}

/// Test BLAKE3-based LtHash against fixed test vectors to detect regressions
#[cfg(all(feature = "blake3-backend", not(feature = "folly-compat")))]
#[test]
fn test_blake3_lthash_vectors() -> Result<(), LtHashError> {
    use lthash::{LtHash20_1008, LtHash32_1024};

    // Test LtHash16_1024
    for vector in test_vectors::blake3_lthash::LTHASH_16_1024_VECTORS.iter() {
        let mut hash = LtHash16_1024::new()?;
        if !vector.input.is_empty() {
            hash.add(vector.input)?;
        }
        let result: String = hash.checksum()[..16]
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();
        assert_eq!(
            result, vector.expected_first_16_bytes,
            "LtHash16_1024 failed for input {:?}",
            vector.name
        );
    }

    // Test LtHash20_1008
    for vector in test_vectors::blake3_lthash::LTHASH_20_1008_VECTORS.iter() {
        let mut hash = LtHash20_1008::new()?;
        if !vector.input.is_empty() {
            hash.add(vector.input)?;
        }
        let result: String = hash.checksum()[..16]
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();
        assert_eq!(
            result, vector.expected_first_16_bytes,
            "LtHash20_1008 failed for input {:?}",
            vector.name
        );
    }

    // Test LtHash32_1024
    for vector in test_vectors::blake3_lthash::LTHASH_32_1024_VECTORS.iter() {
        let mut hash = LtHash32_1024::new()?;
        if !vector.input.is_empty() {
            hash.add(vector.input)?;
        }
        let result: String = hash.checksum()[..16]
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();
        assert_eq!(
            result, vector.expected_first_16_bytes,
            "LtHash32_1024 failed for input {:?}",
            vector.name
        );
    }

    Ok(())
}

#[test]
fn test_homomorphic_properties() -> Result<(), LtHashError> {
    // Test commutativity: a+b == b+a
    let mut hash1 = LtHash16_1024::new()?;
    let mut hash2 = LtHash16_1024::new()?;

    hash1.add(b"a")?.add(b"b")?;
    hash2.add(b"b")?.add(b"a")?;

    assert_eq!(hash1.checksum(), hash2.checksum(), "Commutativity failed");

    // Test additive inverse: a+b-a == b
    hash1.remove(b"a")?;
    let mut hash_just_b = LtHash16_1024::new()?;
    hash_just_b.add(b"b")?;

    assert_eq!(
        hash1.checksum(),
        hash_just_b.checksum(),
        "Additive inverse failed"
    );

    // Test homomorphic addition: H(a) + H(b) == H(a+b)
    let mut h_a = LtHash16_1024::new()?;
    let mut h_b = LtHash16_1024::new()?;
    let mut h_ab = LtHash16_1024::new()?;

    h_a.add(b"a")?;
    h_b.add(b"b")?;
    h_ab.add(b"a")?.add(b"b")?;

    let h_sum = h_a + h_b;
    assert_eq!(
        h_sum.checksum(),
        h_ab.checksum(),
        "Homomorphic addition failed"
    );

    Ok(())
}

#[test]
fn test_streaming_equals_inmemory() -> Result<(), LtHashError> {
    // Test that streaming produces identical results to in-memory hashing
    let data = b"The quick brown fox jumps over the lazy dog. ".repeat(1000);

    // Hash using in-memory method
    let mut hash_mem = LtHash16_1024::new()?;
    hash_mem.add(&data)?;

    // Hash using streaming method
    let mut hash_stream = LtHash16_1024::new()?;
    hash_stream.add_stream(std::io::Cursor::new(&data))?;

    assert_eq!(
        hash_mem.checksum(),
        hash_stream.checksum(),
        "Streaming and in-memory hashing produced different results"
    );

    // Also test remove_stream with chaining
    let mut hash_mem2 = LtHash16_1024::new()?;
    hash_mem2.add(&data)?.remove(&data)?;

    let mut hash_stream2 = LtHash16_1024::new()?;
    hash_stream2
        .add_stream(std::io::Cursor::new(&data))?
        .remove_stream(std::io::Cursor::new(&data))?;

    assert_eq!(
        hash_mem2.checksum(),
        hash_stream2.checksum(),
        "Streaming remove produced different results"
    );

    // Both should be back to zero (empty set)
    let empty_hash = LtHash16_1024::new()?;
    assert_eq!(
        hash_stream2.checksum(),
        empty_hash.checksum(),
        "add then remove should equal empty hash"
    );

    Ok(())
}

/// Test interoperability with Solana's BLAKE3-based LtHash implementation.
///
/// This verifies that our implementation produces identical internal state to Solana's
/// lattice-hash crate, enabling cross-platform verification. The test compares the first
/// 16 u16 values (32 bytes) of the internal checksum state against Solana's test vectors.
#[cfg(all(feature = "blake3-backend", not(feature = "folly-compat")))]
#[test]
fn test_solana_interoperability() -> Result<(), LtHashError> {
    for vector in test_vectors::solana_interop::VECTORS.iter() {
        let mut hash = LtHash16_1024::new()?;
        hash.add(vector.input)?;

        // Verify internal state matches (first 32 bytes = first 16 u16 values)
        let checksum = hash.checksum();

        // Convert first 32 bytes to u16 array (little-endian)
        let mut actual_u16s = [0u16; 16];
        for i in 0..16 {
            actual_u16s[i] = u16::from_le_bytes([checksum[i * 2], checksum[i * 2 + 1]]);
        }

        assert_eq!(
            actual_u16s, vector.expected_first_u16s,
            "Internal state mismatch for input {:?}. Our implementation produces \
            different checksum state than Solana's lattice-hash.",
            vector.name
        );
    }

    Ok(())
}

#[test]
fn test_add_all_remove_all() -> Result<(), LtHashError> {
    let items: Vec<&[u8]> = vec![b"alpha", b"beta", b"gamma"];

    // add_all should equal sequential adds
    let mut hash1 = LtHash16_1024::new()?;
    hash1.add_all(&items)?;

    let mut hash2 = LtHash16_1024::new()?;
    for item in &items {
        hash2.add(item)?;
    }

    assert_eq!(
        hash1.checksum(),
        hash2.checksum(),
        "add_all should equal sequential adds"
    );

    // remove_all should work correctly
    let mut hash3 = LtHash16_1024::new()?;
    hash3.add_all(&items)?;
    let to_remove: Vec<&[u8]> = vec![b"alpha", b"beta"];
    hash3.remove_all(&to_remove)?;

    let mut hash4 = LtHash16_1024::new()?;
    hash4.add(b"gamma")?;

    assert_eq!(
        hash3.checksum(),
        hash4.checksum(),
        "remove_all should leave only remaining items"
    );

    // Chaining should work
    let mut hash5 = LtHash16_1024::new()?;
    hash5.add_all(&[b"a", b"b", b"c"])?.remove_all(&[b"a"])?;

    let mut hash6 = LtHash16_1024::new()?;
    hash6.add(b"b")?.add(b"c")?;

    assert_eq!(
        hash5.checksum(),
        hash6.checksum(),
        "chained add_all/remove_all should work"
    );

    Ok(())
}

#[cfg(feature = "parallel")]
#[test]
fn test_parallel_equals_sequential() -> Result<(), LtHashError> {
    // Test that parallel hashing produces identical results to sequential

    let objects: Vec<&[u8]> = vec![
        b"first object",
        b"second object",
        b"third object",
        b"fourth object",
        b"fifth object",
    ];

    // Hash sequentially
    let mut hash_seq = LtHash16_1024::new()?;
    for obj in &objects {
        hash_seq.add(obj)?;
    }

    // Hash in parallel
    let mut hash_par = LtHash16_1024::new()?;
    hash_par.add_parallel(&objects)?;

    assert_eq!(
        hash_seq.checksum(),
        hash_par.checksum(),
        "Parallel and sequential hashing produced different results"
    );

    // Also test from_parallel
    let hash_par2 = LtHash16_1024::from_parallel(&objects)?;
    assert_eq!(
        hash_seq.checksum(),
        hash_par2.checksum(),
        "from_parallel produced different results"
    );

    // Test with readers
    let readers: Vec<std::io::Cursor<&[u8]>> =
        objects.iter().map(|o| std::io::Cursor::new(*o)).collect();

    let hash_par_stream = LtHash16_1024::from_streams_parallel(readers)?;
    assert_eq!(
        hash_seq.checksum(),
        hash_par_stream.checksum(),
        "Parallel streaming produced different results"
    );

    Ok(())
}

/// Issue #24: PartialEq should consider keys, not just checksums
/// Two hashes with different keys but same checksum should NOT be equal
#[test]
fn test_partial_eq_considers_keys() -> Result<(), LtHashError> {
    // Use 32-byte keys (works with both BLAKE3 and Blake2xb backends)
    let key1 = b"this_is_a_32_byte_key_for_test1";
    let key2 = b"this_is_a_32_byte_key_for_test2";

    // Create two hashes with same data but different keys
    let mut hash1 = LtHash16_1024::new()?;
    hash1.set_key(key1)?;
    hash1.add(b"data")?;

    let mut hash2 = LtHash16_1024::new()?;
    hash2.set_key(key2)?;
    hash2.add(b"data")?;

    // Hashes with different keys should NOT be equal, even if we manually
    // set the checksums to be the same
    let mut hash3 = LtHash16_1024::new()?;
    hash3.set_key(key1)?;

    let mut hash4 = LtHash16_1024::new()?;
    hash4.set_key(key2)?;

    // Empty hashes have the same checksum (all zeros) but different keys
    // They should NOT be considered equal
    assert_ne!(
        hash3, hash4,
        "Hashes with different keys should not be equal even with same checksum"
    );

    // Same key, same checksum should be equal
    let mut hash5 = LtHash16_1024::new()?;
    hash5.set_key(key1)?;

    let mut hash6 = LtHash16_1024::new()?;
    hash6.set_key(key1)?;

    assert_eq!(
        hash5, hash6,
        "Hashes with same key and checksum should be equal"
    );

    // No key vs has key should not be equal
    let hash_no_key = LtHash16_1024::new()?;
    let mut hash_with_key = LtHash16_1024::new()?;
    hash_with_key.set_key(key1)?;

    assert_ne!(
        hash_no_key, hash_with_key,
        "Hash without key should not equal hash with key"
    );

    Ok(())
}

/// Issue #20: Blake2xb should reject zero-length output
#[cfg(feature = "folly-compat")]
#[test]
fn test_blake2xb_rejects_zero_length_output() {
    // Zero-length output should be rejected
    let mut output = vec![0u8; 0];
    let result = Blake2xb::hash(&mut output, b"test", &[], &[], &[]);
    assert!(result.is_err(), "Blake2xb should reject zero-length output");
}

/// Issue #21/#22: Blake3 should not report Blake2 errors
#[cfg(feature = "blake3-backend")]
#[test]
fn test_blake3_error_messages() {
    use std::io::{self, Read};

    // Create a reader that always fails
    struct FailingReader;
    impl Read for FailingReader {
        fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::new(io::ErrorKind::Other, "simulated error"))
        }
    }

    let mut xof = Blake3Xof::new();
    xof.init(64, &[], &[], &[]).unwrap();

    let result = xof.update_reader(FailingReader);
    assert!(result.is_err());

    let err = result.unwrap_err();
    let err_msg = err.to_string();

    // The error message should NOT mention Blake2
    assert!(
        !err_msg.to_lowercase().contains("blake2"),
        "Blake3 error should not mention Blake2: {}",
        err_msg
    );
}

/// Test that add_all and remove_all work correctly with empty slices
#[test]
fn test_add_all_empty() -> Result<(), LtHashError> {
    let mut hash = LtHash16_1024::new()?;
    hash.add(b"initial")?;
    let before_checksum = hash.checksum().to_vec();

    // Adding empty slice should not change the hash
    let empty: Vec<&[u8]> = vec![];
    hash.add_all(&empty)?;

    assert_eq!(
        hash.checksum(),
        before_checksum.as_slice(),
        "add_all with empty slice should not change hash"
    );

    // Remove empty slice should not change the hash
    hash.remove_all(&empty)?;

    assert_eq!(
        hash.checksum(),
        before_checksum.as_slice(),
        "remove_all with empty slice should not change hash"
    );

    Ok(())
}

/// Test that with_checksum rejects checksums with invalid padding bits (20-bit variant)
#[test]
fn test_with_checksum_rejects_invalid_padding() {
    use lthash::LtHash20_1008;

    // Create a valid checksum
    let mut valid_checksum = vec![0u8; LtHash20_1008::checksum_size_bytes()];

    // LtHash20_1008 should accept all-zero checksum
    assert!(
        LtHash20_1008::with_checksum(&valid_checksum).is_ok(),
        "Should accept valid all-zero checksum"
    );

    // Set a padding bit (the 20-bit variant has padding at specific positions)
    // Padding bits are at positions defined by the inverse of the data mask.
    // For 20-bit elements: !0xC000020000100000 means bits 62, 63, 17, 20 are padding
    // Set bit 62 (which is in position 7 of the first u64, counting from byte 0)
    valid_checksum[7] |= 0x40; // Set bit 62 (0x40 at byte 7 sets bit 6 of that byte = bit 62)

    let result = LtHash20_1008::with_checksum(&valid_checksum);
    assert!(
        result.is_err(),
        "Should reject checksum with non-zero padding bits"
    );
}

/// Test that Eq trait is properly implemented
#[test]
fn test_eq_trait() -> Result<(), LtHashError> {
    let mut hash1 = LtHash16_1024::new()?;
    let mut hash2 = LtHash16_1024::new()?;
    hash1.add(b"test")?;
    hash2.add(b"test")?;

    // Eq requires that a == a (reflexive)
    assert_eq!(hash1, hash1);
    // PartialEq should work
    assert_eq!(hash1, hash2);
    // Verify Eq is implemented by using it in a comparison
    assert!(hash1 == hash2);

    Ok(())
}

/// Test that parallel methods work with single item (edge case)
#[cfg(feature = "parallel")]
#[test]
fn test_parallel_single_item() -> Result<(), LtHashError> {
    let items: Vec<&[u8]> = vec![b"single item"];

    // Sequential
    let mut hash_seq = LtHash16_1024::new()?;
    hash_seq.add(b"single item")?;

    // Parallel with single item
    let mut hash_par = LtHash16_1024::new()?;
    hash_par.add_parallel(&items)?;

    assert_eq!(
        hash_seq.checksum(),
        hash_par.checksum(),
        "Parallel with single item should match sequential"
    );

    Ok(())
}

/// Test that Blake2xb's update_reader uses IoError, not Blake2Error
#[cfg(feature = "folly-compat")]
#[test]
fn test_blake2xb_io_error_type() {
    use lthash::Blake2xb;
    use std::io::{self, Read};

    // Create a reader that always fails
    struct FailingReader;
    impl Read for FailingReader {
        fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::new(io::ErrorKind::Other, "simulated error"))
        }
    }

    let mut xof = Blake2xb::new();
    xof.init(64, &[], &[], &[]).unwrap();

    let result = xof.update_reader(FailingReader);
    assert!(result.is_err());

    let err = result.unwrap_err();
    let err_msg = err.to_string();

    // The error message should be an I/O error, not a Blake2 error
    assert!(
        err_msg.contains("I/O") || err_msg.contains("error reading"),
        "Blake2xb I/O error should mention I/O: {}",
        err_msg
    );
}

/// Blake3Xof should reject zero-length output (API consistency with Blake2xb)
#[cfg(feature = "blake3-backend")]
#[test]
fn test_blake3_rejects_zero_length_output() {
    // Zero-length output should be rejected
    let mut output = vec![0u8; 0];
    let result = Blake3Xof::hash(&mut output, b"test", &[], &[], &[]);
    assert!(
        result.is_err(),
        "Blake3Xof should reject zero-length output"
    );
}

// ============================================================================
// Additional coverage tests for edge cases and error paths
// ============================================================================

/// Test Clone implementation
#[test]
fn test_clone() -> Result<(), LtHashError> {
    let mut original = LtHash16_1024::new()?;
    original.add(b"test data")?;

    let cloned = original.clone();

    // Cloned should have same checksum
    assert_eq!(original.checksum(), cloned.checksum());

    // Modifying original shouldn't affect clone
    original.add(b"more data")?;
    assert_ne!(original.checksum(), cloned.checksum());

    Ok(())
}

/// Test Debug implementation
#[test]
fn test_debug() -> Result<(), LtHashError> {
    let hash = LtHash16_1024::new()?;
    let debug_str = format!("{:?}", hash);

    // Debug output should contain expected fields
    assert!(debug_str.contains("LtHash"));
    assert!(debug_str.contains("checksum_len"));
    assert!(debug_str.contains("has_key"));

    Ok(())
}

/// Test with_checksum rejects wrong size
#[test]
fn test_with_checksum_wrong_size() {
    // Too small
    let small_checksum = vec![0u8; 100];
    let result = LtHash16_1024::with_checksum(&small_checksum);
    assert!(result.is_err(), "Should reject checksum that's too small");

    // Too large
    let large_checksum = vec![0u8; 10000];
    let result = LtHash16_1024::with_checksum(&large_checksum);
    assert!(result.is_err(), "Should reject checksum that's too large");
}

/// Test set_key with empty key should fail
#[test]
fn test_set_key_empty() -> Result<(), LtHashError> {
    let mut hash = LtHash16_1024::new()?;
    let result = hash.set_key(b"");
    assert!(result.is_err(), "Empty key should be rejected");
    Ok(())
}

/// Test add_iter and remove_iter methods
#[test]
fn test_iter_methods() -> Result<(), LtHashError> {
    let items = vec![b"one".as_slice(), b"two".as_slice(), b"three".as_slice()];

    // Test add_iter
    let mut hash1 = LtHash16_1024::new()?;
    hash1.add_iter(items.iter().copied())?;

    // Should be equivalent to sequential adds
    let mut hash2 = LtHash16_1024::new()?;
    for item in &items {
        hash2.add(*item)?;
    }
    assert_eq!(hash1.checksum(), hash2.checksum());

    // Test remove_iter
    let to_remove = vec![b"one".as_slice(), b"two".as_slice()];
    hash1.remove_iter(to_remove.iter().copied())?;

    let mut hash3 = LtHash16_1024::new()?;
    hash3.add(b"three")?;
    assert_eq!(hash1.checksum(), hash3.checksum());

    Ok(())
}

/// Test checksum_eq method
#[test]
fn test_checksum_eq() -> Result<(), LtHashError> {
    let mut hash = LtHash16_1024::new()?;
    hash.add(b"test")?;

    let checksum = hash.checksum().to_vec();

    // Should return true for matching checksum
    assert!(hash.checksum_eq(&checksum)?);

    // Should return false for different checksum
    let mut different = checksum.clone();
    different[0] ^= 0xFF;
    assert!(!hash.checksum_eq(&different)?);

    // Should error for wrong size
    let wrong_size = vec![0u8; 100];
    assert!(hash.checksum_eq(&wrong_size).is_err());

    Ok(())
}

/// Test try_add and try_sub with key mismatch
#[test]
fn test_try_add_sub_key_mismatch() -> Result<(), LtHashError> {
    let mut hash1 = LtHash16_1024::new()?;
    hash1.set_key(b"key1")?;
    hash1.add(b"data")?;

    let mut hash2 = LtHash16_1024::new()?;
    hash2.set_key(b"key2")?;
    hash2.add(b"data")?;

    // try_add should fail with key mismatch
    let result = hash1.clone().try_add(&hash2);
    assert!(result.is_err(), "try_add should fail with different keys");

    // try_sub should fail with key mismatch
    let result = hash1.clone().try_sub(&hash2);
    assert!(result.is_err(), "try_sub should fail with different keys");

    Ok(())
}

/// Test try_add and try_sub with matching keys
#[test]
fn test_try_add_sub_same_keys() -> Result<(), LtHashError> {
    let mut hash1 = LtHash16_1024::new()?;
    hash1.add(b"data1")?;

    let mut hash2 = LtHash16_1024::new()?;
    hash2.add(b"data2")?;

    // try_add should succeed with same (no) keys
    let mut combined = hash1.clone();
    combined.try_add(&hash2)?;

    // Verify result
    let mut expected = LtHash16_1024::new()?;
    expected.add(b"data1")?.add(b"data2")?;
    assert_eq!(combined.checksum(), expected.checksum());

    // try_sub should work
    combined.try_sub(&hash2)?;
    assert_eq!(combined.checksum(), hash1.checksum());

    Ok(())
}

/// Test Default implementation
#[test]
fn test_default() {
    let hash: LtHash16_1024 = Default::default();
    assert!(hash.is_zero());
}

/// Test Sub and SubAssign operators
#[test]
fn test_sub_operators() -> Result<(), LtHashError> {
    let mut hash1 = LtHash16_1024::new()?;
    hash1.add(b"a")?.add(b"b")?.add(b"c")?;

    let mut hash2 = LtHash16_1024::new()?;
    hash2.add(b"b")?;

    // Test Sub operator (-)
    let result = hash1.clone() - hash2.clone();

    let mut expected = LtHash16_1024::new()?;
    expected.add(b"a")?.add(b"c")?;
    assert_eq!(result.checksum(), expected.checksum());

    // Test SubAssign operator (-=)
    let mut hash3 = hash1.clone();
    hash3 -= hash2;
    assert_eq!(hash3.checksum(), expected.checksum());

    Ok(())
}

/// Test LtHash32_1024 variant for coverage
#[test]
fn test_lthash32_operations() -> Result<(), LtHashError> {
    use lthash::LtHash32_1024;

    let mut hash = LtHash32_1024::new()?;
    assert!(hash.is_zero());

    hash.add(b"test data")?;
    assert!(!hash.is_zero());

    // Test homomorphic property
    let mut h1 = LtHash32_1024::new()?;
    let mut h2 = LtHash32_1024::new()?;
    h1.add(b"a")?.add(b"b")?;
    h2.add(b"b")?.add(b"a")?;
    assert_eq!(h1.checksum(), h2.checksum());

    // Test subtraction
    h1.remove(b"a")?;
    let mut h3 = LtHash32_1024::new()?;
    h3.add(b"b")?;
    assert_eq!(h1.checksum(), h3.checksum());

    Ok(())
}

/// Test LtHash20_1008 variant operations
#[test]
fn test_lthash20_operations() -> Result<(), LtHashError> {
    use lthash::LtHash20_1008;

    let mut hash = LtHash20_1008::new()?;
    assert!(hash.is_zero());

    hash.add(b"test data")?;
    assert!(!hash.is_zero());

    // Test subtraction restores zero
    hash.remove(b"test data")?;
    assert!(hash.is_zero());

    Ok(())
}

/// Test constant_time_eq with different length slices
#[test]
fn test_constant_time_eq_different_lengths() -> Result<(), LtHashError> {
    // This tests the internal constant_time_eq function via checksum_eq
    let mut hash = LtHash16_1024::new()?;
    hash.add(b"test")?;

    // Wrong length should be rejected
    let wrong_len = vec![0u8; 100];
    let result = hash.checksum_eq(&wrong_len);
    assert!(result.is_err(), "Should reject wrong length checksum");

    Ok(())
}

/// Test element_size_in_bits and element_count methods
#[test]
fn test_static_methods() {
    use lthash::{LtHash20_1008, LtHash32_1024};

    // LtHash16_1024
    assert_eq!(LtHash16_1024::element_size_in_bits(), 16);
    assert_eq!(LtHash16_1024::element_count(), 1024);
    assert_eq!(LtHash16_1024::checksum_size_bytes(), 2048);

    // LtHash20_1008
    assert_eq!(LtHash20_1008::element_size_in_bits(), 20);
    assert_eq!(LtHash20_1008::element_count(), 1008);

    // LtHash32_1024
    assert_eq!(LtHash32_1024::element_size_in_bits(), 32);
    assert_eq!(LtHash32_1024::element_count(), 1024);
    assert_eq!(LtHash32_1024::checksum_size_bytes(), 4096);
}

/// Test parallel add with empty slice
#[cfg(feature = "parallel")]
#[test]
fn test_parallel_empty_items() -> Result<(), LtHashError> {
    let mut hash = LtHash16_1024::new()?;
    hash.add(b"initial")?;
    let before = hash.checksum().to_vec();

    // Empty parallel add should not change hash
    let empty: Vec<&[u8]> = vec![];
    hash.add_parallel(&empty)?;

    assert_eq!(hash.checksum(), before.as_slice());

    Ok(())
}

/// Test parallel streams with empty vector
#[cfg(feature = "parallel")]
#[test]
fn test_parallel_streams_empty() -> Result<(), LtHashError> {
    let mut hash = LtHash16_1024::new()?;
    hash.add(b"initial")?;
    let before = hash.checksum().to_vec();

    // Empty parallel streams should not change hash
    let empty: Vec<std::io::Cursor<&[u8]>> = vec![];
    hash.add_streams_parallel(empty)?;

    assert_eq!(hash.checksum(), before.as_slice());

    Ok(())
}

/// Test digest method (available only for blake3-backend without folly-compat)
#[cfg(all(feature = "blake3-backend", not(feature = "folly-compat")))]
#[test]
fn test_digest_empty() -> Result<(), LtHashError> {
    let hash = LtHash16_1024::new()?;
    let digest = hash.digest();

    // Empty hash should have consistent digest
    assert_eq!(digest.len(), 32);

    // Two empty hashes should have same digest
    let hash2 = LtHash16_1024::new()?;
    assert_eq!(hash.digest(), hash2.digest());

    Ok(())
}

/// Test large data streaming
#[test]
fn test_large_data_streaming() -> Result<(), LtHashError> {
    // Generate 1MB of data
    let data: Vec<u8> = (0..1_000_000).map(|i| (i % 256) as u8).collect();

    // Hash using streaming
    let mut hash_stream = LtHash16_1024::new()?;
    hash_stream.add_stream(std::io::Cursor::new(&data))?;

    // Hash using in-memory
    let mut hash_mem = LtHash16_1024::new()?;
    hash_mem.add(&data)?;

    assert_eq!(hash_stream.checksum(), hash_mem.checksum());

    Ok(())
}

/// Test clear_key actually clears the key
#[test]
fn test_clear_key() -> Result<(), LtHashError> {
    let mut hash1 = LtHash16_1024::new()?;
    hash1.set_key(b"secret")?;
    hash1.add(b"data")?;

    let mut hash2 = LtHash16_1024::new()?;
    hash2.set_key(b"secret")?;
    hash2.clear_key();
    hash2.add(b"data")?;

    // After clearing key, hash2 should behave like unkeyed
    let mut hash3 = LtHash16_1024::new()?;
    hash3.add(b"data")?;

    assert_eq!(hash2.checksum(), hash3.checksum());
    assert_ne!(hash1.checksum(), hash2.checksum());

    Ok(())
}

/// Test that Add operator panics with different keys
#[test]
#[should_panic(expected = "Cannot add LtHashes with different keys")]
fn test_add_operator_key_mismatch_panics() {
    let mut hash1 = LtHash16_1024::new().unwrap();
    hash1.set_key(b"key1").unwrap();
    hash1.add(b"data").unwrap();

    let mut hash2 = LtHash16_1024::new().unwrap();
    hash2.set_key(b"key2").unwrap();
    hash2.add(b"data").unwrap();

    let _ = hash1 + hash2; // Should panic
}

/// Test that Sub operator panics with different keys
#[test]
#[should_panic(expected = "Cannot subtract LtHashes with different keys")]
fn test_sub_operator_key_mismatch_panics() {
    let mut hash1 = LtHash16_1024::new().unwrap();
    hash1.set_key(b"key1").unwrap();
    hash1.add(b"data").unwrap();

    let mut hash2 = LtHash16_1024::new().unwrap();
    hash2.set_key(b"key2").unwrap();
    hash2.add(b"data").unwrap();

    let _ = hash1 - hash2; // Should panic
}

/// Test boundary conditions - very small input
#[test]
fn test_small_inputs() -> Result<(), LtHashError> {
    let mut hash = LtHash16_1024::new()?;

    // Empty input
    hash.add(b"")?;
    let empty_hash = hash.checksum().to_vec();

    // Single byte
    hash.reset();
    hash.add(&[0u8])?;
    assert_ne!(hash.checksum(), empty_hash.as_slice());

    // Single byte different value
    hash.reset();
    hash.add(&[1u8])?;
    let one_hash = hash.checksum().to_vec();

    hash.reset();
    hash.add(&[0u8])?;
    assert_ne!(hash.checksum(), one_hash.as_slice());

    Ok(())
}

/// Test reset functionality
#[test]
fn test_reset() -> Result<(), LtHashError> {
    let mut hash = LtHash16_1024::new()?;
    hash.add(b"some data")?;
    assert!(!hash.is_zero());

    hash.reset();
    assert!(hash.is_zero());

    // Can add data after reset
    hash.add(b"new data")?;
    assert!(!hash.is_zero());

    Ok(())
}

/// Test that streaming and non-streaming produce same results for edge cases
#[test]
fn test_streaming_edge_cases() -> Result<(), LtHashError> {
    // Test with data size exactly at buffer boundary (64KB)
    let data = vec![0xABu8; 65536];

    let mut hash_stream = LtHash16_1024::new()?;
    hash_stream.add_stream(std::io::Cursor::new(&data))?;

    let mut hash_mem = LtHash16_1024::new()?;
    hash_mem.add(&data)?;

    assert_eq!(hash_stream.checksum(), hash_mem.checksum());

    // Test with data size slightly over buffer (64KB + 1)
    let data2 = vec![0xCDu8; 65537];

    let mut hash_stream2 = LtHash16_1024::new()?;
    hash_stream2.add_stream(std::io::Cursor::new(&data2))?;

    let mut hash_mem2 = LtHash16_1024::new()?;
    hash_mem2.add(&data2)?;

    assert_eq!(hash_stream2.checksum(), hash_mem2.checksum());

    Ok(())
}

// ============================================================================
// Stress tests and edge case exploration to find breaking inputs
// ============================================================================

/// Test that adding and removing the same element many times returns to zero
#[test]
fn test_add_remove_stress() -> Result<(), LtHashError> {
    let mut hash = LtHash16_1024::new()?;
    let data = b"stress test data";

    // Add and remove many times
    for _ in 0..1000 {
        hash.add(data)?;
        hash.remove(data)?;
    }

    assert!(hash.is_zero(), "Hash should return to zero after equal adds and removes");
    Ok(())
}

/// Test wrapping behavior at u16 boundaries (LtHash16)
#[test]
fn test_u16_wrapping() -> Result<(), LtHashError> {
    // Create a hash and add the same element many times to cause wrapping
    let mut hash = LtHash16_1024::new()?;
    let data = b"wrap";

    // Add 65536 times (2^16) should wrap back to original
    for _ in 0..65536 {
        hash.add(data)?;
    }

    // Adding 65536 times with 16-bit wrapping should be equivalent to adding 0 times
    // (since 65536 mod 2^16 = 0)
    let empty = LtHash16_1024::new()?;
    assert_eq!(hash.checksum(), empty.checksum(), "65536 adds should wrap to zero");

    Ok(())
}

/// Test that hash is deterministic across many operations
#[test]
fn test_determinism_stress() -> Result<(), LtHashError> {
    let items: Vec<&[u8]> = vec![b"a", b"b", b"c", b"d", b"e"];

    // Create hash with all items
    let mut hash1 = LtHash16_1024::new()?;
    for item in &items {
        hash1.add(*item)?;
    }

    // Create same hash in different order
    let mut hash2 = LtHash16_1024::new()?;
    for item in items.iter().rev() {
        hash2.add(*item)?;
    }

    assert_eq!(hash1.checksum(), hash2.checksum(), "Order should not matter");

    // Create same hash using parallel
    let hash3 = LtHash16_1024::from_parallel(&items)?;
    assert_eq!(hash1.checksum(), hash3.checksum(), "Parallel should match sequential");

    Ok(())
}

/// Test with all-zeros input
#[test]
fn test_all_zeros_input() -> Result<(), LtHashError> {
    let zeros = vec![0u8; 10000];

    let mut hash = LtHash16_1024::new()?;
    hash.add(&zeros)?;

    // All-zeros input should produce non-zero hash
    assert!(!hash.is_zero(), "All-zeros input should produce non-zero hash");

    // Removing should return to zero
    hash.remove(&zeros)?;
    assert!(hash.is_zero());

    Ok(())
}

/// Test with all-ones input (0xFF bytes)
#[test]
fn test_all_ones_input() -> Result<(), LtHashError> {
    let ones = vec![0xFFu8; 10000];

    let mut hash = LtHash16_1024::new()?;
    hash.add(&ones)?;

    assert!(!hash.is_zero(), "All-ones input should produce non-zero hash");

    hash.remove(&ones)?;
    assert!(hash.is_zero());

    Ok(())
}

/// Test with maximum length data that's reasonable
#[test]
fn test_large_single_element() -> Result<(), LtHashError> {
    // 10MB element
    let large_data: Vec<u8> = (0..10_000_000).map(|i| (i % 256) as u8).collect();

    let mut hash = LtHash16_1024::new()?;
    hash.add(&large_data)?;

    assert!(!hash.is_zero());

    // Verify streaming matches
    let mut hash_stream = LtHash16_1024::new()?;
    hash_stream.add_stream(std::io::Cursor::new(&large_data))?;

    assert_eq!(hash.checksum(), hash_stream.checksum());

    Ok(())
}

/// Test that same data with different keys produces different hashes
#[test]
fn test_key_affects_hash() -> Result<(), LtHashError> {
    let data = b"test data for keyed hashing";

    let mut hash1 = LtHash16_1024::new()?;
    hash1.set_key(b"key1")?;
    hash1.add(data)?;

    let mut hash2 = LtHash16_1024::new()?;
    hash2.set_key(b"key2")?;
    hash2.add(data)?;

    let mut hash3 = LtHash16_1024::new()?;
    hash3.add(data)?;

    // All three should be different
    assert_ne!(hash1.checksum(), hash2.checksum());
    assert_ne!(hash1.checksum(), hash3.checksum());
    assert_ne!(hash2.checksum(), hash3.checksum());

    Ok(())
}

/// Test associativity: (a + b) + c == a + (b + c)
#[test]
fn test_associativity() -> Result<(), LtHashError> {
    let a = b"element_a";
    let b = b"element_b";
    let c = b"element_c";

    // (a + b) + c
    let mut hash1 = LtHash16_1024::new()?;
    hash1.add(a)?.add(b)?;
    let mut ab = hash1.clone();
    ab.add(c)?;

    // a + (b + c)
    let mut hash2 = LtHash16_1024::new()?;
    hash2.add(b)?.add(c)?;
    let mut bc = LtHash16_1024::new()?;
    bc.add(a)?;
    bc.try_add(&hash2)?;

    assert_eq!(ab.checksum(), bc.checksum(), "Associativity should hold");

    Ok(())
}

/// Test that homomorphic property holds for subtraction: H(A-B) = H(A) - H(B)
#[test]
fn test_homomorphic_subtraction() -> Result<(), LtHashError> {
    let items_a: Vec<&[u8]> = vec![b"1", b"2", b"3", b"4", b"5"];
    let items_b: Vec<&[u8]> = vec![b"3", b"4"];

    // H(A) computed directly
    let mut hash_a = LtHash16_1024::new()?;
    for item in &items_a {
        hash_a.add(*item)?;
    }

    // H(B) computed directly
    let mut hash_b = LtHash16_1024::new()?;
    for item in &items_b {
        hash_b.add(*item)?;
    }

    // H(A) - H(B) via homomorphic subtraction
    let mut result_homomorphic = hash_a.clone();
    result_homomorphic.try_sub(&hash_b)?;

    // H(A-B) computed directly (items in A but not in B)
    let mut result_direct = LtHash16_1024::new()?;
    result_direct.add(b"1")?.add(b"2")?.add(b"5")?;

    assert_eq!(
        result_homomorphic.checksum(),
        result_direct.checksum(),
        "Homomorphic subtraction should equal direct computation"
    );

    Ok(())
}

/// Test edge case: checksum with maximum values (all 0xFF)
#[test]
fn test_max_checksum_values() -> Result<(), LtHashError> {
    // Create a checksum with all maximum values
    let max_checksum = vec![0xFFu8; LtHash16_1024::checksum_size_bytes()];

    let hash = LtHash16_1024::with_checksum(&max_checksum)?;

    // Adding an element should wrap
    let mut hash2 = hash.clone();
    hash2.add(b"test")?;

    // The checksum should have changed
    assert_ne!(hash.checksum(), hash2.checksum());

    Ok(())
}

/// Test that remove_all with duplicates works correctly
#[test]
fn test_remove_all_with_duplicates() -> Result<(), LtHashError> {
    let mut hash = LtHash16_1024::new()?;

    // Add: a, a, b
    hash.add(b"a")?.add(b"a")?.add(b"b")?;

    // Remove: a, a (should leave just b)
    hash.remove_all(&[b"a", b"a"])?;

    let mut expected = LtHash16_1024::new()?;
    expected.add(b"b")?;

    assert_eq!(hash.checksum(), expected.checksum());

    Ok(())
}

/// Test LtHash32 wrapping at u32 boundaries
#[test]
fn test_u32_wrapping() -> Result<(), LtHashError> {
    use lthash::LtHash32_1024;

    // This is a simplified test - we can't easily test 2^32 additions
    // but we can verify the math works with the subtraction path
    let mut hash = LtHash32_1024::new()?;
    hash.add(b"test")?;

    // Add and subtract should cancel out
    hash.add(b"cancel")?;
    hash.remove(b"cancel")?;

    let mut expected = LtHash32_1024::new()?;
    expected.add(b"test")?;

    assert_eq!(hash.checksum(), expected.checksum());

    Ok(())
}

/// Test LtHash20 padding bit handling
#[test]
fn test_lthash20_padding() -> Result<(), LtHashError> {
    use lthash::LtHash20_1008;

    let mut hash = LtHash20_1008::new()?;
    hash.add(b"test data")?;

    // Verify checksum is valid (no padding bits set)
    let checksum = hash.checksum();

    // Create new hash from checksum (validates padding)
    let hash2 = LtHash20_1008::with_checksum(checksum)?;
    assert_eq!(hash.checksum(), hash2.checksum());

    // Operations should preserve valid padding
    let mut hash3 = hash.clone();
    hash3.add(b"more data")?;
    let hash4 = LtHash20_1008::with_checksum(hash3.checksum())?;
    assert_eq!(hash3.checksum(), hash4.checksum());

    Ok(())
}

/// Test Blake3Xof streaming API edge cases
#[cfg(feature = "blake3-backend")]
#[test]
fn test_blake3_xof_streaming_states() {
    // Test calling methods in wrong order
    let mut xof = Blake3Xof::new();

    // Update before init should fail
    let result = xof.update(b"data");
    assert!(result.is_err());

    // Finish before init should fail
    let mut output = [0u8; 64];
    let result = xof.finish(&mut output);
    assert!(result.is_err());

    // Proper sequence
    xof.init(64, &[], &[], &[]).unwrap();
    xof.update(b"data").unwrap();
    xof.finish(&mut output).unwrap();

    // Update after finish should fail
    let result = xof.update(b"more");
    assert!(result.is_err());

    // Double finish should fail
    let result = xof.finish(&mut output);
    assert!(result.is_err());
}

/// Test Blake3Xof output size mismatch
#[cfg(feature = "blake3-backend")]
#[test]
fn test_blake3_xof_output_size_mismatch() {
    let mut xof = Blake3Xof::new();
    xof.init(64, &[], &[], &[]).unwrap();
    xof.update(b"data").unwrap();

    // Wrong output size should fail
    let mut wrong_size = [0u8; 32];
    let result = xof.finish(&mut wrong_size);
    assert!(result.is_err());
}

/// Test keyed streaming with Blake3Xof
#[cfg(feature = "blake3-backend")]
#[test]
fn test_blake3_xof_keyed_streaming() {
    let key = [42u8; 32];
    let mut xof = Blake3Xof::new();
    xof.init(64, &key, &[], &[]).unwrap();
    xof.update(b"hello ").unwrap();
    xof.update(b"world").unwrap();
    let mut streaming_output = [0u8; 64];
    xof.finish(&mut streaming_output).unwrap();

    // Compare with one-shot
    let mut oneshot_output = [0u8; 64];
    Blake3Xof::hash(&mut oneshot_output, b"hello world", &key, &[], &[]).unwrap();

    assert_eq!(streaming_output, oneshot_output);
}

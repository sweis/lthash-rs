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

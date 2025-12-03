use lthash::{LtHash16_1024, LtHashError};

#[cfg(feature = "blake3-backend")]
use lthash::Blake3Xof;
#[cfg(feature = "folly-compat")]
use lthash::Blake2xb;

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
    hash.add_object(b"test")?;

    let checksum = hash.get_checksum();
    assert_eq!(checksum.len(), LtHash16_1024::checksum_size_bytes());
    assert_ne!(checksum, vec![0u8; checksum.len()]); // Should not be all zeros
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
            hash.add_object(vector.input)?;
        }

        let result: String = hash.get_checksum()[..16]
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
            hash.add_object(vector.input)?;
        }
        let result: String = hash.get_checksum()[..16]
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
            hash.add_object(vector.input)?;
        }
        let result: String = hash.get_checksum()[..16]
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
            hash.add_object(vector.input)?;
        }
        let result: String = hash.get_checksum()[..16]
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

    hash1.add_object(b"a")?;
    hash1.add_object(b"b")?;

    hash2.add_object(b"b")?;
    hash2.add_object(b"a")?;

    assert_eq!(
        hash1.get_checksum(),
        hash2.get_checksum(),
        "Commutativity failed"
    );

    // Test additive inverse: a+b-a == b
    hash1.remove_object(b"a")?;
    let mut hash_just_b = LtHash16_1024::new()?;
    hash_just_b.add_object(b"b")?;

    assert_eq!(
        hash1.get_checksum(),
        hash_just_b.get_checksum(),
        "Additive inverse failed"
    );

    // Test homomorphic addition: H(a) + H(b) == H(a+b)
    let mut h_a = LtHash16_1024::new()?;
    let mut h_b = LtHash16_1024::new()?;
    let mut h_ab = LtHash16_1024::new()?;

    h_a.add_object(b"a")?;
    h_b.add_object(b"b")?;
    h_ab.add_object(b"a")?;
    h_ab.add_object(b"b")?;

    let h_sum = h_a + h_b;
    assert_eq!(
        h_sum.get_checksum(),
        h_ab.get_checksum(),
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
    hash_mem.add_object(&data)?;

    // Hash using streaming method
    let mut hash_stream = LtHash16_1024::new()?;
    hash_stream.add_object_stream(std::io::Cursor::new(&data))?;

    assert_eq!(
        hash_mem.get_checksum(),
        hash_stream.get_checksum(),
        "Streaming and in-memory hashing produced different results"
    );

    // Also test remove_object_stream
    let mut hash_mem2 = LtHash16_1024::new()?;
    hash_mem2.add_object(&data)?;
    hash_mem2.remove_object(&data)?;

    let mut hash_stream2 = LtHash16_1024::new()?;
    hash_stream2.add_object_stream(std::io::Cursor::new(&data))?;
    hash_stream2.remove_object_stream(std::io::Cursor::new(&data))?;

    assert_eq!(
        hash_mem2.get_checksum(),
        hash_stream2.get_checksum(),
        "Streaming remove produced different results"
    );

    // Both should be back to zero (empty set)
    let empty_hash = LtHash16_1024::new()?;
    assert_eq!(
        hash_stream2.get_checksum(),
        empty_hash.get_checksum(),
        "add then remove should equal empty hash"
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
        hash_seq.add_object(obj)?;
    }

    // Hash in parallel
    let mut hash_par = LtHash16_1024::new()?;
    hash_par.add_objects_parallel(&objects)?;

    assert_eq!(
        hash_seq.get_checksum(),
        hash_par.get_checksum(),
        "Parallel and sequential hashing produced different results"
    );

    // Also test from_objects_parallel
    let hash_par2 = LtHash16_1024::from_objects_parallel(&objects)?;
    assert_eq!(
        hash_seq.get_checksum(),
        hash_par2.get_checksum(),
        "from_objects_parallel produced different results"
    );

    // Test with readers
    let readers: Vec<std::io::Cursor<&[u8]>> = objects
        .iter()
        .map(|o| std::io::Cursor::new(*o))
        .collect();

    let hash_par_stream = LtHash16_1024::from_readers_parallel(readers)?;
    assert_eq!(
        hash_seq.get_checksum(),
        hash_par_stream.get_checksum(),
        "Parallel streaming produced different results"
    );

    Ok(())
}

/// Test BLAKE3 backend LtHash against fixed test vectors for regression testing.
/// These vectors were generated from the BLAKE3 backend and ensure that
/// future changes don't break backward compatibility.
#[cfg(all(feature = "blake3-backend", not(feature = "folly-compat")))]
#[test]
fn test_blake3_lthash_vectors() -> Result<(), LtHashError> {
    use lthash::{LtHash20_1008, LtHash32_1024};

    // Test vectors for LtHash16_1024 with BLAKE3 backend
    // Format: (name, input, expected_first_16_bytes_hex)
    const LTHASH_16_1024_BLAKE3_VECTORS: &[(&str, &[u8], &str)] = &[
        ("empty", b"", "00000000000000000000000000000000"),
        ("a", b"a", "17762fddd969a453925d65717ac3eea2"),
        ("b", b"b", "10e5cf3d3c8a4f9f3468c8cc58eea848"),
        ("test", b"test", "4878ca0425c739fa427f7eda20fe845f"),
        ("hello", b"hello", "ea8f163db38682925e4491c5e58d4bb3"),
    ];

    const LTHASH_20_1008_BLAKE3_VECTORS: &[(&str, &[u8], &str)] = &[
        ("empty", b"", "00000000000000000000000000000000"),
        ("a", b"a", "17762fddd969a413925d65717ac1ee22"),
        ("b", b"b", "10e5cf3d3c884f1f3468c8cc58eca808"),
        ("test", b"test", "4878ca0425c5393a427f6eda20fc841f"),
        ("hello", b"hello", "ea8f063db38482125e4481c5e58d4b33"),
    ];

    const LTHASH_32_1024_BLAKE3_VECTORS: &[(&str, &[u8], &str)] = &[
        ("empty", b"", "00000000000000000000000000000000"),
        ("a", b"a", "17762fddd969a453925d65717ac3eea2"),
        ("b", b"b", "10e5cf3d3c8a4f9f3468c8cc58eea848"),
        ("test", b"test", "4878ca0425c739fa427f7eda20fe845f"),
        ("hello", b"hello", "ea8f163db38682925e4491c5e58d4bb3"),
    ];

    // Test LtHash16_1024
    for (name, input, expected) in LTHASH_16_1024_BLAKE3_VECTORS {
        let mut hash = LtHash16_1024::new()?;
        if !input.is_empty() {
            hash.add_object(input)?;
        }
        let result: String = hash.get_checksum()[..16]
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();
        assert_eq!(
            &result, expected,
            "LtHash16_1024 BLAKE3 vector mismatch for '{}'",
            name
        );
    }

    // Test LtHash20_1008
    for (name, input, expected) in LTHASH_20_1008_BLAKE3_VECTORS {
        let mut hash = LtHash20_1008::new()?;
        if !input.is_empty() {
            hash.add_object(input)?;
        }
        let result: String = hash.get_checksum()[..16]
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();
        assert_eq!(
            &result, expected,
            "LtHash20_1008 BLAKE3 vector mismatch for '{}'",
            name
        );
    }

    // Test LtHash32_1024
    for (name, input, expected) in LTHASH_32_1024_BLAKE3_VECTORS {
        let mut hash = LtHash32_1024::new()?;
        if !input.is_empty() {
            hash.add_object(input)?;
        }
        let result: String = hash.get_checksum()[..16]
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();
        assert_eq!(
            &result, expected,
            "LtHash32_1024 BLAKE3 vector mismatch for '{}'",
            name
        );
    }

    Ok(())
}

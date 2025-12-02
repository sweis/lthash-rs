use lthash::{LtHash16_1024, LtHashError};

#[cfg(feature = "sodium")]
use lthash::Blake2xb;
#[cfg(feature = "blake3-backend")]
use lthash::Blake3Xof;

mod test_vectors;

#[cfg(feature = "sodium")]
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

#[cfg(feature = "sodium")]
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

#[cfg(feature = "sodium")]
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

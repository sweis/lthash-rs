use lthash::{Blake2xb, LtHash16_1024, LtHash20_1008, LtHash32_1024, LtHashError};

mod test_vectors {
    include!("../../tests/test_vectors.rs");
}

fn main() -> Result<(), LtHashError> {
    println!("=== Cross-Compatibility Test: Rust vs C++ ===");

    // Test Blake2xb with static test vectors
    test_blake2xb_vectors()?;

    // Test LtHash with static test vectors
    test_lthash_vectors()?;

    println!("\n=== All tests completed ===");
    Ok(())
}

fn test_blake2xb_vectors() -> Result<(), LtHashError> {
    println!("\n--- Blake2xb Test Vectors (matching C++) ---");

    println!("\nNon-keyed Blake2xb:");
    for vector in test_vectors::blake2xb::NON_KEYED_VECTORS {
        let mut output = vec![0u8; vector.output_length];
        Blake2xb::hash(
            &mut output,
            vector.input,
            vector.key,
            vector.salt,
            vector.personalization,
        )?;

        let result_hex = hex_encode(&output);
        let passed = result_hex == vector.expected;

        println!(
            "Length {}: {} (got {}, expected {})",
            vector.output_length,
            if passed { "✓ PASS" } else { "✗ FAIL" },
            result_hex,
            vector.expected
        );
    }

    println!("\nKeyed Blake2xb:");
    for vector in test_vectors::blake2xb::KEYED_VECTORS {
        let mut output = vec![0u8; vector.output_length];
        Blake2xb::hash(
            &mut output,
            vector.input,
            vector.key,
            vector.salt,
            vector.personalization,
        )?;

        let result_hex = hex_encode(&output);
        let passed = result_hex == vector.expected;

        println!(
            "Length {}: {} (got {}, expected {})",
            vector.output_length,
            if passed { "✓ PASS" } else { "✗ FAIL" },
            result_hex,
            vector.expected
        );
    }

    Ok(())
}

fn test_lthash_vectors() -> Result<(), LtHashError> {
    println!("\n--- LtHash Test Vectors (matching C++) ---");

    // Test LtHash<16, 1024>
    {
        println!("\nLtHash<16, 1024>:");
        for vector in test_vectors::lthash::LTHASH_16_1024_VECTORS {
            let mut hash = LtHash16_1024::new()?;

            if !vector.input.is_empty() {
                hash.add_object(vector.input)?;
            }

            let result = hex_encode(&hash.get_checksum()[..16]); // First 16 bytes
            let passed = result == vector.expected_first_16_bytes;

            println!(
                "  {}: {} (got {}, expected {})",
                vector.name,
                if passed { "✓ PASS" } else { "✗ FAIL" },
                result,
                vector.expected_first_16_bytes
            );
        }
    }

    // Test LtHash<20, 1008>
    {
        println!("\nLtHash<20, 1008>:");
        for vector in test_vectors::lthash::LTHASH_20_1008_VECTORS {
            let mut hash = LtHash20_1008::new()?;

            if !vector.input.is_empty() {
                hash.add_object(vector.input)?;
            }

            let result = hex_encode(&hash.get_checksum()[..16]); // First 16 bytes
            let passed = result == vector.expected_first_16_bytes;

            println!(
                "  {}: {} (got {}, expected {})",
                vector.name,
                if passed { "✓ PASS" } else { "✗ FAIL" },
                result,
                vector.expected_first_16_bytes
            );
        }
    }

    // Test LtHash<32, 1024>
    {
        println!("\nLtHash<32, 1024>:");
        for vector in test_vectors::lthash::LTHASH_32_1024_VECTORS {
            let mut hash = LtHash32_1024::new()?;

            if !vector.input.is_empty() {
                hash.add_object(vector.input)?;
            }

            let result = hex_encode(&hash.get_checksum()[..16]); // First 16 bytes
            let passed = result == vector.expected_first_16_bytes;

            println!(
                "  {}: {} (got {}, expected {})",
                vector.name,
                if passed { "✓ PASS" } else { "✗ FAIL" },
                result,
                vector.expected_first_16_bytes
            );
        }
    }

    // Test commutativity and homomorphic properties
    {
        println!("\nHomomorphic Property Tests:");
        let mut hash1 = LtHash16_1024::new()?;
        let mut hash2 = LtHash16_1024::new()?;

        // Test: a+b == b+a (commutativity)
        hash1.add_object(b"a")?;
        hash1.add_object(b"b")?;

        hash2.add_object(b"b")?;
        hash2.add_object(b"a")?;

        let commutative = hash1.get_checksum() == hash2.get_checksum();
        println!(
            "  a+b == b+a (commutativity): {}",
            if commutative { "✓ PASS" } else { "✗ FAIL" }
        );

        // Test: a+b-a == b (additive inverse)
        hash1.remove_object(b"a")?;
        let mut hash_just_b = LtHash16_1024::new()?;
        hash_just_b.add_object(b"b")?;

        let removal_works = hash1.get_checksum() == hash_just_b.get_checksum();
        println!(
            "  a+b-a == b (additive inverse): {}",
            if removal_works {
                "✓ PASS"
            } else {
                "✗ FAIL"
            }
        );

        // Test: H(a) + H(b) == H(a+b) (homomorphic addition)
        let mut h_a = LtHash16_1024::new()?;
        let mut h_b = LtHash16_1024::new()?;
        let mut h_ab = LtHash16_1024::new()?;

        h_a.add_object(b"a")?;
        h_b.add_object(b"b")?;
        h_ab.add_object(b"a")?;
        h_ab.add_object(b"b")?;

        let h_sum = h_a + h_b;
        let homomorphic = h_sum.get_checksum() == h_ab.get_checksum();
        println!(
            "  H(a) + H(b) == H(a+b) (homomorphic): {}",
            if homomorphic { "✓ PASS" } else { "✗ FAIL" }
        );
    }

    Ok(())
}

fn hex_encode(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
}

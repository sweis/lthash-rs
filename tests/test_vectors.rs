/// Static test vectors for cross-compatibility testing with C++ implementation
///
/// These test vectors were generated from the C++ reference implementation
/// and ensure that the Rust implementation produces identical results.
#[cfg(feature = "folly-compat")]
pub mod blake2xb {
    #[derive(Debug, Clone)]
    pub struct TestVector {
        pub input: &'static [u8],
        pub key: &'static [u8],
        pub salt: &'static [u8],
        pub personalization: &'static [u8],
        pub output_length: usize,
        pub expected: &'static str, // hex encoded
    }

    // Input data: bytes 0-255
    const INPUT_0_TO_255: &[u8] = &[
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
        25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47,
        48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70,
        71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93,
        94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112,
        113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130,
        131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148,
        149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 165, 166,
        167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179, 180, 181, 182, 183, 184,
        185, 186, 187, 188, 189, 190, 191, 192, 193, 194, 195, 196, 197, 198, 199, 200, 201, 202,
        203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 213, 214, 215, 216, 217, 218, 219, 220,
        221, 222, 223, 224, 225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238,
        239, 240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254, 255,
    ];

    // Key data: bytes 0-63
    const KEY_0_TO_63: &[u8] = &[
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
        25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47,
        48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63,
    ];

    /// Blake2xb test vectors (non-keyed)
    pub const NON_KEYED_VECTORS: &[TestVector] = &[
        TestVector {
            input: INPUT_0_TO_255,
            key: &[],
            salt: &[],
            personalization: &[],
            output_length: 1,
            expected: "f0",
        },
        TestVector {
            input: INPUT_0_TO_255,
            key: &[],
            salt: &[],
            personalization: &[],
            output_length: 2,
            expected: "b5aa",
        },
        TestVector {
            input: INPUT_0_TO_255,
            key: &[],
            salt: &[],
            personalization: &[],
            output_length: 3,
            expected: "bc38f1",
        },
        TestVector {
            input: INPUT_0_TO_255,
            key: &[],
            salt: &[],
            personalization: &[],
            output_length: 4,
            expected: "57624fb2",
        },
        TestVector {
            input: INPUT_0_TO_255,
            key: &[],
            salt: &[],
            personalization: &[],
            output_length: 5,
            expected: "ea9d54f5f2",
        },
        TestVector {
            input: INPUT_0_TO_255,
            key: &[],
            salt: &[],
            personalization: &[],
            output_length: 6,
            expected: "2bcb84c09d35",
        },
        TestVector {
            input: INPUT_0_TO_255,
            key: &[],
            salt: &[],
            personalization: &[],
            output_length: 7,
            expected: "2df3b0c53f2967",
        },
        TestVector {
            input: INPUT_0_TO_255,
            key: &[],
            salt: &[],
            personalization: &[],
            output_length: 8,
            expected: "26de76fed412b6f1",
        },
    ];

    /// Blake2xb test vectors (keyed with key = 0..63)
    #[allow(dead_code)]
    pub const KEYED_VECTORS: &[TestVector] = &[
        TestVector {
            input: INPUT_0_TO_255,
            key: KEY_0_TO_63,
            salt: &[],
            personalization: &[],
            output_length: 1,
            expected: "64",
        },
        TestVector {
            input: INPUT_0_TO_255,
            key: KEY_0_TO_63,
            salt: &[],
            personalization: &[],
            output_length: 2,
            expected: "f457",
        },
        TestVector {
            input: INPUT_0_TO_255,
            key: KEY_0_TO_63,
            salt: &[],
            personalization: &[],
            output_length: 3,
            expected: "e8c045",
        },
        TestVector {
            input: INPUT_0_TO_255,
            key: KEY_0_TO_63,
            salt: &[],
            personalization: &[],
            output_length: 4,
            expected: "a74c6d0d",
        },
        TestVector {
            input: INPUT_0_TO_255,
            key: KEY_0_TO_63,
            salt: &[],
            personalization: &[],
            output_length: 5,
            expected: "eb02ae482a",
        },
        TestVector {
            input: INPUT_0_TO_255,
            key: KEY_0_TO_63,
            salt: &[],
            personalization: &[],
            output_length: 8,
            expected: "074a02fa58d7c7c0",
        },
    ];
}

/// Blake2xb-based LtHash test vectors (for Folly compatibility testing)
#[cfg(feature = "folly-compat")]
pub mod lthash {
    #[derive(Debug, Clone)]
    pub struct TestVector {
        pub name: &'static str,
        pub input: &'static [u8],
        pub expected_first_16_bytes: &'static str, // hex encoded first 16 bytes
    }

    /// LtHash<16, 1024> test vectors
    pub const LTHASH_16_1024_VECTORS: &[TestVector] = &[
        TestVector {
            name: "empty",
            input: &[],
            expected_first_16_bytes: "00000000000000000000000000000000",
        },
        TestVector {
            name: "a",
            input: b"a",
            expected_first_16_bytes: "843dfc8ceced3235bb359d013a9b8f15",
        },
        TestVector {
            name: "b",
            input: b"b",
            expected_first_16_bytes: "b08c6772d2f7f997556c13002b7463bf",
        },
        TestVector {
            name: "test",
            input: b"test",
            expected_first_16_bytes: "d7cdb1156beed0c3573bba589276348c",
        },
        TestVector {
            name: "hello",
            input: b"hello",
            expected_first_16_bytes: "b1feb2d47df7e7b5e1c271dbf2bfa46b",
        },
    ];

    /// LtHash<20, 1008> test vectors
    #[allow(dead_code)]
    pub const LTHASH_20_1008_VECTORS: &[TestVector] = &[
        TestVector {
            name: "empty",
            input: &[],
            expected_first_16_bytes: "00000000000000000000000000000000",
        },
        TestVector {
            name: "a",
            input: b"a",
            expected_first_16_bytes: "28dc6494399021174dbe4cbd92491230",
        },
        TestVector {
            name: "test",
            input: b"test",
            expected_first_16_bytes: "0a4f0e77add5863d0387a05ade0d1b08",
        },
        TestVector {
            name: "hello",
            input: b"hello",
            expected_first_16_bytes: "86ea837d081d342751f0e2a00f80c01d",
        },
    ];

    /// LtHash<32, 1024> test vectors
    #[allow(dead_code)]
    pub const LTHASH_32_1024_VECTORS: &[TestVector] = &[
        TestVector {
            name: "empty",
            input: &[],
            expected_first_16_bytes: "00000000000000000000000000000000",
        },
        TestVector {
            name: "a",
            input: b"a",
            expected_first_16_bytes: "e18df90bf54f96bb39fdbca7c28c5ae8",
        },
        TestVector {
            name: "test",
            input: b"test",
            expected_first_16_bytes: "f84f099e684bd991e5c406132e85052d",
        },
        TestVector {
            name: "hello",
            input: b"hello",
            expected_first_16_bytes: "87334307d11340b436869288da353929",
        },
    ];
}

/// Solana/Agave interoperability test vectors
///
/// These vectors verify compatibility with Solana's lattice-hash implementation which also
/// uses BLAKE3. The internal u16 state representation is verified to match Solana's.
/// Source: https://github.com/anza-xyz/agave/blob/master/lattice-hash/src/lt_hash.rs
///
/// Note: The first 32 bytes (16 u16 values) of the internal state have been verified to match
/// Solana's implementation exactly. This ensures homomorphic operations are compatible.
pub mod solana_interop {
    #[derive(Debug, Clone)]
    pub struct SolanaTestVector {
        pub name: &'static str,
        pub input: &'static [u8],
        /// First 16 u16 values of the LtHash state (little-endian in memory)
        /// These are verified to match Solana's lattice-hash output exactly.
        pub expected_first_u16s: [u16; 16],
    }

    pub const VECTORS: &[SolanaTestVector] = &[
        SolanaTestVector {
            name: "hello",
            input: b"hello",
            // Verified against Solana's lattice-hash test vectors
            expected_first_u16s: [
                0x8fea, 0x3d16, 0x86b3, 0x9282, 0x445e, 0xc591, 0x8de5, 0xb34b, 0x6e50, 0xc1f8,
                0xb74e, 0x868a, 0x08e9, 0x62c5, 0x674a, 0x0f20,
            ],
        },
        SolanaTestVector {
            name: "world!",
            input: b"world!",
            // Verified against Solana's lattice-hash test vectors
            expected_first_u16s: [
                0x56dc, 0x1d98, 0x5420, 0x810d, 0x936f, 0x1011, 0xa2ff, 0x6681, 0x637e, 0x9f2c,
                0x0024, 0xebd4, 0xe5f2, 0x3382, 0xd48b, 0x209e,
            ],
        },
    ];
}

/// BLAKE3-based LtHash test vectors (default backend)
///
/// These vectors are used to detect regressions when using the BLAKE3 backend.
/// Note: BLAKE3 produces different output than Blake2xb/Folly.
pub mod blake3_lthash {
    #[derive(Debug, Clone)]
    pub struct TestVector {
        pub name: &'static str,
        pub input: &'static [u8],
        pub expected_first_16_bytes: &'static str, // hex encoded first 16 bytes
    }

    /// BLAKE3-based LtHash<16, 1024> test vectors
    pub const LTHASH_16_1024_VECTORS: &[TestVector] = &[
        TestVector {
            name: "empty",
            input: b"",
            expected_first_16_bytes: "00000000000000000000000000000000",
        },
        TestVector {
            name: "a",
            input: b"a",
            expected_first_16_bytes: "17762fddd969a453925d65717ac3eea2",
        },
        TestVector {
            name: "b",
            input: b"b",
            expected_first_16_bytes: "10e5cf3d3c8a4f9f3468c8cc58eea848",
        },
        TestVector {
            name: "test",
            input: b"test",
            expected_first_16_bytes: "4878ca0425c739fa427f7eda20fe845f",
        },
        TestVector {
            name: "hello",
            input: b"hello",
            expected_first_16_bytes: "ea8f163db38682925e4491c5e58d4bb3",
        },
        TestVector {
            name: "hello_world",
            input: b"hello world",
            expected_first_16_bytes: "d74981efa70a0c880b8d8c1985d075db",
        },
    ];

    /// BLAKE3-based LtHash<20, 1008> test vectors
    pub const LTHASH_20_1008_VECTORS: &[TestVector] = &[
        TestVector {
            name: "empty",
            input: b"",
            expected_first_16_bytes: "00000000000000000000000000000000",
        },
        TestVector {
            name: "a",
            input: b"a",
            expected_first_16_bytes: "17762fddd969a413925d65717ac1ee22",
        },
        TestVector {
            name: "b",
            input: b"b",
            expected_first_16_bytes: "10e5cf3d3c884f1f3468c8cc58eca808",
        },
        TestVector {
            name: "test",
            input: b"test",
            expected_first_16_bytes: "4878ca0425c5393a427f6eda20fc841f",
        },
        TestVector {
            name: "hello",
            input: b"hello",
            expected_first_16_bytes: "ea8f063db38482125e4481c5e58d4b33",
        },
        TestVector {
            name: "hello_world",
            input: b"hello world",
            expected_first_16_bytes: "d74981efa7080c080b8d8c1985d0751b",
        },
    ];

    /// BLAKE3-based LtHash<32, 1024> test vectors
    pub const LTHASH_32_1024_VECTORS: &[TestVector] = &[
        TestVector {
            name: "empty",
            input: b"",
            expected_first_16_bytes: "00000000000000000000000000000000",
        },
        TestVector {
            name: "a",
            input: b"a",
            expected_first_16_bytes: "17762fddd969a453925d65717ac3eea2",
        },
        TestVector {
            name: "b",
            input: b"b",
            expected_first_16_bytes: "10e5cf3d3c8a4f9f3468c8cc58eea848",
        },
        TestVector {
            name: "test",
            input: b"test",
            expected_first_16_bytes: "4878ca0425c739fa427f7eda20fe845f",
        },
        TestVector {
            name: "hello",
            input: b"hello",
            expected_first_16_bytes: "ea8f163db38682925e4491c5e58d4bb3",
        },
        TestVector {
            name: "hello_world",
            input: b"hello world",
            expected_first_16_bytes: "d74981efa70a0c880b8d8c1985d075db",
        },
    ];
}

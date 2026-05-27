module halo2_common::bn254_serialize {
    use std::vector;

    // BN254 scalar field modulus
    const BN254_MODULUS: u256 = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

    /// The scalar field element zero serialized as 32 zero bytes (little-endian).
    public fun zero(): vector<u8> {
        vector[
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]
    }

    /// The scalar field element one serialized as a 32-byte little-endian value.
    public fun one(): vector<u8> {
        vector[
            1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]
    }

    /// Serializes a u128 value as a 32-byte little-endian BN254 scalar field element.
    /// The low 16 bytes are the little-endian encoding of the value;
    /// the high 16 bytes are zero-padded.
    /// Since u128::MAX (2^128 - 1) < BN254_MODULUS, all u128 values are valid canonical field elements.
    public fun u128_to_bn254_le_bytes(value: u128): vector<u8> {
        let bytes = std::bcs::to_bytes(&value); // u128 -> 16 bytes LE
        // Pad to 32 bytes: append 16 zero bytes for the high half
        let result = vector::empty<u8>();
        vector::append(&mut result, bytes);
        vector::append(&mut result, vector[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        result
    }

    /// Serializes a u256 value as a 32-byte little-endian BN254 scalar field element.
    /// The value is reduced modulo the field modulus before serialization,
    /// ensuring the output is always a canonical field element.
    public fun u256_to_bn254_le_bytes(value: u256): vector<u8> {
        let reduced = value % BN254_MODULUS;
        std::bcs::to_bytes(&reduced) // BCS encoding of u256 is already 32-byte little-endian
    }
}

#[test_only]
module halo2_common::bn254_serialize_tests {
    use aptos_std::crypto_algebra;
    use aptos_std::bn254_algebra::Fr;
    use halo2_common::bn254_utils::{fr_from_u128, serialize_fr, deserialize_fr};
    use halo2_common::bn254_serialize;
    use std::option;

    /// Returns the canonical serialization of a u128 as an Fr element,
    /// used as ground truth to verify bn254_serialize outputs.
    fun fr_bytes_from_u128(v: u128): vector<u8> {
        serialize_fr(&fr_from_u128(v))
    }

    #[test]
    fun test_zero_matches_crypto_algebra() {
        let expected = serialize_fr(&crypto_algebra::zero<Fr>());
        assert!(bn254_serialize::zero() == expected, 0);
    }

    #[test]
    fun test_one_matches_crypto_algebra() {
        let expected = serialize_fr(&crypto_algebra::one<Fr>());
        assert!(bn254_serialize::one() == expected, 1);
    }

    #[test]
    fun test_u128_zero() {
        assert!(bn254_serialize::u128_to_bn254_le_bytes(0) == fr_bytes_from_u128(0), 2);
    }

    #[test]
    fun test_u128_one() {
        assert!(bn254_serialize::u128_to_bn254_le_bytes(1) == fr_bytes_from_u128(1), 3);
    }

    #[test]
    fun test_u128_small_values() {
        assert!(bn254_serialize::u128_to_bn254_le_bytes(255)       == fr_bytes_from_u128(255),       4);
        assert!(bn254_serialize::u128_to_bn254_le_bytes(65536)     == fr_bytes_from_u128(65536),     5);
        assert!(bn254_serialize::u128_to_bn254_le_bytes(123456789) == fr_bytes_from_u128(123456789), 6);
    }

    #[test]
    fun test_u128_max() {
        let max = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFu128;
        assert!(bn254_serialize::u128_to_bn254_le_bytes(max) == fr_bytes_from_u128(max), 7);
    }

    #[test]
    fun test_u128_result_is_deserializable() {
        let bytes = bn254_serialize::u128_to_bn254_le_bytes(0xDEADBEEFCAFEBABEu128);
        // Must round-trip through the field without error
        assert!(option::is_some(&deserialize_fr(&bytes)), 8);
    }

    #[test]
    fun test_u256_zero() {
        let bytes = bn254_serialize::u256_to_bn254_le_bytes(0u256);
        assert!(bytes == bn254_serialize::zero(), 9);
    }

    #[test]
    fun test_u256_one() {
        let bytes = bn254_serialize::u256_to_bn254_le_bytes(1u256);
        assert!(bytes == bn254_serialize::one(), 10);
    }

    #[test]
    fun test_u256_small_value() {
        let bytes = bn254_serialize::u256_to_bn254_le_bytes(123456789u256);
        assert!(bytes == fr_bytes_from_u128(123456789), 11);
    }

    #[test]
    fun test_u256_reduction() {
        // BN254_MODULUS mod MODULUS = 0, so the result should be the zero element
        let modulus: u256 = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
        let bytes = bn254_serialize::u256_to_bn254_le_bytes(modulus);
        assert!(bytes == bn254_serialize::zero(), 12);
    }

    #[test]
    fun test_u256_modulus_plus_one() {
        // MODULUS + 1 ≡ 1 (mod MODULUS)
        let modulus: u256 = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
        let bytes = bn254_serialize::u256_to_bn254_le_bytes(modulus + 1);
        assert!(bytes == bn254_serialize::one(), 13);
    }

    #[test]
    fun test_u256_result_is_deserializable() {
        let bytes = bn254_serialize::u256_to_bn254_le_bytes(0xABCDEF1234567890u256);
        assert!(option::is_some(&deserialize_fr(&bytes)), 14);
    }

    #[test]
    fun test_u256_matches_crypto_algebra_add() {
        // Verify: serialize(a) + serialize(b) == serialize((a + b) mod p) via field arithmetic
        let a: u128 = 0xFFFFFFFFFFFFFFFF;
        let b: u128 = 0xFFFFFFFFFFFFFFFF;
        let fa = option::destroy_some(deserialize_fr(&bn254_serialize::u128_to_bn254_le_bytes(a)));
        let fb = option::destroy_some(deserialize_fr(&bn254_serialize::u128_to_bn254_le_bytes(b)));
        let sum = crypto_algebra::add<Fr>(&fa, &fb);
        let expected = bn254_serialize::u256_to_bn254_le_bytes((a as u256) + (b as u256));
        assert!(serialize_fr(&sum) == expected, 15);
    }
}

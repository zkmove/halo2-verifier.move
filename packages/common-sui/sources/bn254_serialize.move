// Copyright (c) zkMove Authors

module halo2_common::bn254_serialize {
    use sui::bcs;

    const BN254_MODULUS: u256 = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

    /// Returns the BN254 scalar field zero encoded as 32 little-endian bytes.
    public fun zero(): vector<u8> {
        vector[
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]
    }

    /// Returns the BN254 scalar field one encoded as 32 little-endian bytes.
    public fun one(): vector<u8> {
        vector[
            1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]
    }

    /// Serializes a `u128` as a canonical 32-byte little-endian BN254 scalar.
    ///
    /// Every `u128` is strictly smaller than the BN254 scalar field modulus, so
    /// no reduction is needed. The high 16 bytes are zero-padded.
    public fun u128_to_bn254_le_bytes(value: u128): vector<u8> {
        let mut result = bcs::to_bytes(&value);
        vector::append(&mut result, vector[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        result
    }

    /// Serializes a `u256` as a canonical 32-byte little-endian BN254 scalar.
    ///
    /// The input is reduced modulo the BN254 scalar field modulus before
    /// serialization.
    public fun u256_to_bn254_le_bytes(value: u256): vector<u8> {
        let reduced = value % BN254_MODULUS;
        bcs::to_bytes(&reduced)
    }
}

// Copyright (c) zkMove Authors

#[allow(implicit_const_copy)]
module halo2_common::bn254_utils {
    use std::option::{Self, Option};
    use std::vector;
    use sui::bn254;
    use sui::group_ops::{Self, Element};
    use halo2_common::bn254_serialize;

    const S_OF_FR: u8 = 28;
    const MODULUS: u256 = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

    /// `R^2 = 2^512 mod r` for the BN254 scalar field.
    const MONTGOMERY_R2: vector<u8> = x"fbffff4f1c3496ac29cd609f9576fc362e4679786fa36e662fdf079ac1770a0e";
    /// `R^3 = 2^768 mod r` for the BN254 scalar field.
    const MONTGOMERY_R3: vector<u8> = x"a76d21ae45e6b81be3595ce3b13afe538580bb533d83498ca5444e7fb1d01602";

    /// `GENERATOR^t`, where `t * 2^s + 1 = r` and `t` is odd.
    const ROOT_OF_UNITY_OF_FR: vector<u8> = x"9c7cc360d91e4fd3c82993d36dcf1532741fd33da95e8698b7186d16f5b9dd03";
    /// `GENERATOR^{2^s}`, where `t * 2^s + 1 = r` and `t` is odd.
    const DELTA_OF_FR: vector<u8> = x"a2e933e5bb560e87253f965e8e895f5b716ec8d4aa26ec64caf0c6226e6b2209";

    /// Returns the scalar field zero encoded as 32 little-endian bytes.
    public fun scalar_zero_bytes(): vector<u8> {
        bn254_serialize::zero()
    }

    /// Returns the scalar field one encoded as 32 little-endian bytes.
    public fun scalar_one_bytes(): vector<u8> {
        bn254_serialize::one()
    }

    /// Returns the `2^k`-th root of unity in the BN254 scalar field.
    public fun root_of_unity(k: u8): Element<bn254::Scalar> {
        let times = S_OF_FR - k;
        let mut i = 0;
        let mut result = bn254::scalar_from_bytes(&ROOT_OF_UNITY_OF_FR);
        while (i < times) {
            result = bn254::scalar_mul(&result, &result);
            i = i + 1;
        };
        result
    }

    /// Returns `GENERATOR^{2^s}` in the BN254 scalar field.
    public fun delta_of_fr(): Element<bn254::Scalar> {
        bn254::scalar_from_bytes(&DELTA_OF_FR)
    }

    /// Raises a BN254 scalar to a `u32` exponent.
    public fun pow_u32(e: &Element<bn254::Scalar>, num: u32): Element<bn254::Scalar> {
        let mut result = bn254::scalar_one();
        let mut i = 32u8;
        let mut meet_one = false;
        loop {
            i = i - 1;
            if (meet_one) {
                result = bn254::scalar_mul(&result, &result);
            };
            if (((num >> i) & 1) == 1) {
                result = bn254::scalar_mul(&result, e);
                meet_one = true;
            };

            if (i == 0) {
                return result
            }
        }
    }

    /// Creates a BN254 scalar from a 512-bit little-endian integer.
    public fun fr_from_u512_le(bytes_lo: &vector<u8>, bytes_hi: &vector<u8>): Element<bn254::Scalar> {
        assert!(vector::length(bytes_lo) == 32, 100);
        assert!(vector::length(bytes_hi) == 32, 100);

        let lo = bn254::scalar_from_bytes(&mod_r(bytes_lo));
        let hi = bn254::scalar_from_bytes(&mod_r(bytes_hi));
        let r3 = bn254::scalar_from_bytes(&MONTGOMERY_R3);
        let r2 = bn254::scalar_from_bytes(&MONTGOMERY_R2);

        let hi = bn254::scalar_div(&r2, &bn254::scalar_mul(&hi, &r3));
        bn254::scalar_add(&lo, &hi)
    }

    /// Creates a BN254 scalar from a `u128` value.
    public fun fr_from_u128(v: u128): Element<bn254::Scalar> {
        let bytes_lo = vector<u8>[
            ((v >> 0) & 0xFF as u8),
            ((v >> 8) & 0xFF as u8),
            ((v >> 16) & 0xFF as u8),
            ((v >> 24) & 0xFF as u8),
            ((v >> 32) & 0xFF as u8),
            ((v >> 40) & 0xFF as u8),
            ((v >> 48) & 0xFF as u8),
            ((v >> 56) & 0xFF as u8),
            ((v >> 64) & 0xFF as u8),
            ((v >> 72) & 0xFF as u8),
            ((v >> 80) & 0xFF as u8),
            ((v >> 88) & 0xFF as u8),
            ((v >> 96) & 0xFF as u8),
            ((v >> 104) & 0xFF as u8),
            ((v >> 112) & 0xFF as u8),
            ((v >> 120) & 0xFF as u8),
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];

        bn254::scalar_from_bytes(&bytes_lo)
    }

    /// Returns the multiplicative inverse of a non-zero BN254 scalar.
    public fun invert(x: &Element<bn254::Scalar>): Element<bn254::Scalar> {
        bn254::scalar_inv(x)
    }

    /// Serializes a BN254 scalar as 32 little-endian bytes.
    public fun serialize_fr(e: &Element<bn254::Scalar>): vector<u8> {
        *group_ops::bytes(e)
    }

    /// Deserializes a canonical 32-byte little-endian BN254 scalar.
    public fun deserialize_fr(e: &vector<u8>): Option<Element<bn254::Scalar>> {
        if (!is_canonical_scalar_bytes(e)) {
            return option::none()
        };
        option::some(bn254::scalar_from_bytes(e))
    }

    /// Serializes a BN254 G1 point in compressed form.
    public fun serialize_g1(e: &Element<bn254::G1>): vector<u8> {
        *group_ops::bytes(e)
    }

    /// Serializes a BN254 G1 point in uncompressed form.
    public fun serialize_g1_uncompressed(e: &Element<bn254::G1>): vector<u8> {
        let uncompressed = bn254::g1_to_uncompressed_g1(e);
        *group_ops::bytes(&uncompressed)
    }

    /// Deserializes a 32-byte compressed BN254 G1 point.
    public fun deserialize_g1(e: &vector<u8>): Option<Element<bn254::G1>> {
        if (vector::length(e) != 32) {
            return option::none()
        };
        option::some(bn254::g1_from_bytes(e))
    }

    /// Serializes a BN254 G2 point in compressed form.
    public fun serialize_g2(e: &Element<bn254::G2>): vector<u8> {
        *group_ops::bytes(e)
    }

    /// Deserializes a 64-byte compressed BN254 G2 point.
    public fun deserialize_g2(e: &vector<u8>): Option<Element<bn254::G2>> {
        if (vector::length(e) != 64) {
            return option::none()
        };
        option::some(bn254::g2_from_bytes(e))
    }

    /// Returns true if two vectors contain the same group elements in the same order.
    public fun eq_elements<T>(e: &vector<Element<T>>, other: &vector<Element<T>>): bool {
        let elements_len = vector::length(e);
        if (elements_len != vector::length(other)) {
            return false
        };

        let mut i = 0;
        while (i < elements_len) {
            let e_1 = vector::borrow(e, i);
            let e_2 = vector::borrow(other, i);
            if (!group_ops::equal<T>(e_1, e_2)) {
                return false
            };
            i = i + 1;
        };

        true
    }

    fun mod_r(u256_bytes: &vector<u8>): vector<u8> {
        bn254_serialize::u256_to_bn254_le_bytes(u256_from_32_le_bytes(u256_bytes))
    }

    fun is_canonical_scalar_bytes(bytes: &vector<u8>): bool {
        vector::length(bytes) == 32 && u256_from_32_le_bytes(bytes) < MODULUS
    }

    fun u256_from_32_le_bytes(bytes: &vector<u8>): u256 {
        assert!(vector::length(bytes) == 32, 100);

        let mut value = 0u256;
        let mut i = 0u8;
        while (i < 32) {
            value = value + ((*vector::borrow(bytes, (i as u64)) as u256) << (i * 8));
            i = i + 1;
        };
        value
    }
}

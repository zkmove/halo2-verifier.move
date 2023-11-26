/// This module defines marker types and constants for working with BN254 curves
/// using the aptos API defined in `crypto_algebra.move`.

module halo2_verifier::bn254_types {

    use std::option::Option;
    use aptos_std::crypto_algebra::{Self, Element};

    struct Fr {}

    /// A serialization format for `Fr` elements,
    /// where an element is represented by a byte array `b[]` of size 32 with the least significant byte (LSB) coming first.
    struct FormatFrLsb {}

    struct G1 has copy, drop {}

    /// A serialization scheme for `G1` elements
    /// the serialization procedure takes a `G1` element `p` and outputs a byte array of size 32.
    /// the deserialization procedure takes a byte array `b[]` and outputs either a `G1` element or none.
    struct FormatG1Compr {}

    struct G2 {}

    struct Gt {}

    const FR_S: u32 = 28;

    public fun S_FR(): u32 {
        FR_S
    }
    fun ROOT_OF_UNITY_FR(): Element<Fr> {
        abort 100
    }

    public fun root_of_unity(k: u32): Element<Fr> {
        let times = FR_S - k;
        let i = 0;
        let result = ROOT_OF_UNITY_FR();
        while (i < times) {
            result = crypto_algebra::sqr(&result);
        };
        result
    }

    // TODO: fix the format, once we got aptos part done.
    public fun serialize_fr(e: &Element<Fr>): vector<u8>{
        // FIXME: update the format
        crypto_algebra::serialize<Fr, FormatFrLsb>(e)
    }
    public fun deserialize_fr(e: &vector<u8>): Option<Element<Fr>>{
        // FIXME: update the format
        crypto_algebra::deserialize<Fr, FormatFrLsb>(e)
    }

    public fun serialize_g1(e: &Element<G1>): vector<u8>{
        // FIXME: update the format
        crypto_algebra::serialize<G1, FormatFrLsb>(e)
    }
    public fun deserialize_g1(e: &vector<u8>): Option<Element<G1>>{
        // FIXME: update the format
        crypto_algebra::deserialize<G1, FormatFrLsb>(e)
    }
    public fun serialize_g2(e: &Element<G2>): vector<u8>{
        // FIXME: update the format
        crypto_algebra::serialize<G2, FormatFrLsb>(e)
    }
    public fun deserialize_g2(e: &vector<u8>): Option<Element<G2>>{
        // FIXME: update the format
        crypto_algebra::deserialize<G2, FormatFrLsb>(e)
    }
}

/// This module defines marker types and constants for working with BN254 curves
/// using the aptos API defined in `crypto_algebra.move`.

module halo2_verifier::bn254_types {

    use aptos_std::crypto_algebra::Element;
    use aptos_std::crypto_algebra;

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
}

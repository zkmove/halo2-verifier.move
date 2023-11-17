/// This module defines marker types and constants for working with BN254 curves
/// using the aptos API defined in `crypto_algebra.move`.

module halo2_verifier::bn254_types {

    struct Fr {}

    /// A serialization format for `Fr` elements,
    /// where an element is represented by a byte array `b[]` of size 32 with the least significant byte (LSB) coming first.
    struct FormatFrLsb {}

    struct G1 {}

    struct G2 {}

    struct Gt {}
}

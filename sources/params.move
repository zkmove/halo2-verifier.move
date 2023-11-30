module halo2_verifier::params {
    use aptos_std::crypto_algebra::Element;
    use halo2_verifier::bn254_types::{G1, G2};
    use halo2_verifier::bn254_types;
    use std::option;

    /// params in stored form.
    /// because element cannot be stored, we have to serialize the elements to bytes to store them.
    struct StoredParams has key, store {
        g1: vector<u8>,
        g2: vector<u8>,
        s_g2: vector<u8>,
    }
    struct Params has copy, drop {
        g1: Element<G1>,
        g2: Element<G2>,
        s_g2: Element<G2>,
    }

    public fun from_stored(params: &StoredParams): Params {
        Params {
            g1: option::destroy_some(bn254_types::deserialize_g1(&params.g1)),
            g2: option::destroy_some(bn254_types::deserialize_g2(&params.g2)),
            s_g2: option::destroy_some(bn254_types::deserialize_g2(&params.s_g2)),
        }
    }

    /// [1]@g1
    public fun g(params: &Params): &Element<G1> {
        &params.g1
    }

    /// [1]@g2
    public fun g2(params: &Params): &Element<G2> {
        &params.g2
    }
    /// [s]@g2
    public fun s_g2(params: &Params): &Element<G2> {
        &params.s_g2
    }
}
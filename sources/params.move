module halo2_verifier::params {
    use aptos_std::crypto_algebra::Element;
    use halo2_verifier::bn254_types::{G1, G2};

    struct Params {}

    public fun k(_params: &Params): u32 {
        abort 100
    }

    public fun n(_params: &Params): u64 {
        abort 100
    }

    /// [1]@g1
    public fun g(_params: &Params): &Element<G1> {
        abort 100
    }

    /// [1]@g2
    public fun g2(_params: &Params): &Element<G2> {
        abort 100
    }
    /// [s]@g2
    public fun s_g2(_params: &Params): &Element<G2> {
        abort 100
    }
}
module halo2_verifier::params {
    use aptos_std::crypto_algebra::Element;
    use aptos_std::bn254_algebra::{G1, G2};
    struct Params has copy, drop {
        g1: Element<G1>,
        g2: Element<G2>,
        s_g2: Element<G2>,
    }

    public fun new(g1: Element<G1>, g2: Element<G2>, s_g2: Element<G2>): Params {
        Params {
            g1,g2,s_g2
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
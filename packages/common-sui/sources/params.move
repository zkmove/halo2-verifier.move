// Copyright (c) zkMove Authors

module halo2_common::params {
    use sui::bn254;
    use sui::group_ops::Element;

    public struct Params has copy, drop {
        g1: Element<bn254::G1>,
        g2: Element<bn254::G2>,
        s_g2: Element<bn254::G2>,
    }

    public fun new(
        g1: Element<bn254::G1>,
        g2: Element<bn254::G2>,
        s_g2: Element<bn254::G2>,
    ): Params {
        Params { g1, g2, s_g2 }
    }

    /// Returns `[1]@G1`.
    public fun g(params: &Params): &Element<bn254::G1> {
        &params.g1
    }

    /// Returns `[1]@G2`.
    public fun g2(params: &Params): &Element<bn254::G2> {
        &params.g2
    }

    /// Returns `[s]@G2`.
    public fun s_g2(params: &Params): &Element<bn254::G2> {
        &params.s_g2
    }
}

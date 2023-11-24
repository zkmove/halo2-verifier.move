module halo2_verifier::params {
    use halo2_verifier::scalar::Scalar;
    use halo2_verifier::point::Point;
    use halo2_verifier::bn254_types::{G1, G2};

    struct Params {}

    public fun k(params: &Params): u32 {
        abort 100
    }

    public fun n(params: &Params): u64 {
        abort 100
    }

    /// [1]@g1
    public fun g(self: &Params): &Point<G1> {
        abort 100
    }

    /// [1]@g2
    public fun g2(self: &Params): &Point<G2> {
        abort 100
    }
    /// [s]@g2
    public fun s_g2(self: &Params): &Point<G2> {
        abort 100
    }
}
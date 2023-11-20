module halo2_verifier::msm {
    use halo2_verifier::bn254_types::G1;
    use halo2_verifier::point::Point;
    use halo2_verifier::scalar::Scalar;

    struct MSM has copy, drop {}

    public fun empty_msm(): MSM {
        abort 100
    }

    public fun scale(msm: &mut MSM, factor: &Scalar) {
        abort 100
    }

    public fun append_term(msm: &mut MSM, scalar: Scalar, point: Point<G1>) {
        abort 100
    }

    public fun add_msm(msm: &mut MSM, other: &MSM) {
        abort 100
    }
}

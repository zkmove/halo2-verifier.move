module halo2_verifier::msm {
    use halo2_verifier::scalar::Scalar;
    use halo2_verifier::point::Point;

    struct MSM {

    }

    public fun empty_msm(): MSM {
        abort 100
    }
    public fun scale(msm: &mut MSM, factor: &Scalar) {
        abort 100
    }
    public fun append_term(msm: &mut MSM, scalar: Scalar, point: Point) {
        abort 100
    }
    public fun add_msm(msm: &mut MSM, other: &MSM) {
        abort 100
    }
}
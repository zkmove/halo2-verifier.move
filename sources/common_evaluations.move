module halo2_verifier::common_evaluations {
    use halo2_verifier::scalar::Scalar;

    struct CommonEvaluations has copy,drop {

    }

    public fun new(k: u32, x: Scalar): CommonEvaluations {
        abort 100
    }

    public fun xn(commons: &CommonEvaluations): Scalar {
        abort 100
    }
    public fun l_evals(commons: &CommonEvaluations): vector<Scalar> {
        abort 100
    }

    public fun l_last(commons: &CommonEvaluations): Scalar {
        abort 100
    }
    public fun l_blind(commons: &CommonEvaluations): Scalar {
        abort 100
    }
    public fun l_0(commons: &CommonEvaluations): Scalar {
        abort 100
    }
}

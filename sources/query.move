module halo2_verifier::query {

    use halo2_verifier::bn254_types::G1;
    use halo2_verifier::msm::MSM;
    use halo2_verifier::point::Point;
    use halo2_verifier::scalar::Scalar;

    struct VerifierQuery has drop {
        point: Scalar,
        eval: Scalar,
        commitment: CommitmentReference
    }

    struct CommitmentReference has drop {}

    public fun new_commitment(commtiment: Point<G1>, point: Scalar, eval: Scalar): VerifierQuery {
        abort 100
    }

    public fun new_msm(msm: MSM, point: Scalar, eval: Scalar): VerifierQuery {
        abort 100
    }
}

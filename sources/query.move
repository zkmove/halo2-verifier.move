module halo2_verifier::query {

    use halo2_verifier::scalar::Scalar;
    use halo2_verifier::point::G1Affine;
    use halo2_verifier::msm::MSM;

    struct VerifierQuery has drop {
        point: Scalar,
        eval: Scalar,
        commitment: CommitmentReference
    }
    struct CommitmentReference has drop {}
    public fun new_commitment(commtiment: G1Affine,point: Scalar, eval: Scalar): VerifierQuery {
        abort 100
    }

    public fun new_msm(msm: MSM, point: Scalar, eval: Scalar): VerifierQuery {
        abort 100
    }

}

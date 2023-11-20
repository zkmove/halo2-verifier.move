module halo2_verifier::verify_key {
    use halo2_verifier::bn254_types::G1;
    use halo2_verifier::point::Point;
    use halo2_verifier::scalar::Scalar;

    struct VerifyingKey {
        k: u32,
        fixed_commitments: vector<Point<G1>>,
        permutation_commitments: vector<Point<G1>>,
        selectors: vector<vector<bool>>,
    }

    public fun fixed_commitments(self: &VerifyingKey): &vector<Point<G1>> {
        &self.fixed_commitments
    }

    public fun permutation_commitments(self: &VerifyingKey): &vector<Point<G1>> {
        &self.permutation_commitments
    }
    public fun transcript_repr(self: &VerifyingKey): Scalar {
        abort 100
    }
}

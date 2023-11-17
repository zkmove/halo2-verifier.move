module halo2_verifier::verify_key {
    use halo2_verifier::point::G1Affine;

    struct VerifyingKey {
        k: u32,
        fixed_commitments: vector<G1Affine>,
        permutation_commitments: vector<G1Affine>,
        selectors: vector<vector<bool>>,
    }

    public fun fixed_commitments(self: &VerifyingKey): &vector<G1Affine> {
        &self.fixed_commitments
    }

    public fun permutation_commitments(self: &VerifyingKey): &vector<G1Affine> {
        &self.permutation_commitments
    }
}

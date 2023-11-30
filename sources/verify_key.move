module halo2_verifier::verify_key {
    use aptos_std::bn254_algebra::{G1, Fr};
    use aptos_std::crypto_algebra::Element;

    struct VerifyingKey {
        k: u32,
        fixed_commitments: vector<Element<G1>>,
        permutation_commitments: vector<Element<G1>>,
        selectors: vector<vector<bool>>,
    }

    public fun fixed_commitments(self: &VerifyingKey): &vector<Element<G1>> {
        &self.fixed_commitments
    }

    public fun permutation_commitments(self: &VerifyingKey): &vector<Element<G1>> {
        &self.permutation_commitments
    }

    public fun transcript_repr(_self: &VerifyingKey): Element<Fr> {
        abort 100
    }
}

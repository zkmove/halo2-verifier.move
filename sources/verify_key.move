module halo2_verifier::verify_key {
    use aptos_std::bn254_algebra::{G1, Fr};
    use aptos_std::crypto_algebra::Element;
    use std::option;
    use halo2_verifier::bn254_utils;

    struct VerifyingKey {
        fixed_commitments: vector<Element<G1>>,
        permutation_commitments: vector<Element<G1>>,
        selectors: vector<vector<bool>>,
        transcript_repr: vector<u8>,
    }

    public fun fixed_commitments(self: &VerifyingKey): &vector<Element<G1>> {
        &self.fixed_commitments
    }

    public fun permutation_commitments(self: &VerifyingKey): &vector<Element<G1>> {
        &self.permutation_commitments
    }

    public fun transcript_repr(_self: &VerifyingKey): Element<Fr> {
        option::destroy_some( bn254_utils::deserialize_fr(&_self.transcript_repr))
    }
}

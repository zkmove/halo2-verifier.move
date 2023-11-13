module halo2_verifier::verify_key {
    use halo2_verifier::point::Point;

    struct VerifyingKey {
        k: u32,
        fixed_commitments: vector<Point>,
        permutation_commitments: vector<Point>,
        selectors: vector<vector<bool>>,
    }
}

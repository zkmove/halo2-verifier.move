module halo2_verifier::permutation {
    use halo2_verifier::transcript::Transcript;
    use halo2_verifier::point::Point;
    use halo2_verifier::transcript;

    struct Commited has copy, drop {
        permutation_product_commitments: vector<Point>,
    }
    public fun read_product_commitments(transcript: &mut Transcript, num_permutation_z: u64): Commited {
        Commited {
            permutation_product_commitments:transcript::read_n_point(transcript, num_permutation_z)
        }
    }

    public fun permutation_product_commitments(c: &Commited): &vector<Point> {
        &c.permutation_product_commitments
    }
}

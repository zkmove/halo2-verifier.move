module halo2_verifier::vanishing {
    use halo2_verifier::transcript::Transcript;
    use halo2_verifier::transcript;
    use halo2_verifier::point::Point;

    struct Constructed has copy, drop {
        h_commitments: vector<Point>,
    }
    public fun h_commitments(c: &Constructed): &vector<Point> {
        &c.h_commitments
    }

    /// read commitments of H(x) which is (h_1,h_2,.., h_d)
    public fun read_commitments_after_y(transcript: &mut Transcript, quotient_poly_degree: u64): Constructed {
        Constructed {
            h_commitments: transcript::read_n_point(transcript, quotient_poly_degree)
        }
    }
}

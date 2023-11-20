module halo2_verifier::vanishing {
    use halo2_verifier::transcript::Transcript;
    use halo2_verifier::transcript;
    use halo2_verifier::point::Point;
    use halo2_verifier::bn254_types::G1;
    use halo2_verifier::scalar::Scalar;
    use halo2_verifier::msm::MSM;
    use halo2_verifier::query::VerifierQuery;
    use halo2_verifier::query;
    use std::vector;
    use halo2_verifier::scalar;
    use halo2_verifier::msm;

    struct Constructed has copy, drop {
        h_commitments: vector<Point<G1>>,
    }

    struct EvaluatedH has copy, drop {
        expected_h_eval: Scalar,
        h_commitment: MSM,
    }

    public fun h_commitments(c: &Constructed): &vector<Point<G1>> {
        &c.h_commitments
    }

    /// read commitments of H(x) which is (h_1,h_2,.., h_d)
    public fun read_commitments_after_y(transcript: &mut Transcript, quotient_poly_degree: u64): Constructed {
        Constructed {
            h_commitments: transcript::read_n_point(transcript, quotient_poly_degree)
        }
    }


    public fun h_eval(
        self: Constructed,
        expressions: &vector<Scalar>,
        y: &Scalar,
        xn: &Scalar
    ): EvaluatedH {
        let h_commitments = self.h_commitments;
        let i = 0;
        let len = vector::length(expressions);
        let h_eval = scalar::zero();
        while (i < len) {
            let v = vector::borrow(expressions, i);
            h_eval = scalar::add(&scalar::mul(&h_eval, y), v);
            i = i + 1;
        };
        h_eval = scalar::mul(&h_eval, &scalar::invert(&scalar::sub(xn, &scalar::one())));

        let msm = msm::empty_msm();
        let i = vector::length(&h_commitments);
        while (i > 0) {
            i = i - 1;
            // TODO: change to pop?
            let commitment = vector::borrow(&h_commitments, i);
            msm::scale(&mut msm, xn);
            msm::append_term(&mut msm, scalar::one(), *commitment);
        };
        EvaluatedH {
            expected_h_eval: h_eval,
            h_commitment: msm
        }
    }

    public fun queries(self: EvaluatedH, queries: &mut vector<VerifierQuery>, x: &Scalar) {
        vector::push_back(queries, query::new_msm(self.h_commitment, *x, self.expected_h_eval));
    }
}

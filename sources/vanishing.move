module halo2_verifier::vanishing {
    use std::vector;
    use aptos_std::crypto_algebra::{Self, Element};

    use halo2_verifier::bn254_arithmetic;
    use halo2_verifier::bn254_types::{G1, Fr};
    use halo2_verifier::msm::{Self, MSM};
    use halo2_verifier::query::{Self, VerifierQuery};
    use halo2_verifier::transcript::{Self, Transcript};

    struct Constructed has drop {
        random_poly_commitment: Element<G1>,
        h_commitments: vector<Element<G1>>,
    }

    struct PartialEvaluated has drop {
        random_poly_commitment: Element<G1>,
        h_commitments: vector<Element<G1>>,
        random_eval: Element<Fr>,
    }

    struct EvaluatedH has drop {
        expected_h_eval: Element<Fr>,
        random_eval: Element<Fr>,
        h_commitment: MSM,
        random_poly_commitment: Element<G1>,
    }

    public fun h_commitments(c: &Constructed): &vector<Element<G1>> {
        &c.h_commitments
    }

    public fun read_commitments_before_y(transcript: &mut Transcript): Constructed {
        Constructed {
            random_poly_commitment: transcript::read_point(transcript),
            h_commitments: vector::empty(),
        }
    }

    /// read commitments of H(x) which is (h_1,h_2,.., h_d)
    public fun read_commitments_after_y(
        self: Constructed,
        transcript: &mut Transcript,
        quotient_poly_degree: u64
    ): Constructed {
        Constructed {
            random_poly_commitment: self.random_poly_commitment,
            h_commitments: transcript::read_n_point(transcript, quotient_poly_degree)
        }
    }

    /// read random poly eval
    public fun evaluate_after_x(self: Constructed, transcript: &mut Transcript): PartialEvaluated {
        PartialEvaluated {
            h_commitments: self.h_commitments,
            random_poly_commitment: self.random_poly_commitment,
            random_eval: transcript::read_scalar(transcript),
        }
    }

    public fun h_eval(
        self: PartialEvaluated,
        expressions: &vector<Element<Fr>>,
        y: &Element<Fr>,
        xn: &Element<Fr>
    ): EvaluatedH {
        let PartialEvaluated { h_commitments, random_eval, random_poly_commitment } = self;
        let i = 0;
        let len = vector::length(expressions);
        let h_eval = crypto_algebra::zero();
        while (i < len) {
            let v = vector::borrow(expressions, i);
            h_eval = crypto_algebra::add(&crypto_algebra::mul(&h_eval, y), v);
            i = i + 1;
        };
        h_eval = crypto_algebra::mul(&h_eval, &bn254_arithmetic::invert(&crypto_algebra::sub(xn, &crypto_algebra::one())));

        let msm = msm::empty_msm();
        let i = vector::length(&h_commitments);
        while (i > 0) {
            i = i - 1;
            let commitment = vector::pop_back(&mut h_commitments);
            msm::scale(&mut msm, xn);
            msm::append_term(&mut msm, crypto_algebra::one(), commitment);
        };
        EvaluatedH {
            expected_h_eval: h_eval,
            h_commitment: msm,
            random_eval,
            random_poly_commitment
        }
    }

    public fun queries(self: EvaluatedH, queries: &mut vector<VerifierQuery>, x: &Element<Fr>) {
        vector::push_back(queries, query::new_msm(self.h_commitment, *x, self.expected_h_eval));
        vector::push_back(queries, query::new_commitment(self.random_poly_commitment, *x, self.random_eval));
    }
}

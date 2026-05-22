// Copyright (c) zkMove Authors

module halo2_verifier::vanishing {
    use sui::bn254;
    use sui::group_ops::Element;
    use halo2_common::bn254_utils;
    use halo2_common::msm::{Self, MSM};
    use halo2_common::query::{Self, VerifierQuery};
    use halo2_verifier::transcript::{Self, Transcript};

    public struct Constructed has drop {
        random_poly_commitment: Element<bn254::G1>,
        h_commitments: vector<Element<bn254::G1>>,
    }

    public struct PartialEvaluated has drop {
        random_poly_commitment: Element<bn254::G1>,
        h_commitments: vector<Element<bn254::G1>>,
        random_eval: Element<bn254::Scalar>,
    }

    public struct EvaluatedH has drop {
        expected_h_eval: Element<bn254::Scalar>,
        random_eval: Element<bn254::Scalar>,
        h_commitment: MSM,
        random_poly_commitment: Element<bn254::G1>,
    }

    public fun h_commitments(c: &Constructed): &vector<Element<bn254::G1>> {
        &c.h_commitments
    }

    public fun read_commitments_before_y(transcript: &mut Transcript): Constructed {
        Constructed {
            random_poly_commitment: transcript::read_point(transcript),
            h_commitments: vector[],
        }
    }

    /// Reads commitments of H(x), represented as `(h_1, h_2, ..., h_d)`.
    public fun read_commitments_after_y(
        self: Constructed,
        transcript: &mut Transcript,
        quotient_poly_degree: u64,
    ): Constructed {
        Constructed {
            random_poly_commitment: self.random_poly_commitment,
            h_commitments: transcript::read_n_point(transcript, quotient_poly_degree),
        }
    }

    /// Reads the random polynomial evaluation.
    public fun evaluate_after_x(self: Constructed, transcript: &mut Transcript): PartialEvaluated {
        PartialEvaluated {
            h_commitments: self.h_commitments,
            random_poly_commitment: self.random_poly_commitment,
            random_eval: transcript::read_scalar(transcript),
        }
    }

    public fun h_eval(
        self: PartialEvaluated,
        expressions: &vector<Element<bn254::Scalar>>,
        y: &Element<bn254::Scalar>,
        xn: &Element<bn254::Scalar>,
    ): EvaluatedH {
        let PartialEvaluated { h_commitments, random_eval, random_poly_commitment } = self;

        let mut h_eval = bn254::scalar_zero();
        let mut i = 0;
        while (i < expressions.length()) {
            h_eval = bn254::scalar_add(&bn254::scalar_mul(&h_eval, y), &expressions[i]);
            i = i + 1;
        };
        h_eval = bn254::scalar_mul(
            &h_eval,
            &bn254_utils::invert(&bn254::scalar_sub(xn, &bn254::scalar_one())),
        );

        let mut msm = msm::empty_msm();
        let mut i = h_commitments.length();
        while (i > 0) {
            i = i - 1;
            msm::scale(&mut msm, xn);
            msm::append_term(&mut msm, bn254::scalar_one(), h_commitments[i]);
        };

        EvaluatedH {
            expected_h_eval: h_eval,
            h_commitment: msm,
            random_eval,
            random_poly_commitment,
        }
    }

    public fun queries(self: EvaluatedH, queries: &mut vector<VerifierQuery>, x: &Element<bn254::Scalar>) {
        vector::push_back(queries, query::new_msm(self.h_commitment, *x, self.expected_h_eval));
        vector::push_back(queries, query::new_commitment(self.random_poly_commitment, *x, self.random_eval));
    }
}

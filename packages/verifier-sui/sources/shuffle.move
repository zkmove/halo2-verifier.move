// Copyright (c) zkMove Authors

module halo2_verifier::shuffle {
    use sui::bn254;
    use sui::group_ops::Element;
    use halo2_common::domain::{Self, Domain};
    use halo2_common::i32;
    use halo2_common::query::{Self, VerifierQuery};
    use halo2_verifier::evaluator::compress_exprs;
    use halo2_verifier::protocol::{Self, Protocol, Shuffle};
    use halo2_verifier::transcript::{Self, Transcript};

    public struct Commited has copy, drop {
        product_commitment: Element<bn254::G1>,
    }

    public struct Evaluated has drop {
        commited: Commited,
        product_eval: Element<bn254::Scalar>,
        product_next_eval: Element<bn254::Scalar>,
    }

    public fun shuffles_read_product_commitments(transcript: &mut Transcript): Commited {
        Commited {
            product_commitment: transcript::read_point(transcript),
        }
    }

    public fun evaluate(c: &Commited, transcript: &mut Transcript): Evaluated {
        Evaluated {
            commited: *c,
            product_eval: transcript::read_scalar(transcript),
            product_next_eval: transcript::read_scalar(transcript),
        }
    }

    public fun expression(
        self: &Evaluated,
        shuffle: &Shuffle,
        use_u8_fields: u8,
        use_u8_queries: u8,
        coeff_pool: &vector<Element<bn254::Scalar>>,
        advice_evals: &vector<Element<bn254::Scalar>>,
        fixed_evals: &vector<Element<bn254::Scalar>>,
        instance_evals: &vector<Element<bn254::Scalar>>,
        challenges: &vector<Element<bn254::Scalar>>,
        l_0: &Element<bn254::Scalar>,
        l_last: &Element<bn254::Scalar>,
        l_blind: &Element<bn254::Scalar>,
        theta: &Element<bn254::Scalar>,
        gamma: &Element<bn254::Scalar>,
        result: &mut vector<Element<bn254::Scalar>>,
    ) {
        let active_rows = bn254::scalar_sub(
            &bn254::scalar_one(),
            &bn254::scalar_add(l_last, l_blind),
        );

        let shuffle_expr = compress_exprs(
            protocol::shuffle_exprs(shuffle),
            use_u8_fields,
            use_u8_queries,
            coeff_pool,
            advice_evals,
            fixed_evals,
            instance_evals,
            challenges,
            theta,
        );
        let input_expr = compress_exprs(
            protocol::shuffle_input_exprs(shuffle),
            use_u8_fields,
            use_u8_queries,
            coeff_pool,
            advice_evals,
            fixed_evals,
            instance_evals,
            challenges,
            theta,
        );

        let left = bn254::scalar_mul(
            &self.product_next_eval,
            &bn254::scalar_add(&shuffle_expr, gamma),
        );
        let right = bn254::scalar_mul(
            &self.product_eval,
            &bn254::scalar_add(&input_expr, gamma),
        );
        let product_expression = bn254::scalar_mul(&active_rows, &bn254::scalar_sub(&left, &right));

        vector::push_back(
            result,
            bn254::scalar_mul(l_0, &bn254::scalar_sub(&bn254::scalar_one(), &self.product_eval)),
        );
        vector::push_back(
            result,
            bn254::scalar_mul(
                l_last,
                &bn254::scalar_sub(
                    &bn254::scalar_mul(&self.product_eval, &self.product_eval),
                    &self.product_eval,
                ),
            ),
        );
        vector::push_back(result, product_expression);
    }

    public fun queries(
        e: &vector<Evaluated>,
        queries: &mut vector<VerifierQuery>,
        _protocol: &Protocol,
        domain: &Domain,
        x: &Element<bn254::Scalar>,
    ) {
        let x_next = domain::rotate_omega(domain, x, &i32::from(1));
        let mut i = 0;
        while (i < e.length()) {
            let eval = &e[i];
            vector::push_back(
                queries,
                query::new_commitment(eval.commited.product_commitment, *x, eval.product_eval),
            );
            vector::push_back(
                queries,
                query::new_commitment(eval.commited.product_commitment, x_next, eval.product_next_eval),
            );
            i = i + 1;
        };
    }
}

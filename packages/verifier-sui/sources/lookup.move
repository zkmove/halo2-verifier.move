// Copyright (c) zkMove Authors

module halo2_verifier::lookup {
    use sui::bn254;
    use sui::group_ops::Element;
    use halo2_common::domain::{Self, Domain};
    use halo2_common::i32;
    use halo2_common::query::{Self, VerifierQuery};
    use halo2_verifier::evaluator::compress_exprs;
    use halo2_verifier::protocol::{Self, Lookup, Protocol};
    use halo2_verifier::transcript::{Self, Transcript};

    public struct PermutationCommitments has copy, drop {
        permuted_input_commitment: Element<bn254::G1>,
        permuted_table_commitment: Element<bn254::G1>,
    }

    public struct Commited has copy, drop {
        permuted: PermutationCommitments,
        product_commitment: Element<bn254::G1>,
    }

    public struct Evaluated has drop {
        commited: Commited,
        product_eval: Element<bn254::Scalar>,
        product_next_eval: Element<bn254::Scalar>,
        permuted_input_eval: Element<bn254::Scalar>,
        permuted_input_inv_eval: Element<bn254::Scalar>,
        permuted_table_eval: Element<bn254::Scalar>,
    }

    public fun read_permuted_commitments(transcript: &mut Transcript): PermutationCommitments {
        PermutationCommitments {
            permuted_input_commitment: transcript::read_point(transcript),
            permuted_table_commitment: transcript::read_point(transcript),
        }
    }

    public fun read_product_commitment(c: PermutationCommitments, transcript: &mut Transcript): Commited {
        Commited {
            permuted: c,
            product_commitment: transcript::read_point(transcript),
        }
    }

    public fun evaluate(c: &Commited, transcript: &mut Transcript): Evaluated {
        Evaluated {
            commited: *c,
            product_eval: transcript::read_scalar(transcript),
            product_next_eval: transcript::read_scalar(transcript),
            permuted_input_eval: transcript::read_scalar(transcript),
            permuted_input_inv_eval: transcript::read_scalar(transcript),
            permuted_table_eval: transcript::read_scalar(transcript),
        }
    }

    public fun expression(
        self: &Evaluated,
        lookup: &Lookup,
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
        beta: &Element<bn254::Scalar>,
        gamma: &Element<bn254::Scalar>,
        result: &mut vector<Element<bn254::Scalar>>,
    ) {
        let active_rows = bn254::scalar_sub(
            &bn254::scalar_one(),
            &bn254::scalar_add(l_last, l_blind),
        );

        let input = compress_exprs(
            protocol::input_exprs(lookup),
            use_u8_fields,
            use_u8_queries,
            coeff_pool,
            advice_evals,
            fixed_evals,
            instance_evals,
            challenges,
            theta,
        );
        let table = compress_exprs(
            protocol::table_exprs(lookup),
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
            &bn254::scalar_mul(
                &bn254::scalar_add(&self.permuted_input_eval, beta),
                &bn254::scalar_add(&self.permuted_table_eval, gamma),
            ),
        );
        let right = bn254::scalar_mul(
            &self.product_eval,
            &bn254::scalar_mul(
                &bn254::scalar_add(&input, beta),
                &bn254::scalar_add(&table, gamma),
            ),
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
        vector::push_back(
            result,
            bn254::scalar_mul(l_0, &bn254::scalar_sub(&self.permuted_input_eval, &self.permuted_table_eval)),
        );
        vector::push_back(
            result,
            bn254::scalar_mul(
                &active_rows,
                &bn254::scalar_mul(
                    &bn254::scalar_sub(&self.permuted_input_eval, &self.permuted_table_eval),
                    &bn254::scalar_sub(&self.permuted_input_eval, &self.permuted_input_inv_eval),
                ),
            ),
        );
    }

    public fun queries(
        e: &vector<Evaluated>,
        queries: &mut vector<VerifierQuery>,
        _protocol: &Protocol,
        domain: &Domain,
        x: &Element<bn254::Scalar>,
    ) {
        let x_inv = domain::rotate_omega(domain, x, &i32::neg_from(1));
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
                query::new_commitment(
                    eval.commited.permuted.permuted_input_commitment,
                    *x,
                    eval.permuted_input_eval,
                ),
            );
            vector::push_back(
                queries,
                query::new_commitment(
                    eval.commited.permuted.permuted_table_commitment,
                    *x,
                    eval.permuted_table_eval,
                ),
            );
            vector::push_back(
                queries,
                query::new_commitment(
                    eval.commited.permuted.permuted_input_commitment,
                    x_inv,
                    eval.permuted_input_inv_eval,
                ),
            );
            vector::push_back(
                queries,
                query::new_commitment(eval.commited.product_commitment, x_next, eval.product_next_eval),
            );
            i = i + 1;
        };
    }
}

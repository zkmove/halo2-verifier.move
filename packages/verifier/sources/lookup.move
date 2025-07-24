module halo2_verifier::lookup {
    use std::vector::{Self, for_each_ref};
    use aptos_std::crypto_algebra::{Self, Element};
    use aptos_std::bn254_algebra::{G1, Fr};

    use halo2_common::domain::{Self, Domain};
    use halo2_common::query::{Self, VerifierQuery};
    use halo2_common::i32;
    use halo2_verifier::protocol::{Self, Protocol, Lookup};
    use halo2_verifier::transcript::{Self, Transcript};
    use halo2_verifier::evaluator::compress_exprs;

    struct PermutationCommitments has copy, drop {
        permuted_input_commitment: Element<G1>,
        permuted_table_commitment: Element<G1>,
    }

    struct Commited has copy, drop {
        permuted: PermutationCommitments,
        product_commitment: Element<G1>,
    }

    struct Evaluated has drop {
        commited: Commited,
        product_eval: Element<Fr>,
        product_next_eval: Element<Fr>,
        permuted_input_eval: Element<Fr>,
        permuted_input_inv_eval: Element<Fr>,
        permuted_table_eval: Element<Fr>,
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
        let product_eval = transcript::read_scalar(transcript);
        let product_next_eval = transcript::read_scalar(transcript);
        let permuted_input_eval = transcript::read_scalar(transcript);
        let permuted_input_inv_eval = transcript::read_scalar(transcript);
        let permuted_table_eval = transcript::read_scalar(transcript);
        Evaluated {
            commited: *c,
            product_eval,
            product_next_eval,
            permuted_input_eval,
            permuted_input_inv_eval,
            permuted_table_eval
        }
    }

    public fun expression(
        self: &Evaluated,
        lookup: &Lookup,
        coeff_pool: &vector<Element<Fr>>,
        advice_evals: &vector<Element<Fr>>,
        fixed_evals: &vector<Element<Fr>>,
        instance_evals: &vector<Element<Fr>>,
        challenges: &vector<Element<Fr>>,
        l_0: &Element<Fr>,
        l_last: &Element<Fr>,
        l_blind: &Element<Fr>,
        theta: &Element<Fr>,
        beta: &Element<Fr>,
        gamma: &Element<Fr>,
        result: &mut vector<Element<Fr>>,
    ) {
        let active_rows = crypto_algebra::sub(&crypto_algebra::one(), &crypto_algebra::add(l_last, l_blind));

        // z(\omega X) (a'(X) + \beta) (s'(X) + \gamma)
        // - z(X) (\theta^{m-1} a_0(X) + ... + a_{m-1}(X) + \beta) (\theta^{m-1} s_0(X) + ... + s_{m-1}(X) + \gamma)
        let product_expression = {
            let left = crypto_algebra::mul(
                &self.product_next_eval,
                &crypto_algebra::mul(
                    &crypto_algebra::add(&self.permuted_input_eval, beta),
                    &crypto_algebra::add(&self.permuted_table_eval, gamma)
                ));
            let right = crypto_algebra::mul(
                &self.product_eval,
                &crypto_algebra::mul(
                    &crypto_algebra::add(
                        &compress_exprs(
                            protocol::input_exprs(lookup),
                            coeff_pool,
                            advice_evals,
                            fixed_evals,
                            instance_evals,
                            challenges,
                            theta
                        ),
                        beta
                    ),
                    &crypto_algebra::add(
                        &compress_exprs(
                            protocol::table_exprs(lookup),
                            coeff_pool,
                            advice_evals,
                            fixed_evals,
                            instance_evals,
                            challenges,
                            theta
                        ), gamma),
                )
            );

            crypto_algebra::mul(&active_rows, &crypto_algebra::sub(&left, &right))
        };

        // l_0(X) * (1 - z'(X)) = 0
        vector::push_back(result, crypto_algebra::mul(l_0, &crypto_algebra::sub(&crypto_algebra::one(), &self.product_eval)));
        // l_last(X) * (z(X)^2 - z(X)) = 0
        vector::push_back(
            result,
            crypto_algebra::mul(l_last, &crypto_algebra::sub(&crypto_algebra::sqr(&self.product_eval), &self.product_eval))
        );
        // (1 - (l_last(X) + l_blind(X))) * (
        //   z(\omega X) (a'(X) + \beta) (s'(X) + \gamma)
        //   - z(X) (\theta^{m-1} a_0(X) + ... + a_{m-1}(X) + \beta) (\theta^{m-1} s_0(X) + ... + s_{m-1}(X) + \gamma)
        // ) = 0
        vector::push_back(result, product_expression);

        // l_0(X) * (a'(X) - s'(X)) = 0
        vector::push_back(
            result,
            crypto_algebra::mul(l_0, &crypto_algebra::sub(&self.permuted_input_eval, &self.permuted_table_eval))
        );
        // (1 - (l_last(X) + l_blind(X))) * (a'(X) - s'(X))*(a'(X) - a'(\omega^{-1} X)) = 0
        vector::push_back(result,
            crypto_algebra::mul(&active_rows,
                &crypto_algebra::mul(
                    &crypto_algebra::sub(&self.permuted_input_eval, &self.permuted_table_eval),
                    &crypto_algebra::sub(&self.permuted_input_eval, &self.permuted_input_inv_eval)),
            ));

    }

    public fun queries(e: &vector<Evaluated>, queries: &mut vector<VerifierQuery>, _protocol: &Protocol, domain: &Domain, x: &Element<Fr>) {
        let x_inv = domain::rotate_omega(domain, x, &i32::neg_from(1));
        let x_next = domain::rotate_omega(domain, x, &i32::from(1));
        for_each_ref(e, |evaluated| {
            let eval: &Evaluated = evaluated;
            // Open lookup product commitment at x
            vector::push_back(queries, query::new_commitment(eval.commited.product_commitment, *x, eval.product_eval));
            // Open lookup input commitments at x
            vector::push_back(
                queries,
                query::new_commitment(eval.commited.permuted.permuted_input_commitment, *x, eval.permuted_input_eval)
            );
            // Open lookup table commitments at x
            vector::push_back(
                queries,
                query::new_commitment(eval.commited.permuted.permuted_table_commitment, *x, eval.permuted_table_eval)
            );
            // Open lookup input commitments at \omega^{-1} x
            vector::push_back(
                queries,
                query::new_commitment(
                    eval.commited.permuted.permuted_input_commitment,
                    x_inv,
                    eval.permuted_input_inv_eval
                )
            );
            // Open lookup product commitment at \omega x
            vector::push_back(
                queries,
                query::new_commitment(eval.commited.product_commitment, x_next, eval.product_next_eval)
            );
        });
    }
}

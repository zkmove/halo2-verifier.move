module halo2_verifier::lookup {
    use std::vector::{Self, for_each_ref};
    use aptos_std::crypto_algebra::{Element};

    use halo2_verifier::bn254_types::{G1, Fr};
    use halo2_verifier::domain;
    use halo2_verifier::expression::{Self, Expression};
    use halo2_verifier::arithmetic;
    use halo2_verifier::protocol::{Self, Protocol, Lookup};
    use halo2_verifier::query::{Self, VerifierQuery};
    use halo2_verifier::rotation;
    use halo2_verifier::transcript::{Self, Transcript};

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
    ): vector<Element<Fr>> {
        let active_rows = arithmetic::sub(&arithmetic::one(), &arithmetic::add(l_last, l_blind));

        // z(\omega X) (a'(X) + \beta) (s'(X) + \gamma)
        // - z(X) (\theta^{m-1} a_0(X) + ... + a_{m-1}(X) + \beta) (\theta^{m-1} s_0(X) + ... + s_{m-1}(X) + \gamma)
        let product_expression = {
            let left = arithmetic::mul(
                &self.product_next_eval,
                &arithmetic::mul(
                    &arithmetic::add(&self.permuted_input_eval, beta),
                    &arithmetic::add(&self.permuted_table_eval, gamma)
                ));
            let right = arithmetic::mul(
                &self.product_eval,
                &arithmetic::mul(
                    &arithmetic::add(
                        &compress_expressions(
                            protocol::input_exprs(lookup),
                            advice_evals,
                            fixed_evals,
                            instance_evals,
                            challenges,
                            theta
                        ),
                        beta
                    ),
                    &arithmetic::add(
                        &compress_expressions(
                            protocol::table_exprs(lookup),
                            advice_evals,
                            fixed_evals,
                            instance_evals,
                            challenges,
                            theta
                        ), gamma),
                )
            );

            arithmetic::mul(&active_rows, &arithmetic::sub(&left, &right))
        };

        let result = vector::empty();
        // l_0(X) * (1 - z'(X)) = 0
        vector::push_back(&mut result, arithmetic::mul(l_0, &arithmetic::sub(&arithmetic::one(), &self.product_eval)));
        // l_last(X) * (z(X)^2 - z(X)) = 0
        vector::push_back(
            &mut result,
            arithmetic::mul(l_last, &arithmetic::sub(&arithmetic::square(&self.product_eval), &self.product_eval))
        );
        // (1 - (l_last(X) + l_blind(X))) * (
        //   z(\omega X) (a'(X) + \beta) (s'(X) + \gamma)
        //   - z(X) (\theta^{m-1} a_0(X) + ... + a_{m-1}(X) + \beta) (\theta^{m-1} s_0(X) + ... + s_{m-1}(X) + \gamma)
        // ) = 0
        vector::push_back(&mut result, product_expression);

        // l_0(X) * (a'(X) - s'(X)) = 0
        vector::push_back(
            &mut result,
            arithmetic::mul(l_0, &arithmetic::sub(&self.permuted_input_eval, &self.permuted_table_eval))
        );
        // (1 - (l_last(X) + l_blind(X))) * (a'(X) - s'(X))*(a'(X) - a'(\omega^{-1} X)) = 0
        vector::push_back(&mut result,
            arithmetic::mul(&active_rows,
                &arithmetic::mul(
                    &arithmetic::sub(&self.permuted_input_eval, &self.permuted_table_eval),
                    &arithmetic::sub(&self.permuted_input_eval, &self.permuted_input_inv_eval)),
            ));

        result
    }

    fun compress_expressions(exprs: &vector<Expression>,
                             advice_evals: &vector<Element<Fr>>,
                             fixed_evals: &vector<Element<Fr>>,
                             instance_evals: &vector<Element<Fr>>,
                             challenges: &vector<Element<Fr>>,
                             theta: &Element<Fr>
    ): Element<Fr> {
        let acc = arithmetic::zero();
        let i = 0;
        let len = vector::length(exprs);
        while (i < len) {
            let eval = expression::evaluate(
                vector::borrow(exprs, i),
                advice_evals,
                fixed_evals,
                instance_evals,
                challenges
            );
            acc = arithmetic::add(&arithmetic::mul(theta, &acc), &eval);
            i = i + 1;
        };
        acc
    }

    public fun queries(self: &vector<Evaluated>, queries: &mut vector<VerifierQuery>, protocol: &Protocol, x: &Element<Fr>) {
        let domain = protocol::domain(protocol);
        let x_inv = domain::rotate_omega(domain, x, &rotation::prev(1));
        let x_next = domain::rotate_omega(domain, x, &rotation::next(1));
        for_each_ref(self, |evaluated| {
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

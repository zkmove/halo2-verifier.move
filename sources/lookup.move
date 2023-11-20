module halo2_verifier::lookup {
    use std::vector::{Self, for_each_ref};

    use halo2_verifier::bn254_types::G1;
    use halo2_verifier::domain;
    use halo2_verifier::expression::{Self, Expression};
    use halo2_verifier::point::Point;
    use halo2_verifier::protocol::{Self, Protocol, Lookup};
    use halo2_verifier::query::{Self, VerifierQuery};
    use halo2_verifier::rotation;
    use halo2_verifier::scalar::{Self, Scalar};
    use halo2_verifier::transcript::{Self, Transcript};

    struct PermutationCommitments has copy, drop {
        permuted_input_commitment: Point<G1>,
        permuted_table_commitment: Point<G1>,
    }

    struct Commited has copy, drop {
        permuted: PermutationCommitments,
        product_commitment: Point<G1>,
    }

    struct Evaluated has drop {
        commited: Commited,
        product_eval: Scalar,
        product_next_eval: Scalar,
        permuted_input_eval: Scalar,
        permuted_input_inv_eval: Scalar,
        permuted_table_eval: Scalar,
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
        advice_evals: &vector<Scalar>,
        fixed_evals: &vector<Scalar>,
        instance_evals: &vector<Scalar>,
        challenges: &vector<Scalar>,
        l_0: &Scalar,
        l_last: &Scalar,
        l_blind: &Scalar,
        theta: &Scalar,
        beta: &Scalar,
        gamma: &Scalar,
    ): vector<Scalar> {
        let active_rows = scalar::sub(&scalar::one(), &scalar::add(l_last, l_blind));

        // z(\omega X) (a'(X) + \beta) (s'(X) + \gamma)
        // - z(X) (\theta^{m-1} a_0(X) + ... + a_{m-1}(X) + \beta) (\theta^{m-1} s_0(X) + ... + s_{m-1}(X) + \gamma)
        let product_expression = {
            let left = scalar::mul(
                &self.product_next_eval,
                &scalar::mul(
                    &scalar::add(&self.permuted_input_eval, beta),
                    &scalar::add(&self.permuted_table_eval, gamma)
                ));
            let right = scalar::mul(
                &self.product_eval,
                &scalar::mul(
                    &scalar::add(
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
                    &scalar::add(
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

            scalar::mul(&active_rows, &scalar::sub(&left, &right))
        };

        let result = vector::empty();
        // l_0(X) * (1 - z'(X)) = 0
        vector::push_back(&mut result, scalar::mul(l_0, &scalar::sub(&scalar::one(), &self.product_eval)));
        // l_last(X) * (z(X)^2 - z(X)) = 0
        vector::push_back(
            &mut result,
            scalar::mul(l_last, &scalar::sub(&scalar::square(&self.product_eval), &self.product_eval))
        );
        // (1 - (l_last(X) + l_blind(X))) * (
        //   z(\omega X) (a'(X) + \beta) (s'(X) + \gamma)
        //   - z(X) (\theta^{m-1} a_0(X) + ... + a_{m-1}(X) + \beta) (\theta^{m-1} s_0(X) + ... + s_{m-1}(X) + \gamma)
        // ) = 0
        vector::push_back(&mut result, product_expression);

        // l_0(X) * (a'(X) - s'(X)) = 0
        vector::push_back(
            &mut result,
            scalar::mul(l_0, &scalar::sub(&self.permuted_input_eval, &self.permuted_table_eval))
        );
        // (1 - (l_last(X) + l_blind(X))) * (a'(X) - s'(X))*(a'(X) - a'(\omega^{-1} X)) = 0
        vector::push_back(&mut result,
            scalar::mul(&active_rows,
                &scalar::mul(
                    &scalar::sub(&self.permuted_input_eval, &self.permuted_table_eval),
                    &scalar::sub(&self.permuted_input_eval, &self.permuted_input_inv_eval)),
            ));

        result
    }

    fun compress_expressions(exprs: &vector<Expression>,
                             advice_evals: &vector<Scalar>,
                             fixed_evals: &vector<Scalar>,
                             instance_evals: &vector<Scalar>,
                             challenges: &vector<Scalar>,
                             theta: &Scalar
    ): Scalar {
        let acc = scalar::zero();
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
            acc = scalar::add(&scalar::mul(theta, &acc), &eval);
            i = i + 1;
        };
        acc
    }

    public fun queries(self: &vector<Evaluated>, queries: &mut vector<VerifierQuery>, protocol: &Protocol, x: &Scalar) {
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

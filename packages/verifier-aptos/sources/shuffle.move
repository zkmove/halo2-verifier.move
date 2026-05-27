module halo2_verifier::shuffle {
    use std::vector::{Self, for_each_ref};
    use aptos_std::crypto_algebra::{Self, Element};
    use aptos_std::bn254_algebra::{G1, Fr};

    use halo2_common::domain::{Self, Domain};
    use halo2_common::query::{Self, VerifierQuery};
    use halo2_common::i32;
    use halo2_verifier::protocol::{Self, Protocol, Shuffle};
    use halo2_verifier::transcript::{Self, Transcript};
    use halo2_verifier::evaluator::compress_exprs;

    struct Commited has copy, drop {
        product_commitment: Element<G1>,
    }

    struct Evaluated has drop {
        commited: Commited,
        product_eval: Element<Fr>,
        product_next_eval: Element<Fr>,
    }

    public fun shuffles_read_product_commitments(transcript: &mut Transcript): Commited {
        Commited {
            product_commitment: transcript::read_point(transcript),
        }
    }

    public fun evaluate(c: &Commited, transcript: &mut Transcript): Evaluated {
        let product_eval = transcript::read_scalar(transcript);
        let product_next_eval = transcript::read_scalar(transcript);
        Evaluated {
            commited: *c,
            product_eval,
            product_next_eval,
        }
    }

    public fun expression(
        self: &Evaluated,
        shuffle: &Shuffle,
        use_u8_fields: u8,
        use_u8_queries: u8,
        coeff_pool: &vector<Element<Fr>>,
        advice_evals: &vector<Element<Fr>>,
        fixed_evals: &vector<Element<Fr>>,
        instance_evals: &vector<Element<Fr>>,
        challenges: &vector<Element<Fr>>,
        l_0: &Element<Fr>,
        l_last: &Element<Fr>,
        l_blind: &Element<Fr>,
        theta: &Element<Fr>,
        gamma: &Element<Fr>,
        result: &mut vector<Element<Fr>>,
    ) {
        let active_rows = crypto_algebra::sub(&crypto_algebra::one(), &crypto_algebra::add(l_last, l_blind));

        // z(\omega X) (s(X) + \gamma) - z(X) (a(X) + \gamma)
        let product_expression = {
            let left = crypto_algebra::mul(
                &self.product_next_eval,
                &crypto_algebra::add(
                    &compress_exprs(
                        protocol::shuffle_exprs(shuffle),
                        use_u8_fields,
                        use_u8_queries,
                        coeff_pool,
                        advice_evals,
                        fixed_evals,
                        instance_evals,
                        challenges,
                        theta
                    ), gamma,
                ),
            );
            let right = crypto_algebra::mul(
                &self.product_eval,
                &crypto_algebra::add(
                    &compress_exprs(
                        protocol::shuffle_input_exprs(shuffle),
                        use_u8_fields,
                        use_u8_queries,
                        coeff_pool,
                        advice_evals,
                        fixed_evals,
                        instance_evals,
                        challenges,
                        theta
                    ), gamma,
                ),
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
        // (1 - (l_last(X) + l_blind(X))) * ( z(\omega X) (s(X) + \gamma) - z(X) (a(X) + \gamma))
        vector::push_back(result, product_expression);
    }

    public fun queries(e: &vector<Evaluated>, queries: &mut vector<VerifierQuery>, _protocol: &Protocol, domain: &Domain, x: &Element<Fr>) {
        let x_next = domain::rotate_omega(domain, x, &i32::from(1));
        for_each_ref(e, |evaluated| {
            let eval: &Evaluated = evaluated;
            // Open shuffle product commitment at x
            vector::push_back(queries, query::new_commitment(eval.commited.product_commitment, *x, eval.product_eval));
            // Open shuffle product commitment at \omega x
            vector::push_back(
                queries,
                query::new_commitment(eval.commited.product_commitment, x_next, eval.product_next_eval)
            );
        });
    }
}
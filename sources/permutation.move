module halo2_verifier::permutation {
    use std::option::{Self, Option};
    use std::vector::{Self, zip, for_each_ref, for_each_reverse};

    use halo2_verifier::bn254_types::G1;
    use halo2_verifier::column;
    use halo2_verifier::domain;
    use halo2_verifier::point::Point;
    use halo2_verifier::protocol::{Self, Protocol, permutation_columns};
    use halo2_verifier::query::{Self, VerifierQuery};
    use halo2_verifier::rotation;
    use halo2_verifier::scalar::{Self, Scalar};
    use halo2_verifier::transcript::{Self, Transcript};

    struct Commited has drop {
        permutation_product_commitments: vector<Point<G1>>,
    }

    struct CommonEvaluted has drop {
        permutation_evals: vector<Scalar>,
    }

    struct PermutationEvaluatedSet has drop {
        permutation_product_commitment: Point<G1>,
        permutation_product_eval: Scalar,
        permutation_product_next_eval: Scalar,
        permutation_product_last_eval: Option<Scalar>,
    }

    struct Evaluted has drop {
        sets: vector<PermutationEvaluatedSet>,
    }

    public fun read_product_commitments(transcript: &mut Transcript, num_permutation_z: u64): Commited {
        Commited {
            permutation_product_commitments: transcript::read_n_point(transcript, num_permutation_z)
        }
    }

    public fun permutation_product_commitments(self: &Commited): &vector<Point<G1>> {
        &self.permutation_product_commitments
    }

    public fun evalute_common(transcript: &mut Transcript, len: u64): CommonEvaluted {
        CommonEvaluted {
            permutation_evals: transcript::read_n_scalar(transcript, len)
        }
    }

    public fun evaluate(self: Commited, transcript: &mut Transcript): Evaluted {
        let product_commitments: &vector<Point<G1>> = &self.permutation_product_commitments;
        let i = 0;
        let len = vector::length(product_commitments);
        let sets = vector::empty();
        while (i < len) {
            let permutation_product_commitment = *vector::borrow(product_commitments, i);
            let permutation_product_eval = transcript::read_scalar(transcript);
            let permutation_product_next_eval = transcript::read_scalar(transcript);
            i = i + 1;
            let permutation_product_last_eval = if (i == len) {
                option::some(transcript::read_scalar(transcript))
            } else {
                option::none()
            };

            vector::push_back(&mut sets, PermutationEvaluatedSet {
                permutation_product_commitment,
                permutation_product_eval,
                permutation_product_next_eval,
                permutation_product_last_eval
            });
        };
        Evaluted {
            sets
        }
    }

    public fun expressions(
        self: &Evaluted,
        protocol: &Protocol,
        permutations_common: &CommonEvaluted,
        advice_evals: &vector<Scalar>,
        fixed_evals: &vector<Scalar>,
        instance_evals: &vector<Scalar>,
        l_0: &Scalar,
        l_last: &Scalar,
        l_blind: &Scalar,
        beta: &Scalar,
        gamma: &Scalar,
        x: &Scalar
    ): vector<Scalar> {
        let evaluted = &self.sets;
        let sets_len = vector::length(evaluted);
        let results = vector::empty();
        if (sets_len == 0) {
            return results
        };

        // l_0(X)*(1 - z_0(X)) = 0
        let first_set = vector::borrow(evaluted, 0);
        vector::push_back(
            &mut results,
            scalar::mul(l_0, &scalar::sub(&scalar::one(), &first_set.permutation_product_eval))
        );
        // l_last(X)*(z_l(X)^2 - z_l(X)) = 0
        let last_set = vector::borrow(evaluted, sets_len - 1);
        vector::push_back(&mut results,
            scalar::mul(
                l_last,
                &scalar::sub(
                    &scalar::square(&last_set.permutation_product_eval),
                    &last_set.permutation_product_eval
                )
            ));
        // Except for the first set, enforce.
        // l_0(X) * (z_i(X) - z_{i-1}(\omega^(last) X)) = 0
        {
            let i = 1;
            while (i < sets_len) {
                let prev = vector::borrow(evaluted, i - 1);
                let cur = vector::borrow(evaluted, i);
                vector::push_back(
                    &mut results,
                    scalar::mul(
                        l_0,
                        &scalar::sub(
                            &cur.permutation_product_eval,
                            option::borrow(&prev.permutation_product_last_eval)
                        )
                    )
                );
                i = i + 1;
            }
        };

        // And for all the sets we enforce:
        // (1 - (l_last(X) + l_blind(X))) * (
        //   z_i(\omega X) \prod (p(X) + \beta s_i(X) + \gamma)
        // - z_i(X) \prod (p(X) + \delta^i \beta X + \gamma)
        // )
        {
            let chunk_len = protocol::permutation_chunk_size(protocol);
            let permutation_columns = permutation_columns(protocol);
            let permutation_columns_len = vector::length(permutation_columns);
            let i = 0;
            while (i < sets_len) {
                let set = vector::borrow(evaluted, i);
                // left = z_i(w*X) * (p(X) + beta * s_i(X) + gamma)
                let left = set.permutation_product_next_eval;
                // right = z_i(X) * (p(X) + delta^i * beta * X + gamma)
                let right = set.permutation_product_eval;
                // cur_delta = beta * x * delta^(i*chunk_len)
                let current_delta = scalar::mul(&scalar::mul(beta, x), &scalar::pow(&scalar::delta(), i * chunk_len));
                let j = i * chunk_len;
                while (j < (i + 1) * chunk_len && j < permutation_columns_len) {
                    let permutation_eval = vector::borrow(&permutations_common.permutation_evals, j);
                    let column = vector::borrow(permutation_columns, j);
                    let eval = if (column::is_fixed(column)) {
                        let query_index = protocol::get_query_index(protocol, column, &rotation::cur());
                        vector::borrow(fixed_evals, query_index)
                    } else if (column::is_instance(column)) {
                        let query_index = protocol::get_query_index(protocol, column, &rotation::cur());
                        vector::borrow(instance_evals, query_index)
                    } else {
                        let query_index = protocol::get_query_index(protocol, column, &rotation::cur());
                        vector::borrow(advice_evals, query_index)
                    };
                    left = scalar::mul(
                        &left,
                        &scalar::add(&scalar::add(eval, gamma), &scalar::mul(beta, permutation_eval))
                    );
                    right = scalar::mul(&right, &scalar::add(&scalar::add(eval, gamma), &current_delta));
                    current_delta = scalar::mul(&current_delta, &scalar::delta());
                    j = j + 1;
                };

                // (1-(l_last(X) + l_blind(X))) * (left - right)
                vector::push_back(
                    &mut results,
                    scalar::mul(
                        &scalar::sub(&left, &right),
                        &scalar::sub(&scalar::one(), &scalar::add(l_last, l_blind))
                    )
                );
                i = i + 1;
            }
        };


        results
    }

    public fun queries(self: Evaluted, queries: &mut vector<VerifierQuery>, protocol: &Protocol, x: &Scalar) {
        let blinding_factors = protocol::blinding_factors(protocol);
        let domain = protocol::domain(protocol);
        let x_next = domain::rotate_omega(domain, x, &rotation::next(1));
        let x_last = domain::rotate_omega(domain, x, &rotation::prev((blinding_factors as u32) + 1));
        // Open permutation product commitments at x and \omega^{-1} x
        // Open permutation product commitments at x and \omega x
        for_each_ref(&self.sets, |set| {
            let s: &PermutationEvaluatedSet = set;
            vector::push_back(queries,
                query::new_commitment(s.permutation_product_commitment, *x, s.permutation_product_eval));
            vector::push_back(queries,
                query::new_commitment(s.permutation_product_commitment, x_next, s.permutation_product_next_eval));
        });

        // Open it at \omega^{last} x for all but the last set
        vector::pop_back(&mut self.sets);
        let Evaluted { sets } = self;
        for_each_reverse(sets, |set| {
            let s: PermutationEvaluatedSet = set;
            vector::push_back(queries,
                query::new_commitment(
                    s.permutation_product_commitment,
                    x_last,
                    option::destroy_some(s.permutation_product_last_eval)
                ));
        });
    }

    public fun common_queries(
        self: CommonEvaluted,
        queries: &mut vector<VerifierQuery>,
        permutation_commitments: vector<Point<G1>>,
        x: &Scalar
    ) {
        zip<Point<G1>, Scalar>(
            permutation_commitments, self.permutation_evals,
            |commit, eval| vector::push_back(queries, query::new_commitment(commit, *x, eval))
        );
    }
}
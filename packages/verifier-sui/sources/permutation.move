// Copyright (c) zkMove Authors

module halo2_verifier::permutation {
    use sui::bn254;
    use sui::group_ops::Element;
    use halo2_common::bn254_utils;
    use halo2_common::column;
    use halo2_common::domain::{Self, Domain};
    use halo2_common::i32;
    use halo2_common::query::{Self, VerifierQuery};
    use halo2_verifier::protocol::{Self, Protocol, permutation_columns};
    use halo2_verifier::transcript::{Self, Transcript};

    public struct Commited has drop {
        permutation_product_commitments: vector<Element<bn254::G1>>,
    }

    public struct CommonEvaluted has drop {
        permutation_evals: vector<Element<bn254::Scalar>>,
    }

    public struct PermutationEvaluatedSet has drop {
        permutation_product_commitment: Element<bn254::G1>,
        permutation_product_eval: Element<bn254::Scalar>,
        permutation_product_next_eval: Element<bn254::Scalar>,
        permutation_product_last_eval: Option<Element<bn254::Scalar>>,
    }

    public struct Evaluted has drop {
        sets: vector<PermutationEvaluatedSet>,
    }

    public fun read_product_commitments(transcript: &mut Transcript, num_permutation_z: u64): Commited {
        Commited {
            permutation_product_commitments: transcript::read_n_point(transcript, num_permutation_z),
        }
    }

    public fun permutation_product_commitments(self: &Commited): &vector<Element<bn254::G1>> {
        &self.permutation_product_commitments
    }

    public fun evalute_common(transcript: &mut Transcript, len: u64): CommonEvaluted {
        CommonEvaluted {
            permutation_evals: transcript::read_n_scalar(transcript, len),
        }
    }

    public fun evaluate(self: Commited, transcript: &mut Transcript): Evaluted {
        let product_commitments = &self.permutation_product_commitments;
        let mut i = 0;
        let len = product_commitments.length();
        let mut sets = vector[];
        while (i < len) {
            let permutation_product_commitment = product_commitments[i];
            let permutation_product_eval = transcript::read_scalar(transcript);
            let permutation_product_next_eval = transcript::read_scalar(transcript);
            i = i + 1;
            let permutation_product_last_eval = if (i == len) {
                option::none()
            } else {
                option::some(transcript::read_scalar(transcript))
            };

            vector::push_back(&mut sets, PermutationEvaluatedSet {
                permutation_product_commitment,
                permutation_product_eval,
                permutation_product_next_eval,
                permutation_product_last_eval,
            });
        };
        Evaluted { sets }
    }

    public fun expressions(
        self: &Evaluted,
        protocol: &Protocol,
        permutations_common: &CommonEvaluted,
        advice_evals: &vector<Element<bn254::Scalar>>,
        fixed_evals: &vector<Element<bn254::Scalar>>,
        instance_evals: &vector<Element<bn254::Scalar>>,
        l_0: &Element<bn254::Scalar>,
        l_last: &Element<bn254::Scalar>,
        l_blind: &Element<bn254::Scalar>,
        beta: &Element<bn254::Scalar>,
        gamma: &Element<bn254::Scalar>,
        x: &Element<bn254::Scalar>,
        results: &mut vector<Element<bn254::Scalar>>,
    ) {
        let evaluted = &self.sets;
        let sets_len = evaluted.length();
        if (sets_len == 0) {
            return
        };

        let first_set = &evaluted[0];
        vector::push_back(
            results,
            bn254::scalar_mul(
                l_0,
                &bn254::scalar_sub(&bn254::scalar_one(), &first_set.permutation_product_eval),
            ),
        );

        let last_set = &evaluted[sets_len - 1];
        vector::push_back(
            results,
            bn254::scalar_mul(
                l_last,
                &bn254::scalar_sub(
                    &bn254::scalar_mul(&last_set.permutation_product_eval, &last_set.permutation_product_eval),
                    &last_set.permutation_product_eval,
                ),
            ),
        );

        let mut i = 1;
        while (i < sets_len) {
            let prev = &evaluted[i - 1];
            let cur = &evaluted[i];
            vector::push_back(
                results,
                bn254::scalar_mul(
                    l_0,
                    &bn254::scalar_sub(
                        &cur.permutation_product_eval,
                        option::borrow(&prev.permutation_product_last_eval),
                    ),
                ),
            );
            i = i + 1;
        };

        let chunk_len = protocol::permutation_chunk_size(protocol) as u64;
        let permutation_columns = permutation_columns(protocol);
        let permutation_columns_len = permutation_columns.length();
        let mut set_index = 0;
        while (set_index < sets_len) {
            let set = &evaluted[set_index];
            let mut left = set.permutation_product_next_eval;
            let mut right = set.permutation_product_eval;
            let mut current_delta = bn254::scalar_mul(
                &bn254::scalar_mul(beta, x),
                &bn254_utils::pow_u32(&bn254_utils::delta_of_fr(), ((set_index * chunk_len) as u32)),
            );
            let mut j = set_index * chunk_len;
            while (j < (set_index + 1) * chunk_len && j < permutation_columns_len) {
                let permutation_eval = &permutations_common.permutation_evals[j];
                let col = &permutation_columns[j];
                let eval = if (column::is_fixed(col)) {
                    let query_index = protocol::get_query_index(protocol, col, &i32::zero());
                    &fixed_evals[query_index]
                } else if (column::is_instance(col)) {
                    let query_index = protocol::get_query_index(protocol, col, &i32::zero());
                    &instance_evals[query_index]
                } else {
                    let query_index = protocol::get_query_index(protocol, col, &i32::zero());
                    &advice_evals[query_index]
                };

                left = bn254::scalar_mul(
                    &left,
                    &bn254::scalar_add(
                        &bn254::scalar_add(eval, gamma),
                        &bn254::scalar_mul(beta, permutation_eval),
                    ),
                );
                right = bn254::scalar_mul(
                    &right,
                    &bn254::scalar_add(&bn254::scalar_add(eval, gamma), &current_delta),
                );
                current_delta = bn254::scalar_mul(&current_delta, &bn254_utils::delta_of_fr());
                j = j + 1;
            };

            vector::push_back(
                results,
                bn254::scalar_mul(
                    &bn254::scalar_sub(&left, &right),
                    &bn254::scalar_sub(&bn254::scalar_one(), &bn254::scalar_add(l_last, l_blind)),
                ),
            );
            set_index = set_index + 1;
        };
    }

    public fun queries(
        mut self: Evaluted,
        queries: &mut vector<VerifierQuery>,
        protocol: &Protocol,
        domain: &Domain,
        x: &Element<bn254::Scalar>,
    ) {
        let blinding_factors = protocol::blinding_factors(protocol);
        let x_next = domain::rotate_omega(domain, x, &i32::from(1));
        let x_last = domain::rotate_omega(domain, x, &i32::neg_from((blinding_factors as u32) + 1));

        let mut i = 0;
        while (i < self.sets.length()) {
            let s = &self.sets[i];
            vector::push_back(
                queries,
                query::new_commitment(s.permutation_product_commitment, *x, s.permutation_product_eval),
            );
            vector::push_back(
                queries,
                query::new_commitment(s.permutation_product_commitment, x_next, s.permutation_product_next_eval),
            );
            i = i + 1;
        };

        if (self.sets.length() > 0) {
            vector::pop_back(&mut self.sets);
        };

        let mut i = self.sets.length();
        while (i > 0) {
            i = i - 1;
            let s = vector::remove(&mut self.sets, i);
            vector::push_back(
                queries,
                query::new_commitment(
                    s.permutation_product_commitment,
                    x_last,
                    option::destroy_some(s.permutation_product_last_eval),
                ),
            );
        };
    }

    public fun common_queries(
        self: CommonEvaluted,
        queries: &mut vector<VerifierQuery>,
        permutation_commitments: vector<Element<bn254::G1>>,
        x: &Element<bn254::Scalar>,
    ) {
        let mut i = 0;
        let len = permutation_commitments.length();
        assert!(len == self.permutation_evals.length(), 100);
        while (i < len) {
            vector::push_back(
                queries,
                query::new_commitment(permutation_commitments[i], *x, self.permutation_evals[i]),
            );
            i = i + 1;
        };
    }
}

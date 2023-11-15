module halo2_verifier::plonk_proof {
    use halo2_verifier::protocol::{Protocol, transcript_initial_state, evaluations_len, query_instance, instance_queries, permutation_columns};
    use halo2_verifier::scalar::Scalar;
    use halo2_verifier::transcript::{Transcript};
    use std::vector;
    use halo2_verifier::protocol;
    use halo2_verifier::transcript;
    use halo2_verifier::point::Point;
    use halo2_verifier::pcs;
    use halo2_verifier::params::Params;
    use halo2_verifier::pcs::Proof;
    use halo2_verifier::verify_key::VerifyingKey;
    use std::vector::{map_ref, fold};
    use std::option::Option;
    use std::option;
    use halo2_verifier::common_evaluations;
    use halo2_verifier::params;
    use halo2_verifier::scalar;
    use halo2_verifier::column;
    use halo2_verifier::rotation;
    use halo2_verifier::msm::MSM;
    use halo2_verifier::msm;
    use halo2_verifier::plonk_proof::h_eval;

    const INVALID_INSTANCES: u64 = 100;

    struct PlonkProof {
        commitments: vector<Point>,
        challenges: vector<Scalar>,
        quotients: vector<Point>,

        instance_evals: vector<vector<Scalar>>,
        advice_evals: vector<vector<Scalar>>,
        fixed_evals: vector<Scalar>,
        random_poly_eval: Scalar,
        permutations_common: vector<Scalar>,
        permutations_evaluated: vector<vector<PermutationEvaluatedSet>>,
        lookups_evaluated: vector<vector<LookupEvaluated>>,
        z: Scalar,
        pcs: Proof,
    }

    struct PermutationEvaluatedSet {
        permutation_product_commitment: Point,
        permutation_product_eval: Scalar,
        permutation_product_next_eval: Scalar,
        permutation_product_last_eval: Option<Scalar>,
    }

    struct LookupCommited {
        permuted_input_commitment: Point,
        permuted_table_commitment: Point,
        product_commitment: Point,
    }

    struct LookupEvaluated {
        product_eval: Scalar,
        product_next_eval: Scalar,
        permuted_input_eval: Scalar,
        permuted_input_inv_eval: Scalar,
        permuted_table_eval: Scalar,
    }

    struct EvaluatedH {
        expected_h_eval: Scalar,
        h_commitment: MSM,
    }

    public fun read(
        params: &Params,
        vk: &VerifyingKey,
        protocol: &Protocol,
        instances: vector<vector<vector<Scalar>>>,
        transcript: Transcript
    ): PlonkProof {
        let scalar = transcript_initial_state(protocol);
        transcript::common_scalar(&mut transcript, scalar);
        // check_instances(&instances, protocol::num_instance(protocol));
        // TODO: read committed_instances
        let num_proof = vector::length(&instances);
        // - read advice commitments and challenges
        let (witness_commitments, challenges) = read_commitment_and_challenges(
            &mut transcript,
            &protocol::num_witness(protocol, num_proof),
            &protocol::num_challenge(protocol),
        );


        // FIXME
        let beta: Scalar;
        let gamma: Scalar;
        let y: Scalar;
        let permutations_committed = vector::empty<vector<Point>>();
        let lookups_commited = vector::empty<vector<LookupCommited>>();
        let random_poly_commited: Point;

        // - read commitments of H(x) which is (h_1,h_2,.., h_d)
        let quotients = transcript::read_n_point(
            &mut transcript,
            protocol::num_chunks_of_quotient(protocol, num_proof)
        );
        // - eval at point: z
        let z = transcript::squeeze_challenge(&mut transcript);

        // TODO: check instance evals
        let instance_evals = if (query_instance(protocol)) {
            let len = vector::length(instance_queries(protocol));
            let i = 0;
            let result = vector::empty();
            while (i < num_proof) {
                vector::push_back(&mut result, transcript::read_n_scalar(&mut transcript, len));
                i = i + 1;
            };
            result
        } else {
            vector::empty()
        };

        let advice_evals = {
            let len = vector::length(protocol::advice_queries(protocol));
            let i = 0;
            let result = vector::empty();
            while (i < num_proof) {
                vector::push_back(&mut result, transcript::read_n_scalar(&mut transcript, len));
                i = i + 1;
            };
            result
        };
        let fixed_evals = transcript::read_n_scalar(&mut transcript, vector::length(protocol::fixed_queries(protocol)));
        let random_poly_eval = transcript::read_scalar(&mut transcript);
        let permutations_common = transcript::read_n_scalar(&mut transcript, protocol::num_permutation_fixed(protocol));
        let permutations_evaluated = {
            map_ref<vector<Point>, vector<PermutationEvaluatedSet>>(&permutations_committed, |product_commitments| {
                let i = 0;
                let len = vector::length(product_commitments);
                let result = vector::empty();
                while (i < len) {
                    let permutation_product_commitment = *vector::borrow(product_commitments, i);
                    let permutation_product_eval = transcript::read_scalar(&mut transcript);
                    let permutation_product_next_eval = transcript::read_scalar(&mut transcript);
                    i = i + 1;
                    let permutation_product_last_eval = if (i == len) {
                        option::some(transcript::read_scalar(&mut transcript))
                    } else {
                        option::none()
                    };

                    vector::push_back(&mut result, PermutationEvaluatedSet {
                        permutation_product_commitment,
                        permutation_product_eval,
                        permutation_product_next_eval,
                        permutation_product_last_eval
                    });
                };
                result
            })
        };
        let lookups_evaluated = map_ref<vector<LookupCommited>, vector<LookupEvaluated>>(&lookups_commited, |commited| {
            map_ref<LookupCommited, LookupEvaluated>(commited, |c| {
                let product_eval = transcript::read_scalar(&mut transcript);
                let product_next_eval = transcript::read_scalar(&mut transcript);
                let permuted_input_eval = transcript::read_scalar(&mut transcript);
                let permuted_input_inv_eval = transcript::read_scalar(&mut transcript);
                let permuted_table_eval = transcript::read_scalar(&mut transcript);
                LookupEvaluated {
                    product_eval,
                    product_next_eval,
                    permuted_input_eval,
                    permuted_input_inv_eval,
                    permuted_table_eval
                }
            })
        });


        let vanishing = {
            let commons = common_evaluations::new(params::k(params), z);
            let expressions = vector::empty();
            let i = 0;
            while (i < num_proof) {
                // todo: calculate gates' evals result
                let gate_expressions = vector::empty();
                let permutation_expressions = permutation_expressions(
                    vector::borrow(&permutations_evaluated, i),
                    protocol,
                    &permutations_common,
                    vector::borrow(&advice_evals, i),
                    &fixed_evals,
                    vector::borrow(&instance_evals, i),
                    &common_evaluations::l_0(&commons),
                    &common_evaluations::l_last(&commons),
                    &common_evaluations::l_blind(&commons),
                    &beta,
                    &gamma,
                    &z,
                    );
                // todo: lookup polys evals
                let lookup_expressions: vector<Scalar>;

                vector::append(&mut expressions, gate_expressions);
                vector::append(&mut expressions, permutation_expressions);
                vector::append(&mut expressions, lookup_expressions);
                i = i+1;
            };
            let xn = common_evaluations::xn(&commons);
            h_eval(&quotients,&expressions,&y, &xn )
        };

        //let evaluation_len = evaluations_len(protocol, num_proof);
        // read evaluations of polys at z.
        //let evaluations = transcript::read_n_scalar(&mut transcript, evaluation_len);
        let proof = pcs::read_proof(params, protocol, &mut transcript);
        PlonkProof {
            commitments: witness_commitments,
            challenges,
            quotients,
            z,
            instance_evals: vector::empty(),
            advice_evals,
            fixed_evals,
            random_poly_eval,
            permutations_common,
            permutations_evaluated,
            lookups_evaluated,
            pcs: proof
        }
    }


    fun check_instances(instances: &vector<vector<Scalar>>, num: u64) {
        let i = 0;
        let len = vector::length(instances);
        while (i < len) {
            assert!(vector::length(vector::borrow(instances, i)) == num, INVALID_INSTANCES);
            i = i + 1;
        }
    }

    fun read_commitment_and_challenges(
        transcript: &mut Transcript,
        num_in_phase: &vector<u64>,
        num_challenge_in_phase: &vector<u64>,
    ): (vector<Point>, vector<Scalar>) {
        let phase_len = vector::length(num_in_phase);
        let i = 0;
        let commitments = vector[];
        let challenges = vector[];
        while (i < phase_len) {
            vector::append(&mut commitments, transcript::read_n_point(transcript, *vector::borrow(num_in_phase, i)));
            vector::append(
                &mut challenges,
                transcript::squeeze_n_challenges(transcript, *vector::borrow(num_challenge_in_phase, i))
            );
            i = i + 1;
        };
        (commitments, challenges)
    }

    fun permutation_expressions(
        evaluted: &vector<PermutationEvaluatedSet>,
        protocol: &Protocol,
        permutations_common: &vector<Scalar>,
        advice_evals: &vector<Scalar>, fixed_evals: &vector<Scalar>, instance_evals: &vector<Scalar>,
        l_0: &Scalar, l_last: &Scalar, l_blind: &Scalar, beta: &Scalar, gamma: &Scalar, x: &Scalar
    ): vector<Scalar> {
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
                    let permutation_eval = vector::borrow(permutations_common, j);
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
                    current_delta = scalar::mul(*current_delta, *scalar::delta());
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

    public fun h_eval(h_commitments: &vector<Point>, expressions: &vector<Scalar>, y: &Scalar, xn: &Scalar): EvaluatedH {
        let i = 0;
        let len = vector::length(expressions);
        let h_eval = scalar::zero();
        while (i < len) {
            let v = vector::borrow(expressions, i);
            h_eval = scalar::add(&scalar::mul(&h_eval, y), v);
            i=i+1;
        };
        h_eval = scalar::mul(&h_eval, &scalar::invert(&scalar::sub(xn, &scalar::one())));

        let msm = msm::empty_msm();
        let i = vector::length(h_commitments);
        while (i > 0) {
            i = i - 1;
            // TODO: change to pop?
            let commitment = vector::borrow(h_commitments, i);
            msm::scale(&mut msm, xn);
            msm::append_term(&mut msm, scalar::one(), *commitment);
        };
        EvaluatedH {
            expected_h_eval: h_eval,
            h_commitment: msm
        }
    }
}

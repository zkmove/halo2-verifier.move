module halo2_verifier::plonk_proof {
    use halo2_verifier::protocol::{Protocol, transcript_initial_state, query_instance, instance_queries, num_challenges};
    use halo2_verifier::scalar::Scalar;
    use halo2_verifier::transcript::{Transcript};
    use std::vector;
    use halo2_verifier::protocol;
    use halo2_verifier::transcript;
    use halo2_verifier::point::G1Affine;
    use halo2_verifier::pcs;
    use halo2_verifier::params::Params;
    use halo2_verifier::pcs::Proof;
    use halo2_verifier::verify_key::VerifyingKey;
    use std::vector::{map_ref, map, enumerate_ref};
    use std::option::Option;
    use halo2_verifier::common_evaluations;
    use halo2_verifier::params;
    use halo2_verifier::scalar;
    use halo2_verifier::column;
    use halo2_verifier::msm::MSM;
    use halo2_verifier::vec_utils::repeat;
    use halo2_verifier::point;
    use halo2_verifier::lookup;
    use halo2_verifier::lookup::PermutationCommitments;
    use halo2_verifier::permutation;
    use halo2_verifier::vanishing;
    use halo2_verifier::query::VerifierQuery;
    use halo2_verifier::query;
    use halo2_verifier::domain;
    use halo2_verifier::verify_key;

    const INVALID_INSTANCES: u64 = 100;

    struct PlonkProof has copy, drop {
        //commitments: vector<G1Affine>,
        challenges: vector<Scalar>,
        //quotients: vector<G1Affine>,

        instance_evals: vector<vector<Scalar>>,
        advice_evals: vector<vector<Scalar>>,
        fixed_evals: vector<Scalar>,
        random_poly_eval: Scalar,
        //permutations_common: vector<Scalar>,
        //permutations_evaluated: vector<vector<PermutationEvaluatedSet>>,
        //lookups_evaluated: vector<vector<LookupEvaluated>>,
        z: Scalar,
        pcs: Proof,
    }

    struct PermutationEvaluatedSet has copy, drop {
        permutation_product_commitment: G1Affine,
        permutation_product_eval: Scalar,
        permutation_product_next_eval: Scalar,
        permutation_product_last_eval: Option<Scalar>,
    }

    struct EvaluatedH has copy, drop {
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
        // check_instances(&instances, protocol::num_instance(protocol));
        let instance_commitments: vector<vector<G1Affine>> = if (protocol::query_instance(protocol)) {
            // TODO: not implemented for ipa
            abort 100
        } else {
            map_ref(&instances, |i| vector::empty())
        };
        let num_proof = vector::length(&instances);
        transcript::common_scalar(&mut transcript, transcript_initial_state(protocol));

        if (protocol::query_instance(protocol)) {
            // TODO: impl for ipa
            abort 100
        } else {
            // use while loop to keep the code more portable.
            // if protable is not the priority, can use for_each instead in aptos.
            let i = 0;
            while (i < num_proof) {
                let instance = vector::borrow(&instances, i);
                let col_len = vector::length(instance);
                let j = 0;
                while (j < col_len) {
                    let col_values = vector::borrow(instance, j);
                    let value_len = vector::length(col_values);
                    let k = 0;
                    while (k < value_len) {
                        transcript::common_scalar(&mut transcript, *vector::borrow(col_values, k));
                        k = k + 1;
                    };
                    j = j + 1;
                };
                i = i + 1;
            };

            // in aptos, we can use for_each_ref
            // for_each_ref(&instances, |instance| {
            //     let instance: vector<vector<Scalar>> = instance;
            //     for_each_ref(instance, |ic| {
            //         for_each_ref(ic, |i| {
            //             transcript::common_scalar(&mut transcript, *i);
            //         });
            //     });
            // });
        };

        // read advice commitments and challenges
        let advice_commitments = repeat(
            repeat(point::default(), protocol::num_advice_columns(protocol)),
            num_proof
        );
        let challenges = repeat(scalar::zero(), num_challenges(protocol));
        {
            let num_phase = protocol::num_phase(protocol);
            let i = 0;
            while (i < num_phase) {
                let j = 0;
                while (j < num_proof) {
                    let advice_columns_phase = protocol::advice_column_phase(protocol);
                    let advice_commitments = vector::borrow_mut(&mut advice_commitments, j);
                    let k = 0;
                    let columns_len = protocol::num_advice_columns(protocol);
                    while (k < columns_len) {
                        if (*vector::borrow(advice_columns_phase, k) == i) {
                            *vector::borrow_mut(advice_commitments, k) = transcript::read_point(&mut transcript);
                        };
                        k = k + 1;
                    };
                    j = j + 1;
                };
                let challenge_phase = protocol::challenge_phase(protocol);
                let challenge_len = num_challenges(protocol);
                let j = 0;
                while (j < challenge_len) {
                    if (*vector::borrow(challenge_phase, j) == i) {
                        *vector::borrow_mut(&mut challenges, j) = transcript::squeeze_challenge(&mut transcript);
                    };
                    j = j + 1;
                };

                i = i + 1;
            }
        };

        let theta = transcript::squeeze_challenge(&mut transcript);


        // lookup commitments
        let lookups_permuted = lookup_read_permuted_commitments(
            &mut transcript,
            num_proof,
            protocol::num_lookup(protocol)
        );
        let beta = transcript::squeeze_challenge(&mut transcript);
        let gamma = transcript::squeeze_challenge(&mut transcript);
        let permutations_committed = permutation_read_product_commitments(
            &mut transcript,
            num_proof,
            protocol::num_permutation_z(protocol)
        );
        let lookups_committed = lookup_read_product_commitments(lookups_permuted, &mut transcript);
        let random_poly_committed = transcript::read_point(&mut transcript);
        let y = transcript::squeeze_challenge(&mut transcript);

        let quotients = vanishing::read_commitments_after_y(
            &mut transcript,
            protocol::num_chunks_of_quotient(protocol, num_proof)
        );
        // - eval at point: z
        let z = transcript::squeeze_challenge(&mut transcript);

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
            // TODO: calculate instances eval
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
        let permutations_common =permutation::evalute_common(&mut transcript,protocol::num_permutation_fixed(protocol));
        let permutations_evaluated =
            map<permutation::Commited, permutation::Evaluted>(
                permutations_committed,
                |product_commitments|permutation::evaluate(product_commitments, &mut transcript)
            );

        let lookups_evaluated = map_ref<vector<lookup::Commited>, vector<lookup::Evaluated>>(
            &lookups_committed,
            |commited| {
                map_ref<lookup::Commited, lookup::Evaluated>(commited, |c| {
                    lookup::evaluate(c, &mut transcript)
                })
            }
        );


        let vanishing = {
            let commons = common_evaluations::new(params::k(params), z);
            let expressions = vector::empty();
            let i = 0;
            while (i < num_proof) {
                // todo: calculate gates' evals result
                let gate_expressions = vector::empty();
                let permutation_expressions = permutation::expressions(
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
                let lookup_expressions: vector<Scalar> = vector::empty();

                vector::append(&mut expressions, gate_expressions);
                vector::append(&mut expressions, permutation_expressions);
                vector::append(&mut expressions, lookup_expressions);
                i = i + 1;
            };
            let xn = common_evaluations::xn(&commons);

            vanishing::h_eval(quotients, &expressions, &y, &xn)
        };


        // mapping query with it commitments
        let queries = vector::empty();
        {
            let i = 0;
            while (i < num_proof) {
                queries(protocol,
                    &mut queries,
                    &z,
                    vector::borrow(&instance_commitments, i),
                    vector::borrow(&instance_evals, i),
                    vector::borrow(&advice_commitments, i),
                    vector::borrow(&advice_evals, i),
                    vector::borrow(&permutations_evaluated, i),
                    vector::borrow(&lookups_evaluated, i),
                );
                i = i + 1;
            };

            // fixed queries
            let fixed_commitments = verify_key::fixed_commitments(vk);
            enumerate_ref(protocol::fixed_queries(protocol), |query_index, query|{
                let (column, rotation) = protocol::from_fixed_query(query);
                vector::push_back(&mut queries,
                    query::new_commitment(
                        *vector::borrow(fixed_commitments, (column::column_index(column) as u64)),
                        domain::rotate_omega(protocol::domain(protocol), &z, rotation),
                        *vector::borrow(&fixed_evals, query_index),
                    ));
            });

            permutation::common_queries(&permutations_common, &mut queries, verify_key::permutation_commitments(vk), &z);
            vanishing::queries(vanishing, &mut queries, &z);
        };


        //let evaluation_len = evaluations_len(protocol, num_proof);
        // read evaluations of polys at z.
        //let evaluations = transcript::read_n_scalar(&mut transcript, evaluation_len);
        let proof = pcs::read_proof(params, protocol, &mut transcript);
        PlonkProof {
            //commitments: witness_commitments,
            challenges,
            //quotients,
            z,
            instance_evals: vector::empty(),
            advice_evals,
            fixed_evals,
            random_poly_eval,
            //permutations_common,
            //permutations_evaluated,
            //lookups_evaluated,
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


    // fun read_commitment_and_challenges(
    //     transcript: &mut Transcript,
    //     num_in_phase: &vector<u64>,
    //     num_challenge_in_phase: &vector<u64>,
    // ): (vector<G1Affine>, vector<Scalar>) {
    //     let phase_len = vector::length(num_in_phase);
    //     let i = 0;
    //     let commitments = vector[];
    //     let challenges = vector[];
    //     while (i < phase_len) {
    //         vector::append(&mut commitments, transcript::read_n_point(transcript, *vector::borrow(num_in_phase, i)));
    //         vector::append(
    //             &mut challenges,
    //             transcript::squeeze_n_challenges(transcript, *vector::borrow(num_challenge_in_phase, i))
    //         );
    //         i = i + 1;
    //     };
    //     (commitments, challenges)
    // }

    fun lookup_read_permuted_commitments(
        transcript: &mut Transcript,
        num_proof: u64,
        num_lookup: u64
    ): vector<vector<PermutationCommitments>> {
        let lookups_permuted = vector::empty(); // (A', S')
        let i = 0;
        while (i < num_proof) {
            let j = 0;
            let result = vector::empty();
            while (j < num_lookup) {
                vector::push_back(&mut result, lookup::read_permuted_commitments(transcript));
                j = j + 1;
            };
            vector::push_back(&mut lookups_permuted, result);
            i = i + 1;
        };
        lookups_permuted
    }

    fun lookup_read_product_commitments(
        lookups_permuted: vector<vector<PermutationCommitments>>,
        transcript: &mut Transcript
    ): vector<vector<lookup::Commited>> {
        map(lookups_permuted, |lookups| map(lookups, |l| lookup::read_product_commitment(l, transcript)))
    }

    fun permutation_read_product_commitments(
        transcript: &mut Transcript,
        num_proof: u64,
        num_permutation_z: u64
    ): vector<permutation::Commited> {
        let i = 0;
        let result = vector::empty();
        while (i < num_proof) {
            vector::push_back(&mut result, permutation::read_product_commitments(transcript, num_permutation_z));
            i = i + 1;
        };

        result
    }

    fun queries(
        protocol: &Protocol,
        queries: &mut vector<VerifierQuery>,
        x: &Scalar,
        instance_commitments: &vector<G1Affine>,
        instance_evals: &vector<Scalar>,
        advice_commitments: &vector<G1Affine>,
        advice_evals: &vector<Scalar>,
        permutation: &permutation::Evaluted,
        lookups: &vector<lookup::Evaluated>
    ) {
        // instance queries
        if (protocol::query_instance(protocol)) {
            enumerate_ref(protocol::instance_queries(protocol), |query_index, query| {
                let (column, rotation) = protocol::from_instance_query(query);
                vector::push_back(queries,
                    query::new_commitment(
                        *vector::borrow(instance_commitments, (column::column_index(column) as u64)),
                        domain::rotate_omega(protocol::domain(protocol), x, rotation),
                        *vector::borrow(instance_evals, query_index),
                    ));
            });
        };

        // advice queries
        enumerate_ref(protocol::advice_queries(protocol), |query_index, query|{
            let (column, rotation) = protocol::from_advice_query(query);
            vector::push_back(queries,
                query::new_commitment(
                    *vector::borrow(advice_commitments, (column::column_index(column) as u64)),
                    domain::rotate_omega(protocol::domain(protocol), x, rotation),
                    *vector::borrow(advice_evals, query_index),
                ));
        });

        permutation::queries(permutation, queries, protocol, x);
        lookup::queries(lookups, queries, protocol, x);

    }
}

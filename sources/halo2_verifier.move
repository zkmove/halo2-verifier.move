module halo2_verifier::halo2_verifier {
    use std::vector::{Self, map_ref, map, enumerate_ref};

    use aptos_std::crypto_algebra;

    use halo2_verifier::bn254_types::G1;
    use halo2_verifier::column;
    use halo2_verifier::domain;
    use halo2_verifier::expression;
    use halo2_verifier::gwc;
    use halo2_verifier::lookup::{Self, PermutationCommitments};
    use halo2_verifier::params::Params;
    use halo2_verifier::permutation;
    use halo2_verifier::point::{Self, Point};
    use halo2_verifier::protocol::{Self, Protocol, query_instance, instance_queries, num_challenges, Gate, Lookup, blinding_factors};
    use halo2_verifier::query::{Self, VerifierQuery};
    use halo2_verifier::rotation;
    use halo2_verifier::scalar::{Self, Scalar, inner, from_element};
    use halo2_verifier::transcript::{Self, Transcript};
    use halo2_verifier::vanishing;
    use halo2_verifier::vec_utils::repeat;
    use halo2_verifier::verify_key::{Self, VerifyingKey};

    const INVALID_INSTANCES: u64 = 100;

    public fun verify(
        params: &Params,
        vk: &VerifyingKey,
        protocol: &Protocol,
        instances: vector<vector<vector<Scalar>>>,
        proof: vector<u8>
    ): bool {
        let transcript = transcript::init(proof);
        verify_inner(params, vk, protocol, instances, transcript)
    }

    fun verify_inner(
        params: &Params,
        vk: &VerifyingKey,
        protocol: &Protocol,
        instances: vector<vector<vector<Scalar>>>,
        transcript: Transcript
    ): bool {
        // check_instances(&instances, protocol::num_instance(protocol));
        let instance_commitments: vector<vector<Point<G1>>> = if (protocol::query_instance(protocol)) {
            // TODO: not implemented for ipa
            abort 100
        } else {
            map_ref(&instances, |i| vector::empty())
        };
        let num_proof = vector::length(&instances);
        transcript::common_scalar(&mut transcript, verify_key::transcript_repr(vk));

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
        let vanishing = vanishing::read_commitments_before_y(&mut transcript);
        let y = transcript::squeeze_challenge(&mut transcript);
        let vanishing = vanishing::read_commitments_after_y(
            vanishing,
            &mut transcript,
            protocol::quotient_poly_degree(protocol)
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
        let vanishing = vanishing::evaluate_after_x(vanishing, &mut transcript);
        let permutations_common = permutation::evalute_common(
            &mut transcript,
            vector::length(protocol::permutation_columns(protocol))
        );
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

        let z_n = scalar::pow(inner(&z), domain::n(protocol::domain(protocol)));
        let vanishing = {
            // -(blinding_factor+1)..=0
            let blinding_factors = blinding_factors(protocol);
            let l_evals = domain::l_i_range(
                protocol::domain(protocol),
                inner(&z),
                &z_n,
                rotation::prev((blinding_factors as u32) + 1),
                rotation::next(1)
            );
            // todo: assert len(l_evals) = blinding_factor+2
            let l_last = scalar::from_element(*vector::borrow(&l_evals, 0));
            let l_0 = scalar::from_element(*vector::borrow(&l_evals, blinding_factors + 1));
            let l_blind = {
                let i = 1;
                let len = blinding_factors + 2;
                let result = crypto_algebra::zero();
                while (i < len) {
                    result = crypto_algebra::add(&result, vector::borrow(&l_evals, i));
                };
                scalar::from_element(result)
            };

            let expressions = vector::empty();
            let i = 0;
            while (i < num_proof) {
                let gate_expressions = evaluate_gates(
                    protocol::gates(protocol),
                    vector::borrow(&advice_evals, i),
                    &fixed_evals,
                    vector::borrow(&instance_evals, i),
                    &challenges,
                );

                let permutation_expressions = permutation::expressions(
                    vector::borrow(&permutations_evaluated, i),
                    protocol,
                    &permutations_common,
                    vector::borrow(&advice_evals, i),
                    &fixed_evals,
                    vector::borrow(&instance_evals, i),
                    &l_0, &l_last, &l_blind,
                    &beta,
                    &gamma,
                    &z,
                );
                let lookup_expressions: vector<Scalar> = evaluate_lookups(
                    vector::borrow(&lookups_evaluated, i),
                    protocol::lookups(protocol),
                    protocol,
                    vector::borrow(&advice_evals, i),
                    &fixed_evals,
                    vector::borrow(&instance_evals, i),
                    &challenges,
                    &l_0, &l_last, &l_blind,
                    &theta, &beta, &gamma
                );
                // TODO: optimize the vector
                vector::append(&mut expressions, gate_expressions);
                vector::append(&mut expressions, permutation_expressions);
                vector::append(&mut expressions, lookup_expressions);
                i = i + 1;
            };

            vanishing::h_eval(vanishing, &expressions, &y, &from_element(z_n))
        };


        // mapping evaluations with it commitments
        let queries = vector::empty();
        {
            vector::reverse(&mut permutations_evaluated);
            vector::reverse(&mut lookups_evaluated);
            let i = 0;
            while (i < num_proof) {
                queries(protocol,
                    &mut queries,
                    &z,
                    vector::borrow(&instance_commitments, i),
                    vector::borrow(&instance_evals, i),
                    vector::borrow(&advice_commitments, i),
                    vector::borrow(&advice_evals, i),
                    vector::pop_back(&mut permutations_evaluated),
                    vector::pop_back(&mut lookups_evaluated),
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

            permutation::common_queries(
                permutations_common,
                &mut queries,
                *verify_key::permutation_commitments(vk),
                &z
            );
            vanishing::queries(vanishing, &mut queries, &z);
        };


        //let evaluation_len = evaluations_len(protocol, num_proof);
        // read evaluations of polys at z.
        //let evaluations = transcript::read_n_scalar(&mut transcript, evaluation_len);
        gwc::verify(params, &mut transcript, &queries)
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
    // ): (vector<Point<G1>>, vector<Scalar>) {
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
        instance_commitments: &vector<Point<G1>>,
        instance_evals: &vector<Scalar>,
        advice_commitments: &vector<Point<G1>>,
        advice_evals: &vector<Scalar>,
        permutation: permutation::Evaluted,
        lookups: vector<lookup::Evaluated>
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
        lookup::queries(&lookups, queries, protocol, x);
    }

    fun evaluate_gates(gates: &vector<Gate>,
                       advice_evals: &vector<Scalar>,
                       fixed_evals: &vector<Scalar>,
                       instance_evals: &vector<Scalar>, challenges: &vector<Scalar>): vector<Scalar> {
        let result = vector::empty();
        let gate_len = vector::length(gates);
        let i = 0;
        while (i < gate_len) {
            let gate = vector::borrow(gates, i);
            let gate_polys = protocol::polys(gate);
            let polys_len = vector::length(gate_polys);
            let j = 0;
            while (j < polys_len) {
                let poly = vector::borrow(gate_polys, j);
                let poly_eval = expression::evaluate(poly, advice_evals, fixed_evals, instance_evals, challenges);
                vector::push_back(&mut result, poly_eval);
                j = j + 1;
            };
            i = i + 1;
        };

        result
    }

    fun evaluate_lookups(
        lookup_evaluates: &vector<lookup::Evaluated>,
        lookup: &vector<Lookup>,
        protocol: &Protocol,
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
        let result = vector::empty();
        let i = 0;
        let lookup_len = vector::length(lookup_evaluates);
        while (i < lookup_len) {
            i = i + 1;
            vector::append(&mut result,
                lookup::expression(
                    vector::borrow(lookup_evaluates, i),
                    vector::borrow(lookup, i),
                    advice_evals,
                    fixed_evals,
                    instance_evals, challenges, l_0, l_last, l_blind, theta, beta, gamma
                ));
        };
        result
    }
}
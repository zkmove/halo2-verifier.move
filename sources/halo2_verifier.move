module halo2_verifier::halo2_verifier {
    use std::vector::{Self, map_ref, map, enumerate_ref};

    use aptos_std::bn254_algebra::{G1, Fr};
    use aptos_std::crypto_algebra::{Self, Element};

    use halo2_verifier::bn254_utils;
    use halo2_verifier::column;
    use halo2_verifier::domain::{Self, Domain};
    use halo2_verifier::expression::{Self, Expression};
    use halo2_verifier::gwc;
    use halo2_verifier::lookup::{Self, PermutationCommitments};
    use halo2_verifier::params::Params;
    use halo2_verifier::permutation;
    use halo2_verifier::protocol::{Self, Protocol,  query_instance, instance_queries, num_challenges, Lookup, blinding_factors, num_advice_columns};
    use halo2_verifier::query::{Self, VerifierQuery};
    use halo2_verifier::i32;
    use halo2_verifier::transcript::{Self, Transcript};
    use halo2_verifier::vanishing;
    use halo2_verifier::vec_utils::repeat;
    use halo2_verifier::column_query;
    use halo2_verifier::column_query::ColumnQuery;

    const INVALID_INSTANCES: u64 = 100;

    public fun verify(
        params: &Params,
        protocol: &Protocol,
        instances: vector<vector<vector<Element<Fr>>>>,
        proof: vector<u8>
    ): bool {
        let transcript = transcript::init(proof);
        verify_inner(params, protocol, instances, transcript)
    }

    fun verify_inner(
        params: &Params,
        protocol: &Protocol,
        instances: vector<vector<vector<Element<Fr>>>>,
        transcript: Transcript
    ): bool {
        let domain = protocol::domain(protocol);
        // check_instances(&instances, protocol::num_instance(protocol));
        let instance_commitments: vector<vector<Element<G1>>> = if (protocol::query_instance(protocol)) {
            // TODO: not implemented for ipa
            abort 100
        } else {
            map_ref(&instances, |i| vector::empty())
        };
        let num_proof = vector::length(&instances);

        transcript::common_scalar(&mut transcript, protocol::transcript_repr(protocol));
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
            //     let instance: vector<vector<Element<Fr>>> = instance;
            //     for_each_ref(instance, |ic| {
            //         for_each_ref(ic, |i| {
            //             transcript::common_scalar(&mut transcript, *i);
            //         });
            //     });
            // });
        };
        // read advice commitments and challenges
        let advice_commitments = if (num_advice_columns(protocol) == 0) {
            vector::empty()
        } else {
            repeat(
                repeat(crypto_algebra::zero(), protocol::num_advice_columns(protocol)),
                num_proof
            )
        };
        let challenges = if (num_challenges(protocol) == 0) {
            vector::empty()
        } else {
            repeat(crypto_algebra::zero(), num_challenges(protocol))
        };
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
            domain::quotient_poly_degree(&domain)
        );
        // - eval at point: z
        let z = transcript::squeeze_challenge(&mut transcript);
        let z_n = bn254_utils::pow_u32(&z, domain::n(&domain));

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
            let instance_queries = instance_queries(protocol);
            let min_rotation = i32::zero();
            let max_rotation = i32::zero();

            vector::for_each_ref(instance_queries, |q| {
                let q: &ColumnQuery = q;
                let rotation = column_query::rotation(q);
                // GREATER_THAN = 2
                if (i32::compare(&min_rotation, rotation) == 2) {
                    min_rotation = *rotation;
                }
                else if (i32::compare(rotation, &max_rotation) == 2) {
                    max_rotation = *rotation;
                }
            });

            let max_instance_len = 0;
            vector::for_each_ref(&instances, |i| {
                vector::for_each_ref(i, |r| {
                    let length = vector::length(r);
                    if (length > max_instance_len) {
                        max_instance_len = length;
                    }
                })
            });

            let l_i_s = domain::l_i_range(
                &domain,
                &z,
                &z_n,
                i32::neg(&max_rotation),
                i32::from((max_instance_len as u32) + i32::abs(&min_rotation))
            );


            vector::map_ref(&instances, |instances| {
                vector::map_ref(instance_queries, |q| {
                    let q: &ColumnQuery = q;
                    let column = column_query::column(q);
                    let rotation = column_query::rotation(q);
                    let column_index = (column::column_index(column) as u64);
                    let instances = vector::borrow(instances, column_index);
                    let instances_len = vector::length(instances);
                    let offset = (i32::abs(&i32::sub(&max_rotation, rotation)) as u64);

                    let i = 0;
                    let acc = crypto_algebra::zero();
                    while (i < instances_len) {
                        let val = vector::borrow(instances, i);
                        let l = *vector::borrow(&l_i_s, offset + i);
                        acc = crypto_algebra::add(&acc, &crypto_algebra::mul(val, &l));
                        i = i + 1;
                    };

                    acc
                })
            })
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

        let vanishing = {
            // -(blinding_factor+1)..=0
            let blinding_factors = blinding_factors(protocol);
            let l_evals = domain::l_i_range(
                &domain,
                &z,
                &z_n,
                i32::neg_from((blinding_factors as u32) + 1),
                i32::from(1)
            );
            // todo: assert len(l_evals) = blinding_factor+2
            let l_last = *vector::borrow(&l_evals, 0);
            let l_0 = *vector::borrow(&l_evals, blinding_factors + 1);
            let l_blind = {
                let i = 1;
                let len = blinding_factors + 1;
                let result = crypto_algebra::zero();
                while (i < len) {
                    result = crypto_algebra::add(&result, vector::borrow(&l_evals, i));
                    i=i+1;
                };
                result
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
                let lookup_expressions: vector<Element<Fr>> = evaluate_lookups(
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

            vanishing::h_eval(vanishing, &expressions, &y, &z_n)
        };


        // mapping evaluations with it commitments
        let queries = vector::empty();
        {
            vector::reverse(&mut permutations_evaluated);
            vector::reverse(&mut lookups_evaluated);
            let i = 0;
            while (i < num_proof) {
                queries(protocol,
                    &domain,
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
            let fixed_commitments = protocol::fixed_commitments(protocol);
            enumerate_ref(protocol::fixed_queries(protocol), |query_index, query|{
                let column = column_query::column(query);
                let  rotation = column_query::rotation(query);

                vector::push_back(&mut queries,
                    query::new_commitment(
                        *vector::borrow(fixed_commitments, (column::column_index(column) as u64)),
                        domain::rotate_omega(&domain, &z, rotation),
                        *vector::borrow(&fixed_evals, query_index),
                    ));
            });

            permutation::common_queries(
                permutations_common,
                &mut queries,
                *protocol::permutation_commitments(protocol),
                &z
            );
            vanishing::queries(vanishing, &mut queries, &z);
        };


        gwc::verify(params, &mut transcript, &queries)
    }


    fun check_instances(instances: &vector<vector<Element<Fr>>>, num: u64) {
        let i = 0;
        let len = vector::length(instances);
        while (i < len) {
            assert!(vector::length(vector::borrow(instances, i)) == num, INVALID_INSTANCES);
            i = i + 1;
        }
    }

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
        domain: &Domain,
        queries: &mut vector<VerifierQuery>,
        x: &Element<Fr>,
        instance_commitments: &vector<Element<G1>>,
        instance_evals: &vector<Element<Fr>>,
        advice_commitments: &vector<Element<G1>>,
        advice_evals: &vector<Element<Fr>>,
        permutation: permutation::Evaluted,
        lookups: vector<lookup::Evaluated>
    ) {
        // instance queries
        if (protocol::query_instance(protocol)) {
            enumerate_ref(protocol::instance_queries(protocol), |query_index, query| {
                let column = column_query::column(query);
                let  rotation = column_query::rotation(query);

                vector::push_back(queries,
                    query::new_commitment(
                        *vector::borrow(instance_commitments, (column::column_index(column) as u64)),
                        domain::rotate_omega(domain, x, rotation),
                        *vector::borrow(instance_evals, query_index),
                    ));
            });
        };

        // advice queries
        enumerate_ref(protocol::advice_queries(protocol), |query_index, query|{
            let column = column_query::column(query);
            let  rotation = column_query::rotation(query);

            vector::push_back(queries,
                query::new_commitment(
                    *vector::borrow(advice_commitments, (column::column_index(column) as u64)),
                    domain::rotate_omega(domain, x, rotation),
                    *vector::borrow(advice_evals, query_index),
                ));
        });

        permutation::queries(permutation, queries, protocol, domain, x);
        lookup::queries(&lookups, queries, protocol, domain, x);
    }

    fun evaluate_gates(gates: &vector<Expression>,
                       advice_evals: &vector<Element<Fr>>,
                       fixed_evals: &vector<Element<Fr>>,
                       instance_evals: &vector<Element<Fr>>, challenges: &vector<Element<Fr>>): vector<Element<Fr>> {
        let result = vector::empty();
        let gate_len = vector::length(gates);
        let i = 0;
        while (i < gate_len) {
            let gate = vector::borrow(gates, i);
            let poly_eval = expression::evaluate(gate, advice_evals, fixed_evals, instance_evals, challenges);
            vector::push_back(&mut result, poly_eval);

            i = i + 1;
        };

        result
    }

    fun evaluate_lookups(
        lookup_evaluates: &vector<lookup::Evaluated>,
        lookup: &vector<Lookup>,
        _protocol: &Protocol,
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

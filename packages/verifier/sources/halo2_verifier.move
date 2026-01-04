module halo2_verifier::halo2_verifier {
    use std::option;
    use std::vector::{Self, map_ref, map, enumerate_ref};
    use aptos_std::bn254_algebra::{G1, Fr};
    use aptos_std::crypto_algebra::{Self, Element};
    use halo2_common::bn254_utils::{Self, deserialize_g1, deserialize_fr};
    use halo2_common::column;
    use halo2_common::column_query::{Self, ColumnQuery};
    use halo2_common::domain::{Self, Domain};
    use halo2_common::i32;
    use halo2_common::params::Params;
    use halo2_common::query::{Self, VerifierQuery};
    use halo2_common::vec_utils::repeat;

    use halo2_verifier::gwc;
    use halo2_verifier::lookup::{Self, PermutationCommitments};
    use halo2_verifier::shuffle;
    use halo2_verifier::permutation;
    use halo2_verifier::protocol::{Self, Protocol, instance_queries, num_challenges, Lookup, Shuffle, blinding_factors, num_advice_columns, use_u8_fields, use_u8_queries};
    use halo2_verifier::transcript::{Self, Transcript};
    use halo2_verifier::vanishing;
    use halo2_verifier::shplonk;
    use halo2_verifier::evaluator;
    use halo2_verifier::public_inputs::{Self, PublicInputs};
    // use std::debug;
    // use std::string::{Self, String, utf8};
    // use std::bn254_algebra::FormatFrLsb;


    const INVALID_INSTANCES: u64 = 100;
    const GWC: u8 = 0;
    const SHPLONK: u8 = 1;

    public fun verify_single(
        params: &Params,
        protocol: &Protocol,
        instances: vector<vector<vector<u8>>>,
        proof: vector<u8>,
        kzg_variant: u8,
    ): bool {
        let instances = vector::map_ref(&instances, |column_instances| {
            vector::map_ref<vector<u8>, Element<Fr>>(column_instances, |instance| {
                option::destroy_some( bn254_utils::deserialize_fr(instance))
            })
        });
        verify(params, protocol, vector::singleton(instances), proof, kzg_variant)
    }

    public fun verify_single_vm(
        params: &Params,
        protocol: &Protocol,
        instances: PublicInputs<Fr>,
        proof: vector<u8>,
        kzg_variant: u8,
    ): bool {

        let instances = public_inputs::as_vec(&instances);
        verify(params, protocol, vector::singleton(instances), proof, kzg_variant)
    }

    /// `verify` function verify the proof in transcript with given params, protocol, and instances.
    /// instances is multi instances of the circuit.
    public fun verify(
        params: &Params,
        protocol: &Protocol,
        instances: vector<vector<vector<Element<Fr>>>>,
        proof: vector<u8>,
        kzg_variant: u8,
    ): bool {
        let transcript = transcript::init(proof);
        let domain = protocol::domain(protocol);
        // TODO: check instance?
        // check_instances(&instances, protocol::num_instance(protocol));
        let num_proof = vector::length(&instances);

        transcript::common_scalar(&mut transcript,  option::destroy_some( bn254_utils::deserialize_fr(protocol::vk_transcript_repr(protocol))));
        vector::for_each_ref(&instances, |instance| {
            vector::for_each_ref(instance, |ic| {
                vector::for_each_ref(ic, |i| {
                    transcript::common_scalar(&mut transcript, *i);
                });
            });
        });

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
        let shuffles_committed = shuffle_read_product_commitments(
            &mut transcript,
            num_proof,
            protocol::num_shuffle(protocol)
        );
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

        let instance_evals = vector::map_ref(&instances, |instances| {
            vector::map_ref(instance_queries, |q| {
                let q: &ColumnQuery = q;
                let column = column_query::column(q);
                let rotation = column_query::rotation(q);
                let column_index = (column::column_index(column) as u64);
                let instances = vector::borrow(instances, column_index);
                let offset = (i32::abs(&i32::sub(&max_rotation, rotation)) as u64);

                let acc = crypto_algebra::zero();
                vector::enumerate_ref(instances, |i, val| {
                    let l = *vector::borrow(&l_i_s, offset + i);
                    acc = crypto_algebra::add(&acc, &crypto_algebra::mul(val, &l));
                });

                acc
            })
        });

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

        let shuffles_evaluated = map_ref<vector<shuffle::Commited>, vector<shuffle::Evaluated>>(
            &shuffles_committed,
            |commited| {
                map_ref<shuffle::Commited, shuffle::Evaluated>(commited, |c| {
                    shuffle::evaluate(c, &mut transcript)
                })
            }
        );

        let vanishing = {
            // -(blinding_factor+1)..=0
            let blinding_factors = blinding_factors(protocol);
            let blinding_evals = domain::l_i_range(
                &domain,
                &z,
                &z_n,
                i32::neg_from((blinding_factors as u32) + 1),
                i32::from(1)
            );
            // todo: assert len(l_evals) = blinding_factor+2
            let l_last = *vector::borrow(&blinding_evals, 0);
            let l_0 = *vector::borrow(&blinding_evals, blinding_factors + 1);
            let l_blind = {
                let i = 1;
                let len = blinding_factors + 1;
                let result = crypto_algebra::zero();
                while (i < len) {
                    result = crypto_algebra::add(&result, vector::borrow(&blinding_evals, i));
                    i = i + 1;
                };
                result
            };
            let coeff_pool = vector::map_ref(protocol::fields_pool(protocol), |e| option::destroy_some(deserialize_fr(e)));
            let expressions = vector::empty();
            let i = 0;
            let use_u8_fields = use_u8_fields(protocol);
            let use_u8_queries = use_u8_queries(protocol);
            while (i < num_proof) {
                evaluate_gates(
                    protocol::gates(protocol),
                    use_u8_fields,
                    use_u8_queries,
                    &coeff_pool,
                    vector::borrow(&advice_evals, i),
                    &fixed_evals,
                    vector::borrow(&instance_evals, i),
                    &challenges,
                    &mut expressions,
                );

                permutation::expressions(
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
                    &mut expressions,
                );
                evaluate_lookups(
                    vector::borrow(&lookups_evaluated, i),
                    protocol::lookups(protocol),
                    use_u8_fields,
                    use_u8_queries,
                    &coeff_pool,
                    vector::borrow(&advice_evals, i),
                    &fixed_evals,
                    vector::borrow(&instance_evals, i),
                    &challenges,
                    &l_0, &l_last, &l_blind,
                    &theta, &beta, &gamma,
                    &mut expressions,
                );
                evaluate_shuffles(
                    vector::borrow(&shuffles_evaluated, i),
                    protocol::shuffles(protocol),
                    use_u8_fields,
                    use_u8_queries,
                    &coeff_pool,
                    vector::borrow(&advice_evals, i),
                    &fixed_evals,
                    vector::borrow(&instance_evals, i),
                    &challenges,
                    &l_0, &l_last, &l_blind,
                    &theta, &gamma,
                    &mut expressions,
                );
                i = i + 1;
            };

            vanishing::h_eval(vanishing, &expressions, &y, &z_n)
        };

        // mapping evaluations with it commitments
        let queries = vector::empty();
        {
            vector::reverse(&mut permutations_evaluated);
            vector::reverse(&mut lookups_evaluated);
            vector::reverse(&mut shuffles_evaluated);
            let i = 0;
            while (i < num_proof) {
                queries(protocol,
                    &domain,
                    &mut queries,
                    &z,
                    vector::borrow(&advice_commitments, i),
                    vector::borrow(&advice_evals, i),
                    vector::pop_back(&mut permutations_evaluated),
                    vector::pop_back(&mut lookups_evaluated),
                    vector::pop_back(&mut shuffles_evaluated),
                );
                i = i + 1;
            };

            // fixed queries
            let fixed_commitments = map_ref(protocol::fixed_commitments(protocol), |c| option::destroy_some(deserialize_g1(c)));
            enumerate_ref(protocol::fixed_queries(protocol), |query_index, query| {
                let column = column_query::column(query);
                let rotation = column_query::rotation(query);

                vector::push_back(&mut queries,
                    query::new_commitment(
                        *vector::borrow(&fixed_commitments, (column::column_index(column) as u64)),
                        domain::rotate_omega(&domain, &z, rotation),
                        *vector::borrow(&fixed_evals, query_index),
                    ));
            });

            permutation::common_queries(
                permutations_common,
                &mut queries,
                map_ref(protocol::permutation_commitments(protocol), |c| option::destroy_some(deserialize_g1(c))),
                &z
            );
            vanishing::queries(vanishing, &mut queries, &z);
        };

        if (kzg_variant == GWC) {
            gwc::verify(params, &mut transcript, &queries)
        } else if (kzg_variant == SHPLONK) {
            shplonk::verify(params, &mut transcript, &queries)
        } else {
            abort 400
        }
    }


    fun check_instances(instances: &vector<vector<Element<Fr>>>, num: u64) {
        vector::for_each_ref(instances, |i| {
            assert!(vector::length(i) == num, INVALID_INSTANCES);
        });
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

    fun shuffle_read_product_commitments(
        transcript: &mut Transcript,
        num_proof: u64,
        num_shuffle: u64
    ): vector<vector<shuffle::Commited>> {
        let shuffles = vector::empty(); // (A, S)
        let i = 0;
        while (i < num_proof) {
            let j = 0;
            let result = vector::empty();
            while (j < num_shuffle) {
                vector::push_back(&mut result, shuffle::shuffles_read_product_commitments(transcript));
                j = j + 1;
            };
            vector::push_back(&mut shuffles, result);
            i = i + 1;
        };
        shuffles
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
        // instance_commitments: &vector<Element<G1>>,
        // instance_evals: &vector<Element<Fr>>,
        advice_commitments: &vector<Element<G1>>,
        advice_evals: &vector<Element<Fr>>,
        permutation: permutation::Evaluted,
        lookups: vector<lookup::Evaluated>,
        shuffles: vector<shuffle::Evaluated>,

    ) {
        /*
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
        */

        // advice queries
        enumerate_ref(protocol::advice_queries(protocol), |query_index, query| {
            let column = column_query::column(query);
            let rotation = column_query::rotation(query);

            vector::push_back(queries,
                query::new_commitment(
                    *vector::borrow(advice_commitments, (column::column_index(column) as u64)),
                    domain::rotate_omega(domain, x, rotation),
                    *vector::borrow(advice_evals, query_index),
                ));
        });

        permutation::queries(permutation, queries, protocol, domain, x);
        lookup::queries(&lookups, queries, protocol, domain, x);
        shuffle::queries(&shuffles, queries, protocol, domain, x);
    }

    fun evaluate_gates(
        gates: &vector<vector<u8>>,
        use_u8_fields: u8,
        use_u8_queries: u8,
        coeff_pool: &vector<Element<Fr>>,
        advice_evals: &vector<Element<Fr>>,
        fixed_evals: &vector<Element<Fr>>,
        instance_evals: &vector<Element<Fr>>,
        challenges: &vector<Element<Fr>>,
        results: &mut vector<Element<Fr>>,
    ) {
        vector::for_each_ref(gates, |exprs| {
            let eval_result = evaluator::evaluate_exprs(exprs, use_u8_fields, use_u8_queries, coeff_pool, advice_evals, fixed_evals, instance_evals, challenges);
            vector::for_each_ref(&eval_result, |item| {
                vector::push_back(results, *item);
            });
        });
    }

    fun evaluate_lookups(
        lookup_evaluates: &vector<lookup::Evaluated>,
        lookup: &vector<Lookup>,
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
        beta: &Element<Fr>,
        gamma: &Element<Fr>,
        results: &mut vector<Element<Fr>>,
    ) {
        vector::zip_ref(lookup_evaluates, lookup, | lookup_evaluate, l| {
            lookup::expression(
                lookup_evaluate,
                l,
                use_u8_fields,
                use_u8_queries,
                coeff_pool,
                advice_evals,
                fixed_evals,
                instance_evals, challenges, l_0, l_last, l_blind, theta, beta, gamma,
                results
            );
        });
    }

    fun evaluate_shuffles(
        shuffle_evaluates: &vector<shuffle::Evaluated>,
        shuffle: &vector<Shuffle>,
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
        results: &mut vector<Element<Fr>>,
    ) {
        vector::zip_ref(shuffle_evaluates, shuffle, | shuffle_evaluate, s| {
            shuffle::expression(
                shuffle_evaluate,
                s,
                use_u8_fields,
                use_u8_queries,
                coeff_pool,
                advice_evals,
                fixed_evals,
                instance_evals, challenges, l_0, l_last, l_blind, theta, gamma,
                results
            );
        });
    }
}
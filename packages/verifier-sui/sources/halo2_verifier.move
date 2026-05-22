// Copyright (c) zkMove Authors

module halo2_verifier::halo2_verifier {
    use sui::bn254;
    use sui::group_ops::Element;
    use halo2_common::bn254_utils::{Self, deserialize_fr, deserialize_g1};
    use halo2_common::column;
    use halo2_common::column_query;
    use halo2_common::domain::{Self, Domain};
    use halo2_common::i32;
    use halo2_common::params::Params;
    use halo2_common::public_inputs::{Self, PublicInputs};
    use halo2_common::query::{Self, VerifierQuery};
    use halo2_verifier::evaluator;
    use halo2_verifier::gwc;
    use halo2_verifier::lookup::{Self, PermutationCommitments};
    use halo2_verifier::permutation;
    use halo2_verifier::protocol::{Self, Lookup, Protocol, Shuffle};
    use halo2_verifier::shuffle;
    use halo2_verifier::shplonk;
    use halo2_verifier::transcript::{Self, Transcript};
    use halo2_verifier::vanishing;

    const GWC: u8 = 0;
    const SHPLONK: u8 = 1;

    public fun verify_single(
        params: &Params,
        protocol: &Protocol,
        instances: vector<vector<vector<u8>>>,
        proof: vector<u8>,
        kzg_variant: u8,
    ): bool {
        let pubs = public_inputs::from_bytes(&instances);
        let instances = public_inputs::columns(&pubs);
        verify(params, protocol, vector[instances], proof, kzg_variant)
    }

    public fun verify_single_proof(
        params: &Params,
        protocol: &Protocol,
        instances: PublicInputs,
        proof: vector<u8>,
        kzg_variant: u8,
    ): bool {
        let instances = public_inputs::columns(&instances);
        verify(params, protocol, vector[instances], proof, kzg_variant)
    }

    public fun verify(
        params: &Params,
        protocol: &Protocol,
        instances: vector<vector<vector<Element<bn254::Scalar>>>>,
        proof: vector<u8>,
        kzg_variant: u8,
    ): bool {
        let mut transcript = transcript::new(proof);
        let domain = protocol::domain(protocol);
        let num_proof = instances.length();

        transcript::common_scalar(&mut transcript, option::destroy_some(deserialize_fr(protocol::vk_transcript_repr(protocol))));
        absorb_instances(&mut transcript, &instances);

        let mut advice_commitments = init_advice_commitments(protocol, num_proof);
        let mut challenges = init_challenges(protocol);
        read_advice_commitments_and_challenges(protocol, &mut transcript, &mut advice_commitments, &mut challenges, num_proof);
        let theta = transcript::squeeze_challenge(&mut transcript);

        let lookups_permuted = lookup_read_permuted_commitments(
            &mut transcript,
            num_proof,
            protocol::num_lookup(protocol),
        );
        let beta = transcript::squeeze_challenge(&mut transcript);
        let gamma = transcript::squeeze_challenge(&mut transcript);

        let permutations_committed = permutation_read_product_commitments(
            &mut transcript,
            num_proof,
            protocol::num_permutation_z(protocol),
        );
        let lookups_committed = lookup_read_product_commitments(lookups_permuted, &mut transcript);
        let shuffles_committed = shuffle_read_product_commitments(
            &mut transcript,
            num_proof,
            protocol::num_shuffle(protocol),
        );

        let vanishing = vanishing::read_commitments_before_y(&mut transcript);
        let y = transcript::squeeze_challenge(&mut transcript);
        let vanishing = vanishing::read_commitments_after_y(
            vanishing,
            &mut transcript,
            domain::quotient_poly_degree(&domain),
        );
        let z = transcript::squeeze_challenge(&mut transcript);
        let z_n = bn254_utils::pow_u32(&z, domain::n(&domain));

        let instance_evals = evaluate_instances(protocol, &domain, &instances, &z, &z_n);
        let advice_evals = read_advice_evals(protocol, &mut transcript, num_proof);
        let fixed_evals = transcript::read_n_scalar(&mut transcript, protocol::fixed_queries(protocol).length());
        let vanishing = vanishing::evaluate_after_x(vanishing, &mut transcript);
        let permutations_common = permutation::evalute_common(
            &mut transcript,
            protocol::permutation_columns(protocol).length(),
        );
        let mut permutations_evaluated = evaluate_permutations(permutations_committed, &mut transcript);
        let mut lookups_evaluated = evaluate_lookup_sets(&lookups_committed, &mut transcript);
        let mut shuffles_evaluated = evaluate_shuffle_sets(&shuffles_committed, &mut transcript);

        let vanishing = evaluate_vanishing_expressions(
            vanishing,
            protocol,
            &domain,
            &z,
            &z_n,
            &y,
            &beta,
            &gamma,
            &theta,
            &challenges,
            &advice_evals,
            &fixed_evals,
            &instance_evals,
            &permutations_common,
            &permutations_evaluated,
            &lookups_evaluated,
            &shuffles_evaluated,
            num_proof,
        );

        let mut queries = vector[];
        reverse_per_proof_evaluations(&mut permutations_evaluated, &mut lookups_evaluated, &mut shuffles_evaluated);
        let mut i = 0;
        while (i < num_proof) {
            queries_for_proof(
                protocol,
                &domain,
                &mut queries,
                &z,
                &advice_commitments[i],
                &advice_evals[i],
                vector::pop_back(&mut permutations_evaluated),
                vector::pop_back(&mut lookups_evaluated),
                vector::pop_back(&mut shuffles_evaluated),
            );
            i = i + 1;
        };

        append_fixed_queries(protocol, &domain, &mut queries, &z, &fixed_evals);
        permutation::common_queries(
            permutations_common,
            &mut queries,
            deserialize_g1_list(protocol::permutation_commitments(protocol)),
            &z,
        );
        vanishing::queries(vanishing, &mut queries, &z);

        if (kzg_variant == GWC) {
            gwc::verify(params, &mut transcript, &queries)
        } else if (kzg_variant == SHPLONK) {
            shplonk::verify(params, &mut transcript, &queries)
        } else {
            abort 400
        }
    }

    fun absorb_instances(transcript: &mut Transcript, instances: &vector<vector<vector<Element<bn254::Scalar>>>>) {
        let mut proof_idx = 0;
        while (proof_idx < instances.length()) {
            let instance = &instances[proof_idx];
            let mut col = 0;
            while (col < instance.length()) {
                let column_values = &instance[col];
                let mut row = 0;
                while (row < column_values.length()) {
                    transcript::common_scalar(transcript, column_values[row]);
                    row = row + 1;
                };
                col = col + 1;
            };
            proof_idx = proof_idx + 1;
        };
    }

    fun init_advice_commitments(protocol: &Protocol, num_proof: u64): vector<vector<Element<bn254::G1>>> {
        let mut result = vector[];
        let columns_len = protocol::num_advice_columns(protocol);
        let mut i = 0;
        while (i < num_proof) {
            let mut row = vector[];
            let mut j = 0;
            while (j < columns_len) {
                vector::push_back(&mut row, bn254::g1_identity());
                j = j + 1;
            };
            vector::push_back(&mut result, row);
            i = i + 1;
        };
        result
    }

    fun init_challenges(protocol: &Protocol): vector<Element<bn254::Scalar>> {
        let mut result = vector[];
        let mut i = 0;
        while (i < protocol::num_challenges(protocol)) {
            vector::push_back(&mut result, bn254::scalar_zero());
            i = i + 1;
        };
        result
    }

    fun read_advice_commitments_and_challenges(
        protocol: &Protocol,
        transcript: &mut Transcript,
        advice_commitments: &mut vector<vector<Element<bn254::G1>>>,
        challenges: &mut vector<Element<bn254::Scalar>>,
        num_proof: u64,
    ) {
        let num_phase = protocol::num_phase(protocol);
        let mut phase = 0;
        while (phase < num_phase) {
            let mut proof_idx = 0;
            while (proof_idx < num_proof) {
                let advice_columns_phase = protocol::advice_column_phase(protocol);
                let mut col = 0;
                while (col < protocol::num_advice_columns(protocol)) {
                    if (advice_columns_phase[col] == phase) {
                        *vector::borrow_mut(&mut advice_commitments[proof_idx], col) = transcript::read_point(transcript);
                    };
                    col = col + 1;
                };
                proof_idx = proof_idx + 1;
            };

            let challenge_phase = protocol::challenge_phase(protocol);
            let mut challenge_idx = 0;
            while (challenge_idx < protocol::num_challenges(protocol)) {
                if (challenge_phase[challenge_idx] == phase) {
                    *vector::borrow_mut(challenges, challenge_idx) = transcript::squeeze_challenge(transcript);
                };
                challenge_idx = challenge_idx + 1;
            };
            phase = phase + 1;
        };
    }

    fun evaluate_instances(
        protocol: &Protocol,
        domain: &Domain,
        instances: &vector<vector<vector<Element<bn254::Scalar>>>>,
        z: &Element<bn254::Scalar>,
        z_n: &Element<bn254::Scalar>,
    ): vector<vector<Element<bn254::Scalar>>> {
        let instance_queries = protocol::instance_queries(protocol);
        let mut min_rotation = i32::zero();
        let mut max_rotation = i32::zero();

        let mut i = 0;
        while (i < instance_queries.length()) {
            let rotation = column_query::rotation(&instance_queries[i]);
            if (i32::compare(&min_rotation, rotation) == 2) {
                min_rotation = *rotation;
            } else if (i32::compare(rotation, &max_rotation) == 2) {
                max_rotation = *rotation;
            };
            i = i + 1;
        };

        let max_instance_len = max_instance_len(instances);
        let l_i_s = domain::l_i_range(
            domain,
            z,
            z_n,
            i32::neg(&max_rotation),
            i32::from((max_instance_len as u32) + i32::abs(&min_rotation)),
        );

        let mut all = vector[];
        let mut proof_idx = 0;
        while (proof_idx < instances.length()) {
            let proof_instances = &instances[proof_idx];
            let mut evals = vector[];
            let mut q_idx = 0;
            while (q_idx < instance_queries.length()) {
                let q = &instance_queries[q_idx];
                let col = column_query::column(q);
                let rotation = column_query::rotation(q);
                let column_index = column::column_index(col) as u64;
                let values = &proof_instances[column_index];
                let offset = i32::abs(&i32::sub(&max_rotation, rotation)) as u64;

                let mut acc = bn254::scalar_zero();
                let mut row = 0;
                while (row < values.length()) {
                    let l = l_i_s[offset + row];
                    acc = bn254::scalar_add(&acc, &bn254::scalar_mul(&values[row], &l));
                    row = row + 1;
                };
                vector::push_back(&mut evals, acc);
                q_idx = q_idx + 1;
            };
            vector::push_back(&mut all, evals);
            proof_idx = proof_idx + 1;
        };
        all
    }

    fun max_instance_len(instances: &vector<vector<vector<Element<bn254::Scalar>>>>): u64 {
        let mut max_len = 0;
        let mut proof_idx = 0;
        while (proof_idx < instances.length()) {
            let instance = &instances[proof_idx];
            let mut col = 0;
            while (col < instance.length()) {
                let len = instance[col].length();
                if (len > max_len) {
                    max_len = len;
                };
                col = col + 1;
            };
            proof_idx = proof_idx + 1;
        };
        max_len
    }

    fun read_advice_evals(
        protocol: &Protocol,
        transcript: &mut Transcript,
        num_proof: u64,
    ): vector<vector<Element<bn254::Scalar>>> {
        let len = protocol::advice_queries(protocol).length();
        let mut result = vector[];
        let mut i = 0;
        while (i < num_proof) {
            vector::push_back(&mut result, transcript::read_n_scalar(transcript, len));
            i = i + 1;
        };
        result
    }

    fun evaluate_permutations(
        permutations_committed: vector<permutation::Commited>,
        transcript: &mut Transcript,
    ): vector<permutation::Evaluted> {
        let mut result = vector[];
        let mut committed = permutations_committed;
        while (!committed.is_empty()) {
            vector::push_back(&mut result, permutation::evaluate(vector::remove(&mut committed, 0), transcript));
        };
        result
    }

    fun evaluate_lookup_sets(
        lookups_committed: &vector<vector<lookup::Commited>>,
        transcript: &mut Transcript,
    ): vector<vector<lookup::Evaluated>> {
        let mut result = vector[];
        let mut i = 0;
        while (i < lookups_committed.length()) {
            let committed = &lookups_committed[i];
            let mut row = vector[];
            let mut j = 0;
            while (j < committed.length()) {
                vector::push_back(&mut row, lookup::evaluate(&committed[j], transcript));
                j = j + 1;
            };
            vector::push_back(&mut result, row);
            i = i + 1;
        };
        result
    }

    fun evaluate_shuffle_sets(
        shuffles_committed: &vector<vector<shuffle::Commited>>,
        transcript: &mut Transcript,
    ): vector<vector<shuffle::Evaluated>> {
        let mut result = vector[];
        let mut i = 0;
        while (i < shuffles_committed.length()) {
            let committed = &shuffles_committed[i];
            let mut row = vector[];
            let mut j = 0;
            while (j < committed.length()) {
                vector::push_back(&mut row, shuffle::evaluate(&committed[j], transcript));
                j = j + 1;
            };
            vector::push_back(&mut result, row);
            i = i + 1;
        };
        result
    }

    fun evaluate_vanishing_expressions(
        vanishing: vanishing::PartialEvaluated,
        protocol: &Protocol,
        domain: &Domain,
        z: &Element<bn254::Scalar>,
        z_n: &Element<bn254::Scalar>,
        y: &Element<bn254::Scalar>,
        beta: &Element<bn254::Scalar>,
        gamma: &Element<bn254::Scalar>,
        theta: &Element<bn254::Scalar>,
        challenges: &vector<Element<bn254::Scalar>>,
        advice_evals: &vector<vector<Element<bn254::Scalar>>>,
        fixed_evals: &vector<Element<bn254::Scalar>>,
        instance_evals: &vector<vector<Element<bn254::Scalar>>>,
        permutations_common: &permutation::CommonEvaluted,
        permutations_evaluated: &vector<permutation::Evaluted>,
        lookups_evaluated: &vector<vector<lookup::Evaluated>>,
        shuffles_evaluated: &vector<vector<shuffle::Evaluated>>,
        num_proof: u64,
    ): vanishing::EvaluatedH {
        let blinding_factors = protocol::blinding_factors(protocol);
        let blinding_evals = domain::l_i_range(
            domain,
            z,
            z_n,
            i32::neg_from((blinding_factors as u32) + 1),
            i32::from(1),
        );
        let l_last = blinding_evals[0];
        let l_0 = blinding_evals[blinding_factors + 1];
        let mut l_blind = bn254::scalar_zero();
        let mut i = 1;
        while (i < blinding_factors + 1) {
            l_blind = bn254::scalar_add(&l_blind, &blinding_evals[i]);
            i = i + 1;
        };

        let coeff_pool = deserialize_fr_list(protocol::fields_pool(protocol));
        let mut expressions = vector[];
        let mut proof_idx = 0;
        let use_u8_fields = protocol::use_u8_fields(protocol);
        let use_u8_queries = protocol::use_u8_queries(protocol);
        while (proof_idx < num_proof) {
            evaluate_gates(
                protocol::gates(protocol),
                use_u8_fields,
                use_u8_queries,
                &coeff_pool,
                &advice_evals[proof_idx],
                fixed_evals,
                &instance_evals[proof_idx],
                challenges,
                &mut expressions,
            );

            permutation::expressions(
                &permutations_evaluated[proof_idx],
                protocol,
                permutations_common,
                &advice_evals[proof_idx],
                fixed_evals,
                &instance_evals[proof_idx],
                &l_0,
                &l_last,
                &l_blind,
                beta,
                gamma,
                z,
                &mut expressions,
            );
            evaluate_lookups(
                &lookups_evaluated[proof_idx],
                protocol::lookups(protocol),
                use_u8_fields,
                use_u8_queries,
                &coeff_pool,
                &advice_evals[proof_idx],
                fixed_evals,
                &instance_evals[proof_idx],
                challenges,
                &l_0,
                &l_last,
                &l_blind,
                theta,
                beta,
                gamma,
                &mut expressions,
            );
            evaluate_shuffles(
                &shuffles_evaluated[proof_idx],
                protocol::shuffles(protocol),
                use_u8_fields,
                use_u8_queries,
                &coeff_pool,
                &advice_evals[proof_idx],
                fixed_evals,
                &instance_evals[proof_idx],
                challenges,
                &l_0,
                &l_last,
                &l_blind,
                theta,
                gamma,
                &mut expressions,
            );
            proof_idx = proof_idx + 1;
        };

        vanishing::h_eval(vanishing, &expressions, y, z_n)
    }

    fun reverse_per_proof_evaluations(
        permutations: &mut vector<permutation::Evaluted>,
        lookups: &mut vector<vector<lookup::Evaluated>>,
        shuffles: &mut vector<vector<shuffle::Evaluated>>,
    ) {
        vector::reverse(permutations);
        vector::reverse(lookups);
        vector::reverse(shuffles);
    }

    fun lookup_read_permuted_commitments(
        transcript: &mut Transcript,
        num_proof: u64,
        num_lookup: u64,
    ): vector<vector<PermutationCommitments>> {
        let mut lookups_permuted = vector[];
        let mut i = 0;
        while (i < num_proof) {
            let mut result = vector[];
            let mut j = 0;
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
        transcript: &mut Transcript,
    ): vector<vector<lookup::Commited>> {
        let mut result = vector[];
        let mut outer = lookups_permuted;
        while (!outer.is_empty()) {
            let mut lookups = vector::remove(&mut outer, 0);
            let mut row = vector[];
            while (!lookups.is_empty()) {
                vector::push_back(&mut row, lookup::read_product_commitment(vector::remove(&mut lookups, 0), transcript));
            };
            vector::push_back(&mut result, row);
        };
        result
    }

    fun shuffle_read_product_commitments(
        transcript: &mut Transcript,
        num_proof: u64,
        num_shuffle: u64,
    ): vector<vector<shuffle::Commited>> {
        let mut shuffles = vector[];
        let mut i = 0;
        while (i < num_proof) {
            let mut result = vector[];
            let mut j = 0;
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
        num_permutation_z: u64,
    ): vector<permutation::Commited> {
        let mut result = vector[];
        let mut i = 0;
        while (i < num_proof) {
            vector::push_back(&mut result, permutation::read_product_commitments(transcript, num_permutation_z));
            i = i + 1;
        };
        result
    }

    fun queries_for_proof(
        protocol: &Protocol,
        domain: &Domain,
        queries: &mut vector<VerifierQuery>,
        x: &Element<bn254::Scalar>,
        advice_commitments: &vector<Element<bn254::G1>>,
        advice_evals: &vector<Element<bn254::Scalar>>,
        permutation: permutation::Evaluted,
        lookups: vector<lookup::Evaluated>,
        shuffles: vector<shuffle::Evaluated>,
    ) {
        let advice_queries = protocol::advice_queries(protocol);
        let mut query_index = 0;
        while (query_index < advice_queries.length()) {
            let q = &advice_queries[query_index];
            let col = column_query::column(q);
            let rotation = column_query::rotation(q);
            vector::push_back(
                queries,
                query::new_commitment(
                    advice_commitments[column::column_index(col) as u64],
                    domain::rotate_omega(domain, x, rotation),
                    advice_evals[query_index],
                ),
            );
            query_index = query_index + 1;
        };

        permutation::queries(permutation, queries, protocol, domain, x);
        lookup::queries(&lookups, queries, protocol, domain, x);
        shuffle::queries(&shuffles, queries, protocol, domain, x);
    }

    fun append_fixed_queries(
        protocol: &Protocol,
        domain: &Domain,
        queries: &mut vector<VerifierQuery>,
        z: &Element<bn254::Scalar>,
        fixed_evals: &vector<Element<bn254::Scalar>>,
    ) {
        let fixed_commitments = deserialize_g1_list(protocol::fixed_commitments(protocol));
        let fixed_queries = protocol::fixed_queries(protocol);
        let mut query_index = 0;
        while (query_index < fixed_queries.length()) {
            let q = &fixed_queries[query_index];
            let col = column_query::column(q);
            let rotation = column_query::rotation(q);
            vector::push_back(
                queries,
                query::new_commitment(
                    fixed_commitments[column::column_index(col) as u64],
                    domain::rotate_omega(domain, z, rotation),
                    fixed_evals[query_index],
                ),
            );
            query_index = query_index + 1;
        };
    }

    fun evaluate_gates(
        gates: &vector<vector<u8>>,
        use_u8_fields: u8,
        use_u8_queries: u8,
        coeff_pool: &vector<Element<bn254::Scalar>>,
        advice_evals: &vector<Element<bn254::Scalar>>,
        fixed_evals: &vector<Element<bn254::Scalar>>,
        instance_evals: &vector<Element<bn254::Scalar>>,
        challenges: &vector<Element<bn254::Scalar>>,
        results: &mut vector<Element<bn254::Scalar>>,
    ) {
        let mut i = 0;
        while (i < gates.length()) {
            let eval_result = evaluator::evaluate_exprs(
                &gates[i],
                use_u8_fields,
                use_u8_queries,
                coeff_pool,
                advice_evals,
                fixed_evals,
                instance_evals,
                challenges,
            );
            let mut j = 0;
            while (j < eval_result.length()) {
                vector::push_back(results, eval_result[j]);
                j = j + 1;
            };
            i = i + 1;
        };
    }

    fun evaluate_lookups(
        lookup_evaluates: &vector<lookup::Evaluated>,
        lookups: &vector<Lookup>,
        use_u8_fields: u8,
        use_u8_queries: u8,
        coeff_pool: &vector<Element<bn254::Scalar>>,
        advice_evals: &vector<Element<bn254::Scalar>>,
        fixed_evals: &vector<Element<bn254::Scalar>>,
        instance_evals: &vector<Element<bn254::Scalar>>,
        challenges: &vector<Element<bn254::Scalar>>,
        l_0: &Element<bn254::Scalar>,
        l_last: &Element<bn254::Scalar>,
        l_blind: &Element<bn254::Scalar>,
        theta: &Element<bn254::Scalar>,
        beta: &Element<bn254::Scalar>,
        gamma: &Element<bn254::Scalar>,
        results: &mut vector<Element<bn254::Scalar>>,
    ) {
        let mut i = 0;
        while (i < lookup_evaluates.length()) {
            lookup::expression(
                &lookup_evaluates[i],
                &lookups[i],
                use_u8_fields,
                use_u8_queries,
                coeff_pool,
                advice_evals,
                fixed_evals,
                instance_evals,
                challenges,
                l_0,
                l_last,
                l_blind,
                theta,
                beta,
                gamma,
                results,
            );
            i = i + 1;
        };
    }

    fun evaluate_shuffles(
        shuffle_evaluates: &vector<shuffle::Evaluated>,
        shuffles: &vector<Shuffle>,
        use_u8_fields: u8,
        use_u8_queries: u8,
        coeff_pool: &vector<Element<bn254::Scalar>>,
        advice_evals: &vector<Element<bn254::Scalar>>,
        fixed_evals: &vector<Element<bn254::Scalar>>,
        instance_evals: &vector<Element<bn254::Scalar>>,
        challenges: &vector<Element<bn254::Scalar>>,
        l_0: &Element<bn254::Scalar>,
        l_last: &Element<bn254::Scalar>,
        l_blind: &Element<bn254::Scalar>,
        theta: &Element<bn254::Scalar>,
        gamma: &Element<bn254::Scalar>,
        results: &mut vector<Element<bn254::Scalar>>,
    ) {
        let mut i = 0;
        while (i < shuffle_evaluates.length()) {
            shuffle::expression(
                &shuffle_evaluates[i],
                &shuffles[i],
                use_u8_fields,
                use_u8_queries,
                coeff_pool,
                advice_evals,
                fixed_evals,
                instance_evals,
                challenges,
                l_0,
                l_last,
                l_blind,
                theta,
                gamma,
                results,
            );
            i = i + 1;
        };
    }

    fun deserialize_fr_list(bytes: &vector<vector<u8>>): vector<Element<bn254::Scalar>> {
        let mut result = vector[];
        let mut i = 0;
        while (i < bytes.length()) {
            vector::push_back(&mut result, option::destroy_some(deserialize_fr(&bytes[i])));
            i = i + 1;
        };
        result
    }

    fun deserialize_g1_list(bytes: &vector<vector<u8>>): vector<Element<bn254::G1>> {
        let mut result = vector[];
        let mut i = 0;
        while (i < bytes.length()) {
            vector::push_back(&mut result, option::destroy_some(deserialize_g1(&bytes[i])));
            i = i + 1;
        };
        result
    }
}

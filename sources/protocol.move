module halo2_verifier::protocol {
    use halo2_verifier::Domain::Domain;
    use halo2_verifier::scalar::Scalar;
    use std::vector::{for_each_ref, map_ref, length, fold, map};
    use std::vector;
    use halo2_verifier::protocol::{fix_query, num_lookup};
    use halo2_verifier::column::Column;
    use halo2_verifier::column;

    struct Protocol {
        query_instance: bool,
        // for ipa, true; for kzg, false
        domain: Domain,
        cs_degree: u32,
        blinding_factors: u32,
        num_fixed: u64,
        num_permutation_fixed: u64,

        num_instance: vector<u64>,

        /// Number of witness polynomials in each phase.
        num_advice_in_phase: vector<u64>,
        advice_index: vector<u64>,
        // advice_phase: vector<u8>,
        /// Number of challenges to squeeze from transcript after each phase.
        num_challenge_in_phase: vector<u64>,
        challenge_index: vector<u64>,
        // challenge_phase: vector<u8>,

        lookups_len: u64,
        permutation_columns_len: u64,

        instance_queries: vector<InstanceQuery>,
        advice_queries: vector<AdviceQuery>,
        fixed_queries: vector<FixQuery>,
        permutation_columns: vector<Column>,
        gates: vector<Gate>,
    }

    struct Gate {
        ploys: vector<Expression>,
    }
    struct Expression {

    }

    struct AdviceQuery {
        q: ColumnQuery,
    }

    struct InstanceQuery {
        q: ColumnQuery
    }

    struct FixQuery {
        q: ColumnQuery
    }

    struct ColumnQuery {
        column: Column,
        rotation: Rotation,
    }

    struct Rotation {
        rotation: u32,
        next: bool,
    }

    struct Query {
        poly: u64,
        rotation: Rotation,
    }

    public fun query_instance(protocol: &Protocol): bool {
        protocol.query_instance
    }
    public fun instance_queries(protocol: &Protocol): &vector<InstanceQuery> {
        &protocol.instance_queries
    }
    public fun advice_queries(protocol: &Protocol): &vector<AdviceQuery> {
        &protocol.advice_queries
    }
    public fun fixed_queries(protocol: &Protocol): &vector<FixQuery> {
        &protocol.fixed_queries
    }
    public fun blinding_factors(protocol: &Protocol): u64 {
        abort 100
    }
    public fun transcript_initial_state(protocol: &Protocol): Scalar {
        abort 100
    }

    public fun num_fixed(protocol: &Protocol): u64 {
        protocol.num_fixed
    }

    public fun num_permutation_fixed(protocol: &Protocol): u64 {
        protocol.num_permutation_fixed
    }

    public fun num_preprocessed(protocol: &Protocol): u64 {
        num_fixed(protocol) + num_permutation_fixed(protocol)
    }

    /// return the num of challenges
    public fun num_challenges(protocol: &Protocol): u64 {
        abort 100
    }

    /// return the num of instance columns
    public fun num_instance_columns(protocol: &Protocol): u64 {
        abort 100
    }

    /// return the num of advice columns
    public fun num_advice_columns(protocol: &Protocol): u64 {
        abort 100
    }

    /// return the number of rows of each instance columns
    public fun num_instance(protocol: &Protocol): vector<u64> {
        abort 100
    }

    // public fun num_advice(protocol: &Protocol): u64 {
    //     abort 100
    // }
    // return advice num of each phase
    public fun num_advice_in_phase(protocol: &Protocol): &vector<u64> {
        abort 100
    }

    // return advice's index in each phase
    public fun advice_index(protocol: &Protocol): &vector<u64> {
        abort 100
    }

    // return advice's phase
    public fun advice_phase(protocol: &Protocol): &vector<u8> {
        abort 100
    }

    public fun num_challenge_in_phase(protocol: &Protocol): &vector<u64> {
        abort 100
    }

    public fun challenge_index(protocol: &Protocol): &vector<u64> {
        abort 100
    }

    public fun challenge_phase(protocol: &Protocol): &vector<u8> {
        abort 100
    }

    public fun num_lookup_permuted(protocol: &Protocol): u64 {
        // each lookup has A' and S'
        2 * protocol.lookups_len
    }

    public fun num_lookup(protocol: &Protocol): u64 {
        protocol.lookups_len
    }

    public fun permutation_chunk_size(protocol: &Protocol): u64 {
        abort 100
    }

    public fun num_permutation_z(protocol: &Protocol): u64 {
        let chunk_size = permutation_chunk_size(protocol);
        let chunk = protocol.permutation_columns_len / chunk_size;
        if (protocol.permutation_columns_len % chunk_size != 0) {
            chunk + 1
        } else {
            chunk
        }
    }

    public fun num_chunks_of_quotient(protocol: &Protocol, num_proof: u64): u64 {
        abort 100
    }

    /// return num polys of each phase
    public fun num_witness(protocol: &Protocol, num_proof: u64): vector<u64> {
        let witness = map_ref<u64, u64>(num_advice_in_phase(protocol), |n| num_proof * n);
        vector::push_back(&mut witness, num_proof * num_lookup_permuted(protocol));
        vector::push_back(
            &mut witness,
            num_proof * (num_permutation_z(protocol) + num_lookup(protocol)) + /* for random poly*/ 1
        );
        witness
    }

    public fun num_challenge(protocol: &Protocol): vector<u64> {
        let num_challenge = protocol.num_challenge_in_phase;
        vector::push_back(&mut num_challenge, vector::pop_back(&mut num_challenge) + 1); // theta
        vector::push_back(&mut num_challenge, 2);// beta, gamma
        vector::push_back(&mut num_challenge, 1); // y/alpha
        num_challenge
    }



    public fun evaluations_len(protocol: &Protocol, num_proof: u64): u64 {
        let instance_evals = if (protocol.query_instance) {
            vector::length(&protocol.instance_queries)
        } else {
            0
        };
        num_proof * instance_evals +
            num_proof * vector::length(&protocol.advice_queries) +
            /* fixed polys */ vector::length(&protocol.fixed_queries) +
            /* random poly*/ 1 +
            /* permutation fixed polys */ protocol.num_permutation_fixed +
            /* permutation_z*/ num_proof * (3 * num_permutation_z(protocol) - 1) +
            /* lookups evals*/ num_proof * 5 * num_lookup(protocol)
    }

    public fun evalutations(protocol: &Protocol, num_proof: u64): vector<Query> {
        let evals = vector::empty();

        // instance queries
        if (protocol.query_instance){
            let i = 0;
            while (i < num_proof) {
                vector::append(&mut evals, map_ref<InstanceQuery, Query>(&protocol.instance_queries, |q|
                    instance_query(protocol, i, q)
                ));
                i = i + 1;
            }
        };

        // advice queries
        {
            let i = 0;
            while (i < num_proof) {
                vector::append(&mut evals, map_ref<AdviceQuery, Query>(&protocol.advice_queries, |q|
                    advice_query(protocol, num_proof, i, q)
                ));
                i = i + 1;
            }
        };

        // fixed queries
        {
            vector::append(&mut evals, map_ref<FixQuery, Query>(&protocol.fixed_queries, |q|
                fix_query(protocol, q)
            ));
        };
        // random query
        vector::push_back(&mut evals, random_query(protocol, num_proof));

        // permutation fixed evals.
        {
            let i = 0;

            while (i < protocol.num_permutation_fixed) {
                vector::push_back(&mut evals, Query {
                    poly: protocol.num_fixed + i,
                    rotation: Rotation { rotation: 0, next: true }
                });
                i = i + 1;
            }
        };

        // permutation_z evals
        {
            let i = 0;
            while (i < num_proof) {
                vector::append(&mut evals, permutation_z_evals(protocol, num_proof, i));
                i = i + 1;
            }
        };

        // lookups evals
        {
            let i = 0;
            while (i < num_proof) {
                vector::append(&mut evals, lookup_evals(protocol, num_proof, i));
                i = i + 1;
            }
        };
        evals
    }


    fun instance_offset(protocol: &Protocol): u64 {
        num_preprocessed(protocol)
    }

    fun witness_offset(protocol: &Protocol, num_proof: u64): u64 {
        instance_offset(protocol) + num_instance_columns(protocol) * num_proof
    }

    fun cs_witness_offset(protocol: &Protocol, num_proof: u64): u64 {
        let witness = map_ref<u64, u64>(num_advice_in_phase(protocol), |n| num_proof * n);
        witness_offset(protocol, num_proof) + fold(witness, 0, |acc, elem| acc + elem)
    }

    public fun fix_query(_protocol: &Protocol, query: &FixQuery): Query {
        Query {
            poly: (column::column_index(&query.q.column)as u64),
            rotation: query.q.rotation
        }
    }

    public fun instance_query(protocol: &Protocol, i: u64, query: &InstanceQuery): Query {
        let offset = instance_offset(protocol) + i * length(&protocol.num_instance);
        Query {
            poly: (column::column_index(&query.q.column)as u64) + offset,
            rotation: query.q.rotation
        }
    }

    public fun advice_query(protocol: &Protocol, num_proof: u64, i: u64, query: &AdviceQuery): Query {
        let column_index = *vector::borrow(&protocol.advice_index, (column::column_index(&query.q.column)as u64));
        let sum = {
            let i = 0;
            let sum = 0;
            while (i < column::phase(&query.q.column)) {
                sum = sum + *vector::borrow(&protocol.num_advice_in_phase, i);
                i = i + 1;
            };
            sum
        };
        let phase_offset = num_proof * sum;
        let offset = witness_offset(protocol, num_proof) + phase_offset + i * (*vector::borrow(
            &protocol.num_advice_in_phase,
            (column::phase(&query.q.column) as u64)
        ));
        Query {
            poly: column_index + offset,
            rotation: query.q.rotation
        }
    }

    public fun random_query(protocol: &Protocol, num_proof: u64): Query {
        let poly = witness_offset(protocol, num_proof) + fold(
            num_witness(protocol, num_proof),
            0,
            |acc, elem| acc + elem
        ) - 1;
        Query {
            poly,
            rotation: Rotation { rotation: 0, next: true }
        }
    }

    fun permutation_poly(protocol: &Protocol, num_proof: u64, t: u64, i: u64): u64 {
        cs_witness_offset(protocol, num_proof) + num_proof * num_lookup_permuted(protocol) + num_permutation_z(
            protocol
        ) * t + i
    }

    fun lookup_polys(protocol: &Protocol, num_proof: u64, t: u64, i: u64): (u64, u64, u64) {
        let permuted_offset = cs_witness_offset(protocol, num_proof);
        let z_offset = permuted_offset + num_proof * num_lookup_permuted(protocol) + num_proof * num_permutation_z(
            protocol
        );
        let z = z_offset + t * num_lookup(protocol) + i;
        let permuted_input = permuted_offset + (t * num_lookup(protocol) + i) * 2;
        (z, permuted_input, permuted_input + 1)
    }

    fun permutation_z_evals(protocol: &Protocol, num_proof: u64, t: u64): vector<Query> {
        let i = 0;
        let chunk_num = num_permutation_z(protocol);
        let evals = vector::empty();
        while (i < chunk_num) {
            let z = permutation_poly(protocol, num_proof, t, i);
            vector::push_back(&mut evals, Query { poly: z, rotation: Rotation { rotation: 0, next: true } });
            vector::push_back(&mut evals, Query { poly: z, rotation: Rotation { rotation: 1, next: true } });
            // not the last set
            if (i < chunk_num - 1) {
                vector::push_back(&mut evals, Query { poly: z, rotation: rotation_last(protocol) });
            };
            i = i + 1;
        };
        evals
    }

    fun lookup_evals(protocol: &Protocol, num_proof: u64, t: u64): vector<Query> {
        let i = 0;
        let num_lookup = num_lookup(protocol);
        let evals = vector::empty();
        while (i < num_lookup) {
            let (z, permuted_input, permuted_table) = lookup_polys(protocol, num_proof, t, i);
            vector::push_back(&mut evals, Query { poly: z, rotation: Rotation { rotation: 0, next: true } });
            vector::push_back(&mut evals, Query { poly: z, rotation: Rotation { rotation: 1, next: true } });
            vector::push_back(
                &mut evals,
                Query { poly: permuted_input, rotation: Rotation { rotation: 0, next: true } }
            );
            vector::push_back(
                &mut evals,
                Query { poly: permuted_input, rotation: Rotation { rotation: 1, next: false } }
            );
            vector::push_back(
                &mut evals,
                Query { poly: permuted_table, rotation: Rotation { rotation: 0, next: true } }
            );
            i = i + 1;
        };
        evals
    }

    fun rotation_last(protocol: &Protocol): Rotation {
        Rotation { rotation: protocol.blinding_factors + 1, next: false }
    }
}

module halo2_verifier::protocol {
    use std::vector::{Self, map_ref, length, fold};

    use halo2_verifier::column::{Self, Column};
    use halo2_verifier::domain::Domain;
    use halo2_verifier::rotation::{Self, Rotation};
    use halo2_verifier::scalar::Scalar;
    use aptos_std::math64::max;
    use halo2_verifier::domain;
    use std::error;
    use halo2_verifier::expression::Expression;

    const QUERY_NOT_FOUND: u64 = 1;

    struct Protocol {
        query_instance: bool,
        // for ipa, true; for kzg, false
        domain: Domain,

        /// it's constraint_system's degree()
        cs_degree: u64,

        num_fixed_columns: u64,
        //num_instance_columns: u64,

        num_instance: vector<u64>,

        /// Number of witness polynomials in each phase.
        // num_advice_in_phase: vector<u64>,
        // advice_index: vector<u64>,
        // advice_phase: vector<u8>,
        /// Number of challenges to squeeze from transcript after each phase.
        // num_challenge_in_phase: vector<u64>,
        // challenge_index: vector<u64>,
        // challenge_phase: vector<u8>,

        advice_column_phase: vector<u8>,
        challenge_phase: vector<u8>,

        gates: vector<Gate>,

        advice_queries: vector<AdviceQuery>,
        instance_queries: vector<InstanceQuery>,
        fixed_queries: vector<FixQuery>,

        permutation_columns: vector<Column>,
        lookups: vector<Lookup>,
        /// it's `advice_queries.count_by(|q| q.column).max`
        max_num_query_of_advice_column: u32,
    }

    struct Gate  {
        ploys: vector<Expression>,
    }

    struct Lookup {
        input_expressions: vector<Expression>,
        table_expressions: vector<Expression>,
    }

    struct AdviceQuery has store {
        q: ColumnQuery,
    }

    struct InstanceQuery has store{
        q: ColumnQuery
    }

    struct FixQuery  has store{
        q: ColumnQuery
    }

    struct ColumnQuery  has store{
        column: Column,
        rotation: Rotation,
    }

    public fun domain(p: &Protocol): &Domain {
        &p.domain
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

    public fun lookups(protocol: &Protocol): &vector<Lookup> {
        &protocol.lookups
    }
    public fun gates(protocol: &Protocol): &vector<Gate> {
        &protocol.gates
    }
    public fun polys(gate: &Gate): &vector<Expression> {
        &gate.ploys
    }
    public fun input_exprs(self: &Lookup): &vector<Expression> {
        &self.input_expressions
    }
    public fun table_exprs(self: &Lookup): &vector<Expression> {
        &self.table_expressions
    }
    public fun blinding_factors(protocol: &Protocol): u64 {
        // All of the prover's advice columns are evaluated at no more than
        let factors = max((protocol.max_num_query_of_advice_column as u64), 1);

        // distinct points during gate checks.

        // - The permutation argument witness polynomials are evaluated at most 3 times.
        // - Each lookup argument has independent witness polynomials, and they are
        //   evaluated at most 2 times.
        let factors = max(3, factors);

        // Each polynomial is evaluated at most an additional time during
        // multiopen (at x_3 to produce q_evals):
        let factors = factors + 1;

        // h(x) is derived by the other evaluations so it does not reveal
        // anything; in fact it does not even appear in the proof.

        // h(x_3) is also not revealed; the verifier only learns a single
        // evaluation of a polynomial in x_1 which has h(x_3) and another random
        // polynomial evaluated at x_3 as coefficients -- this random polynomial
        // is "random_poly" in the vanishing argument.

        // Add an additional blinding factor as a slight defense against
        // off-by-one errors.
        factors + 1
    }

    public fun permutation_columns(protocol: &Protocol): &vector<Column> {
        &protocol.permutation_columns
    }

    /// get query index of any column
    public fun get_query_index(protocol: &Protocol, column: &Column, rotation: &Rotation): u64 {
        if (column::is_fixed(column)) {
            let (find, index)  = vector::find(&protocol.fixed_queries, |q| {
                let q: &FixQuery = q;
                (&q.q.column == column) && (&q.q.rotation == rotation)
            });
            assert!(find, error::invalid_state(QUERY_NOT_FOUND));
            index
        } else if (column::is_instance(column)) {
            let (find, index)  = vector::find(&protocol.instance_queries, |q| {
                let q: &InstanceQuery = q;
                (&q.q.column == column) && (&q.q.rotation == rotation)
            });
            assert!(find, error::invalid_state(QUERY_NOT_FOUND));
            index
        } else if (column::is_advice(column)) {
            let (find, index)  = vector::find(&protocol.advice_queries, |q| {
                let q: &AdviceQuery = q;
                (&q.q.column == column) && (&q.q.rotation == rotation)
            });
            assert!(find, error::invalid_state(QUERY_NOT_FOUND));
            index
        } else {
            abort error::invalid_state(QUERY_NOT_FOUND)
        }
    }

    public fun num_phase(protocol: &Protocol): u8 {
        let max_phase = 0;
        vector::for_each_ref(&protocol.advice_column_phase, |p| if (*p > max_phase) { max_phase = *p});
        vector::for_each_ref(&protocol.challenge_phase, |p| if (*p > max_phase) { max_phase = *p});
        max_phase + 1
    }

    /// return the num of challenges
    public fun num_challenges(protocol: &Protocol): u64 {
        vector::length(&protocol.challenge_phase)
    }

    /// return the num of instance columns
    public fun num_instance_columns(protocol: &Protocol): u64 {
        vector::length(&protocol.num_instance)
    }

    /// return the num of advice columns
    public fun num_advice_columns(protocol: &Protocol): u64 {
        vector::length(&protocol.advice_column_phase)
    }

    /// return the number of rows of each instance columns
    public fun num_instance(protocol: &Protocol): &vector<u64> {
        &protocol.num_instance
    }



    // return advice's phase
    public fun advice_column_phase(protocol: &Protocol): &vector<u8> {
        &protocol.advice_column_phase
    }


    public fun challenge_phase(protocol: &Protocol): &vector<u8> {
        &protocol.challenge_phase
    }

    public fun num_lookup(protocol: &Protocol): u64 {
        vector::length(&protocol.lookups)
    }

    public fun permutation_chunk_size(protocol: &Protocol): u64 {
        protocol.cs_degree - 2
    }

    public fun num_permutation_z(protocol: &Protocol): u64 {
        let chunk_size = permutation_chunk_size(protocol);
        let permutation_columns_len = vector::length(&protocol.permutation_columns);
        let chunk = permutation_columns_len / chunk_size;
        if (permutation_columns_len % chunk_size != 0) {
            chunk + 1
        } else {
            chunk
        }
    }

    public fun quotient_poly_degree(protocol: &Protocol): u64 {
        domain::quotient_poly_degree(&protocol.domain)
    }


    public fun from_instance_query(q: &InstanceQuery): (&Column, &Rotation) {
        (&q.q.column, &q.q.rotation)
    }

    public fun from_advice_query(q: &AdviceQuery): (&Column, &Rotation) {
        (&q.q.column, &q.q.rotation)
    }

    public fun from_fixed_query(q: &FixQuery): (&Column, &Rotation) {
        (&q.q.column, &q.q.rotation)
    }

    //
    // public fun num_fixed(protocol: &Protocol): u64 {
    //     protocol.num_fixed
    // }
    //
    //
    // public fun num_preprocessed(protocol: &Protocol): u64 {
    //     num_fixed(protocol) + num_permutation_fixed(protocol)
    // }


    //
    // // return advice num of each phase
    // public fun num_advice_in_phase(protocol: &Protocol): &vector<u64> {
    //     abort 100
    // }
    //
    // // return advice's index in each phase
    // public fun advice_index(protocol: &Protocol): &vector<u64> {
    //     abort 100
    // }

    //
    // public fun num_challenge_in_phase(protocol: &Protocol): &vector<u64> {
    //     abort 100
    // }
    //
    // public fun challenge_index(protocol: &Protocol): &vector<u64> {
    //     abort 100
    // }

    // public fun num_lookup_permuted(protocol: &Protocol): u64 {
    //     // each lookup has A' and S'
    //     2 * protocol.lookups_len
    // }


    // /// return num polys of each phase
    // public fun num_witness(protocol: &Protocol, num_proof: u64): vector<u64> {
    //     let witness = map_ref<u64, u64>(num_advice_in_phase(protocol), |n| num_proof * (*n));
    //     vector::push_back(&mut witness, num_proof * num_lookup_permuted(protocol));
    //     vector::push_back(
    //         &mut witness,
    //         num_proof * (num_permutation_z(protocol) + num_lookup(protocol)) + /* for random poly*/ 1
    //     );
    //     witness
    // }

    // public fun num_challenge(protocol: &Protocol): vector<u64> {
    //     let num_challenge = protocol.num_challenge_in_phase;
    //     let x = vector::pop_back(&mut num_challenge);
    //     vector::push_back(&mut num_challenge, x + 1); // theta
    //     vector::push_back(&mut num_challenge, 2);// beta, gamma
    //     vector::push_back(&mut num_challenge, 1); // y/alpha
    //     num_challenge
    // }


    // public fun evaluations_len(protocol: &Protocol, num_proof: u64): u64 {
    //     let instance_evals = if (protocol.query_instance) {
    //         vector::length(&protocol.instance_queries)
    //     } else {
    //         0
    //     };
    //     num_proof * instance_evals +
    //         num_proof * vector::length(&protocol.advice_queries) +
    //         /* fixed polys */ vector::length(&protocol.fixed_queries) +
    //         /* random poly*/ 1 +
    //         /* permutation fixed polys */ protocol.num_permutation_fixed +
    //         /* permutation_z*/ num_proof * (3 * num_permutation_z(protocol) - 1) +
    //         /* lookups evals*/ num_proof * 5 * num_lookup(protocol)
    // }

    // public fun evalutations(protocol: &Protocol, num_proof: u64): vector<Query> {
    //     let evals = vector::empty();
    //
    //     // instance queries
    //     if (protocol.query_instance) {
    //         let i = 0;
    //         while (i < num_proof) {
    //             vector::append(&mut evals, map_ref<InstanceQuery, Query>(&protocol.instance_queries, |q|
    //                 instance_query(protocol, i, q)
    //             ));
    //             i = i + 1;
    //         }
    //     };
    //
    //     // advice queries
    //     {
    //         let i = 0;
    //         while (i < num_proof) {
    //             vector::append(&mut evals, map_ref<AdviceQuery, Query>(&protocol.advice_queries, |q|
    //                 advice_query(protocol, num_proof, i, q)
    //             ));
    //             i = i + 1;
    //         }
    //     };
    //
    //     // fixed queries
    //     {
    //         vector::append(&mut evals, map_ref<FixQuery, Query>(&protocol.fixed_queries, |q|
    //             fix_query(protocol, q)
    //         ));
    //     };
    //     // random query
    //     vector::push_back(&mut evals, random_query(protocol, num_proof));
    //
    //     // permutation fixed evals.
    //     {
    //         let i = 0;
    //
    //         while (i < protocol.num_permutation_fixed) {
    //             vector::push_back(&mut evals, Query {
    //                 poly: protocol.num_fixed + i,
    //                 rotation: rotation::cur(),
    //             });
    //             i = i + 1;
    //         }
    //     };
    //
    //     // permutation_z evals
    //     {
    //         let i = 0;
    //         while (i < num_proof) {
    //             vector::append(&mut evals, permutation_z_evals(protocol, num_proof, i));
    //             i = i + 1;
    //         }
    //     };
    //
    //     // lookups evals
    //     {
    //         let i = 0;
    //         while (i < num_proof) {
    //             vector::append(&mut evals, lookup_evals(protocol, num_proof, i));
    //             i = i + 1;
    //         }
    //     };
    //     evals
    // }


    // fun instance_offset(protocol: &Protocol): u64 {
    //     num_preprocessed(protocol)
    // }

    // fun witness_offset(protocol: &Protocol, num_proof: u64): u64 {
    //     instance_offset(protocol) + num_instance_columns(protocol) * num_proof
    // }

    // fun cs_witness_offset(protocol: &Protocol, num_proof: u64): u64 {
    //     let witness = map_ref<u64, u64>(num_advice_in_phase(protocol), |n| num_proof * (*n));
    //     witness_offset(protocol, num_proof) + fold(witness, 0, |acc, elem| acc + elem)
    // }
    //
    // public fun fix_query(_protocol: &Protocol, query: &FixQuery): Query {
    //     Query {
    //         poly: (column::column_index(&query.q.column) as u64),
    //         rotation: query.q.rotation
    //     }
    // }
    //
    // public fun instance_query(protocol: &Protocol, i: u64, query: &InstanceQuery): Query {
    //     let offset = instance_offset(protocol) + i * length(&protocol.num_instance);
    //     Query {
    //         poly: (column::column_index(&query.q.column) as u64) + offset,
    //         rotation: query.q.rotation
    //     }
    // }
    //
    // public fun advice_query(protocol: &Protocol, num_proof: u64, i: u64, query: &AdviceQuery): Query {
    //     let column_index = *vector::borrow(&protocol.advice_index, (column::column_index(&query.q.column) as u64));
    //     let sum = {
    //         let i = 0;
    //         let sum = 0;
    //         while (i < column::phase(&query.q.column)) {
    //             sum = sum + *vector::borrow(&protocol.num_advice_in_phase, (i as u64));
    //             i = i + 1;
    //         };
    //         sum
    //     };
    //     let phase_offset = num_proof * sum;
    //     let offset = witness_offset(protocol, num_proof) + phase_offset + i * (*vector::borrow(
    //         &protocol.num_advice_in_phase,
    //         (column::phase(&query.q.column) as u64)
    //     ));
    //     Query {
    //         poly: column_index + offset,
    //         rotation: query.q.rotation
    //     }
    // }

    // public fun random_query(protocol: &Protocol, num_proof: u64): Query {
    //     let poly = witness_offset(protocol, num_proof) + fold(
    //         num_witness(protocol, num_proof),
    //         0,
    //         |acc, elem| acc + elem
    //     ) - 1;
    //     Query {
    //         poly,
    //         rotation: rotation::cur()
    //     }
    // }

    // fun permutation_poly(protocol: &Protocol, num_proof: u64, t: u64, i: u64): u64 {
    //     cs_witness_offset(protocol, num_proof) + num_proof * num_lookup_permuted(protocol) + num_permutation_z(
    //         protocol
    //     ) * t + i
    // }

    // fun lookup_polys(protocol: &Protocol, num_proof: u64, t: u64, i: u64): (u64, u64, u64) {
    //     let permuted_offset = cs_witness_offset(protocol, num_proof);
    //     let z_offset = permuted_offset + num_proof * num_lookup_permuted(protocol) + num_proof * num_permutation_z(
    //         protocol
    //     );
    //     let z = z_offset + t * num_lookup(protocol) + i;
    //     let permuted_input = permuted_offset + (t * num_lookup(protocol) + i) * 2;
    //     (z, permuted_input, permuted_input + 1)
    // }

    // fun permutation_z_evals(protocol: &Protocol, num_proof: u64, t: u64): vector<Query> {
    //     let i = 0;
    //     let chunk_num = num_permutation_z(protocol);
    //     let evals = vector::empty();
    //     while (i < chunk_num) {
    //         let z = permutation_poly(protocol, num_proof, t, i);
    //         vector::push_back(&mut evals, Query { poly: z, rotation: rotation::cur() });
    //         vector::push_back(&mut evals, Query { poly: z, rotation: rotation::next(1) });
    //         // not the last set
    //         if (i < chunk_num - 1) {
    //             vector::push_back(&mut evals, Query { poly: z, rotation: rotation_last(protocol) });
    //         };
    //         i = i + 1;
    //     };
    //     evals
    // }

    // fun lookup_evals(protocol: &Protocol, num_proof: u64, t: u64): vector<Query> {
    //     let i = 0;
    //     let num_lookup = num_lookup(protocol);
    //     let evals = vector::empty();
    //     while (i < num_lookup) {
    //         let (z, permuted_input, permuted_table) = lookup_polys(protocol, num_proof, t, i);
    //         vector::push_back(&mut evals, Query { poly: z, rotation: rotation::cur() });
    //         vector::push_back(&mut evals, Query { poly: z, rotation: rotation::next(1) });
    //         vector::push_back(
    //             &mut evals,
    //             Query { poly: permuted_input, rotation: rotation::cur() }
    //         );
    //         vector::push_back(
    //             &mut evals,
    //             Query { poly: permuted_input, rotation: rotation::prev(1) }
    //         );
    //         vector::push_back(
    //             &mut evals,
    //             Query { poly: permuted_table, rotation: rotation::next(1) }
    //         );
    //         i = i + 1;
    //     };
    //     evals
    // }

    // fun rotation_last(protocol: &Protocol): Rotation {
    //     rotation::prev(protocol.blinding_factors + 1)
    // }
}

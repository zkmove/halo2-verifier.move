module halo2_verifier::protocol {
    use std::error;
    // use std::vector::{Self, map_ref, length, fold};
    use std::vector;
    use std::option;
    use std::debug::{Self};
    use std::bn254_algebra::{Fr, FormatFrLsb};

    use aptos_std::math64::max;
    use aptos_std::from_bcs;
    use aptos_std::crypto_algebra;

    use halo2_verifier::column::{Self, Column};
    use halo2_verifier::domain::{Self, Domain};
    use halo2_verifier::rotation::{Self, Rotation};
    use halo2_verifier::expression::{Self, Expression};
    use halo2_verifier::multivariate_poly;

    #[test_only]
    use aptos_std::crypto_algebra::enable_cryptography_algebra_natives;

    const QUERY_NOT_FOUND: u64 = 1;

    struct Protocol {
        query_instance: bool,
        // for ipa, true; for kzg, false
        k: u8,
        /// it's `advice_queries.count_by(|q| q.column).max`
        max_num_query_of_advice_column: u32,

        /// it's constraint_system's degree()
        cs_degree: u32,

        num_fixed_columns: u64,
        num_instance_columns: u64,

        //num_instance: vector<u64>,

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


        advice_queries: vector<AdviceQuery>,
        instance_queries: vector<InstanceQuery>,
        fixed_queries: vector<FixQuery>,

        permutation_columns: vector<Column>,
        gates: vector<Expression>,
        lookups: vector<Lookup>,
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

    public fun get_bytes(
        source_bytes: &vector<u8>,
        start_idx: u64,
        end_idx: u64,
    ): vector<u8> {
        let i = start_idx;
        let bytes = vector::empty();
        loop {
            if (i >= end_idx) {
                break;
            };

            let b = vector::borrow(source_bytes, i);
            vector::push_back(&mut bytes, *b);

            i = i + 1;
        };

        bytes
    }

    public fun deserialize_column_query(
        q: &vector<u8>,
    ): ColumnQuery {
        let column_type = from_bcs::to_u8(get_bytes(q, 0, 1));
        let index = from_bcs::to_u32(get_bytes(q, 1, 5));
        let next = from_bcs::to_bool(get_bytes(q, 5, 6));
        let rotation = from_bcs::to_u32(get_bytes(q, 6, 10));

        ColumnQuery {
            column: column::new(index, column_type),
            rotation: rotation::new(next, rotation),
        }
    }

    public fun deserialize_column(
        q: &vector<u8>,
    ): Column {
        let column_type = from_bcs::to_u8(get_bytes(q, 0, 1));
        let index = from_bcs::to_u32(get_bytes(q, 1, 5));
        let column = column::new(index, column_type);
        column
    }

    public fun deserialize_expression(
        data: &vector<u8>,
    ): Expression {
        let terms = vector::empty();

        let term_len = from_bcs::to_u32(get_bytes(data, 0, 4));
        let i = 0;
        let idx = 4;
        loop {
            if (i >= term_len) {
                break;
            };
            
            let coff = option::destroy_some(crypto_algebra::deserialize<Fr, FormatFrLsb>(&get_bytes(data, idx, idx + 32)));
            idx = idx + 32;
            
            let sparse_terms = vector::empty();
            let sparse_term_len = from_bcs::to_u32(get_bytes(data, idx, idx + 4));
            idx = idx + 4;
            let i_t = 0;

            loop {
                if (i_t >= sparse_term_len) {
                    break;
                };

                let variable_index = from_bcs::to_u32(get_bytes(data, idx, idx + 4));
                idx = idx + 4;

                let power = from_bcs::to_u32(get_bytes(data, idx, idx + 4));
                idx = idx + 4;

                vector::push_back(&mut sparse_terms, multivariate_poly::new_sparse_term(variable_index, power));
                i_t = i_t + 1;
            };

            vector::push_back(&mut terms, multivariate_poly::new_term(coff, sparse_terms));
            i = i + 1;
        };

        expression::new(multivariate_poly::new_poly(terms))
    }

    public fun from_bytes(
        general_info: vector<vector<u8>>,
        advice_queries:vector<vector<u8>>,
        instance_queries:vector<vector<u8>>,
        fixed_queries:vector<vector<u8>>,
        permutation_columns:vector<vector<u8>>,
        gates:vector<vector<u8>>,
        lookups_input_exprs:vector<vector<u8>>,
        lookups_table_exprs:vector<vector<u8>>,
    ): Protocol {
        let challenge_phase = vector::pop_back(&mut general_info);
        let advice_column_phase = vector::pop_back(&mut general_info);
        let num_instance_columns = from_bcs::to_u64(vector::pop_back(&mut general_info));
        let num_fixed_columns = from_bcs::to_u64(vector::pop_back(&mut general_info));
        let cs_degree = from_bcs::to_u32(vector::pop_back(&mut general_info));
        let max_num_query_of_advice_column = from_bcs::to_u32(vector::pop_back(&mut general_info));
        let k = from_bcs::to_u8(vector::pop_back(&mut general_info));
        let query_instance = from_bcs::to_bool(vector::pop_back(&mut general_info));

        let advice_queries = vector::map_ref(&advice_queries, |q| {
            AdviceQuery {
                q: deserialize_column_query(q)
            }
        });
        let instance_queries = vector::map_ref(&instance_queries, |q| {
            InstanceQuery {
                q: deserialize_column_query(q)
            }
        });
        let fixed_queries = vector::map_ref(&fixed_queries, |q| {
            FixQuery {
                q: deserialize_column_query(q)
            }
        });

        let permutation_columns = vector::map_ref(&permutation_columns, |q| deserialize_column(q));
        let gates = vector::map_ref(&gates, |q| deserialize_expression(q));

        let lookups = vector::empty();
        // let lookups_input_exprs = vector::map_ref(&lookups_input_exprs, |q| deserialize_expression(q));
        // let lookups_table_exprs = vector::map_ref(&lookups_table_exprs, |q| deserialize_expression(q));

        // TODO: deserilize other data.
        let protocol = Protocol {
            query_instance,
            k,
            max_num_query_of_advice_column,
            cs_degree,
            num_fixed_columns,
            num_instance_columns,
            advice_column_phase,
            challenge_phase,

            advice_queries,
            instance_queries,
            fixed_queries,

            permutation_columns,
            gates,
            lookups,
        };
        protocol
    }

    public fun domain(p: &Protocol): Domain {
        domain::new(p.cs_degree, p.k)
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
    public fun gates(protocol: &Protocol): &vector<Expression> {
        &protocol.gates
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
        // is random_poly in the vanishing argument.

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
        protocol.num_instance_columns
    }

    /// return the num of advice columns
    public fun num_advice_columns(protocol: &Protocol): u64 {
        vector::length(&protocol.advice_column_phase)
    }

    /// return the number of rows of each instance columns
    // public fun num_instance(protocol: &Protocol): &vector<u64> {
    //     &protocol.num_instance
    // }



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

    public fun permutation_chunk_size(protocol: &Protocol): u32 {
        protocol.cs_degree - 2
    }

    public fun num_permutation_z(protocol: &Protocol): u64 {
        let chunk_size = (permutation_chunk_size(protocol) as u64);
        let permutation_columns_len = vector::length(&protocol.permutation_columns);
        let chunk = permutation_columns_len / chunk_size;
        if (permutation_columns_len % chunk_size != 0) {
            chunk + 1
        } else {
            chunk
        }
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


    #[test(s = @std)]
    fun test_serialize(s: &signer): Protocol {
        enable_cryptography_algebra_natives(s);
        
        let protocol: Protocol = from_bytes(
            vector[ // general_info
                x"00", // query instance
                x"10", // k
                x"01000000", // max_num_query_of_advice_column
                x"04000000", // cs_degree
                x"0600000000000000", // num_fixed_columns
                x"0000000000000000", // num_instance_columns
                x"000000", // advice_column_phase
                x"00" // challenge_phase
            ],
            vector[ // advice_queries
                x"00010000000100000000",
                x"00020000000100000000",
                x"00030000000100000000",
                x"00040000000101000000",
                x"00000000000001000000"
            ],
            vector[ // instance_queries
            ],
            vector[ // fix_queries
                x"ff050000000100000000",
                x"ff000000000100000000",
                x"ff020000000100000000",
                x"ff030000000100000000",
                x"ff040000000100000000",
                x"ff010000000100000000"
            ],
            vector[ // permutation_columns
                x"0001000000",
                x"0002000000",
                x"0003000000"
            ],
            vector[ // gates
                x"05000000000000f093f5e1439170b97948e833285d588181b64550b829a031e1724e643002000000020000000100000009000000010000000100000000000000000000000000000000000000000000000000000000000000020000000100000001000000080000000100000001000000000000000000000000000000000000000000000000000000000000000200000000000000010000000700000001000000010000000000000000000000000000000000000000000000000000000000000003000000030000000100000004000000010000000600000001000000010000000000000000000000000000000000000000000000000000000000000003000000000000000100000001000000010000000a00000001000000"
            ],
            vector[
                x"0100000030000000010000000100000000000000000000000000000000000000000000000000000000000000010000000000000001000000",
            ],
            vector[
                x"0100000030000000010000000100000000000000000000000000000000000000000000000000000000000000010000000500000001000000",
            ],
        );

        assert!(protocol.k == 0x10, 1);
        assert!(protocol.num_fixed_columns == 0x06, 1);

        let advice_query_len = vector::length(&protocol.advice_queries);
        assert!(advice_query_len == 5, 1);

        let advice_query = vector::borrow(&protocol.advice_queries, 3);
        assert!(column::column_type(&advice_query.q.column) == 0, 1);
        assert!(column::column_index(&advice_query.q.column) == 4, 1);
        assert!(!rotation::is_neg(&advice_query.q.rotation), 1);
        assert!(rotation::value(&advice_query.q.rotation) == 1, 1);

        let permutation_column = vector::borrow(&protocol.permutation_columns, 2);
        assert!(column::column_type(permutation_column) == 0, 1);
        assert!(column::column_index(permutation_column) == 3, 1);

        protocol
    }
}

module halo2_verifier::protocol {
    use std::bn254_algebra::{G1, Fr};
    use std::error;
    use std::option;
    use std::vector;

    use aptos_std::crypto_algebra::Element;
    use aptos_std::from_bcs;
    use aptos_std::math64::max;

    use halo2_verifier::bn254_utils::{Self, deserialize_g1_from_halo2, deserialize_fr};
    use halo2_verifier::column::{Self, Column};
    use halo2_verifier::column_query::{Self, ColumnQuery};
    use halo2_verifier::domain::{Self, Domain};
    use halo2_verifier::expression::{Self, Expression};
    use halo2_verifier::multivariate_poly;
    use halo2_verifier::i32::{Self, I32};

    #[test_only]
    use aptos_std::crypto_algebra::enable_cryptography_algebra_natives;
    #[test_only]
    use aptos_std::string_utils;
    #[test_only]
    use halo2_verifier::bn254_utils::{serialize_fr, serialize_g1_uncompressed};
    #[test_only]
    use std::string::{Self, String};
    #[test_only]
    use std::vector::map_ref;


    const CurvePointLen: u64 = 32;


    const QUERY_NOT_FOUND: u64 = 1;

    struct Protocol has drop {
        vk_transcript_repr: Element<Fr>,
        fixed_commitments: vector<Element<G1>>,
        permutation_commitments: vector<Element<G1>>,
        query_instance: bool,
        // for ipa, true; for kzg, false
        k: u8,
        /// it's `advice_queries.count_by(|q| q.column).max`
        max_num_query_of_advice_column: u32,

        /// it's constraint_system's degree()
        cs_degree: u32,

        num_fixed_columns: u64,
        num_instance_columns: u64,

        advice_column_phase: vector<u8>,
        challenge_phase: vector<u8>,

        advice_queries: vector<ColumnQuery>,
        instance_queries: vector<ColumnQuery>,
        fixed_queries: vector<ColumnQuery>,

        permutation_columns: vector<Column>,
        gates: vector<Expression>,
        lookups: vector<Lookup>,
    }


    struct Lookup has drop {
        input_expressions: vector<Expression>,
        table_expressions: vector<Expression>,
    }

    // --- Protocol Deserialzation start ---

    /// deserialize from a list of vector<vector<u8>> into Protocol.
    /// it corresponds to the serialization in the rust code of circuit-info-generator.
    public fun from_bytes(
        general_info: vector<vector<u8>>,
        advice_queries: vector<vector<u8>>,
        instance_queries: vector<vector<u8>>,
        fixed_queries: vector<vector<u8>>,
        permutation_columns: vector<vector<u8>>,
        gates: vector<vector<u8>>,
        lookups_input_exprs: vector<vector<u8>>,
        lookups_table_exprs: vector<vector<u8>>,
    ): Protocol {
        let challenge_phase = vector::pop_back(&mut general_info);
        let advice_column_phase = vector::pop_back(&mut general_info);
        let num_instance_columns = from_bcs::to_u64(vector::pop_back(&mut general_info));
        let num_fixed_columns = from_bcs::to_u64(vector::pop_back(&mut general_info));
        let cs_degree = from_bcs::to_u32(vector::pop_back(&mut general_info));
        let max_num_query_of_advice_column = from_bcs::to_u32(vector::pop_back(&mut general_info));
        let k = from_bcs::to_u8(vector::pop_back(&mut general_info));
        let query_instance = from_bcs::to_bool(vector::pop_back(&mut general_info));
        let permutation_commitments = deserialize_commitment_list(&vector::pop_back(&mut general_info));
        let fixed_commitments = deserialize_commitment_list(&vector::pop_back(&mut general_info));
        let vk_repr = option::destroy_some(deserialize_fr(&vector::pop_back(&mut general_info)));
        let advice_queries = vector::map_ref(&advice_queries, |q| {
            deserialize_column_query(q)
        });
        let instance_queries = vector::map_ref(&instance_queries, |q| {
            deserialize_column_query(q)
        });
        let fixed_queries = vector::map_ref(&fixed_queries, |q| {
            deserialize_column_query(q)
        });

        let permutation_columns = vector::map_ref(&permutation_columns, |q| deserialize_column(q));
        let gates = vector::map_ref(&gates, |q| deserialize_expression(q));

        let lookups = vector::empty();
        let lookups_input_exprs = vector::map_ref(&lookups_input_exprs, |q| deserialize_lookup_exprs(q));
        let lookups_table_exprs = vector::map_ref(&lookups_table_exprs, |q| deserialize_lookup_exprs(q));
        vector::zip(lookups_input_exprs, lookups_table_exprs, |p, q| vector::push_back(&mut lookups, Lookup {
            input_expressions: p,
            table_expressions: q,
        }));

        let protocol = Protocol {
            vk_transcript_repr: vk_repr,
            fixed_commitments,
            permutation_commitments,
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

    fun read_bytes(
        source_bytes: &vector<u8>,
        start_idx: u64,
        end_idx: u64,
    ): vector<u8> {
        let i = start_idx;
        let bytes = vector::empty();
        loop {
            if (i >= end_idx) {
                break
            };

            let b = vector::borrow(source_bytes, i);
            vector::push_back(&mut bytes, *b);

            i = i + 1;
        };

        bytes
    }

    fun deserialize_column_query(
        q: &vector<u8>,
    ): ColumnQuery {
        let column_type = from_bcs::to_u8(read_bytes(q, 0, 1));
        let index = from_bcs::to_u32(read_bytes(q, 1, 5));
        let next = from_bcs::to_bool(read_bytes(q, 5, 6));
        let rotation = from_bcs::to_u32(read_bytes(q, 6, 10));
        column_query::new(
            column::new(index, column_type),
            i32::new(next, rotation)
        )
    }

    fun deserialize_column(
        q: &vector<u8>,
    ): Column {
        let column_type = from_bcs::to_u8(read_bytes(q, 0, 1));
        let index = from_bcs::to_u32(read_bytes(q, 1, 5));
        let column = column::new(index, column_type);
        column
    }

    fun deserialize_expression(
        data: &vector<u8>,
    ): Expression {
        let terms = vector::empty();

        let term_len = from_bcs::to_u32(read_bytes(data, 0, 4));
        let i = 0;
        let idx = 4;
        loop {
            if (i >= term_len) {
                break
            };

            let coff = option::destroy_some(bn254_utils::deserialize_fr(&read_bytes(data, idx, idx + 32)));
            idx = idx + 32;

            let sparse_terms = vector::empty();
            let sparse_term_len = from_bcs::to_u32(read_bytes(data, idx, idx + 4));
            idx = idx + 4;
            let i_t = 0;

            loop {
                if (i_t >= sparse_term_len) {
                    break
                };

                let variable_index = from_bcs::to_u32(read_bytes(data, idx, idx + 4));
                idx = idx + 4;

                let power = from_bcs::to_u32(read_bytes(data, idx, idx + 4));
                idx = idx + 4;

                vector::push_back(&mut sparse_terms, multivariate_poly::new_sparse_term(variable_index, power));
                i_t = i_t + 1;
            };

            vector::push_back(&mut terms, multivariate_poly::new_term(coff, sparse_terms));
            i = i + 1;
        };

        expression::new(multivariate_poly::new_poly(terms))
    }

    fun deserialize_lookup_exprs(
        data: &vector<u8>,
    ): vector<Expression> {
        let expressions = vector::empty();

        let expr_len = from_bcs::to_u32(read_bytes(data, 0, 4));
        let i = 0;
        let idx = 4;
        loop {
            if (i >= expr_len) {
                break
            };

            let expr_bytes_len = (from_bcs::to_u32(read_bytes(data, idx, idx + 4)) as u64);
            idx = idx + 4;

            vector::push_back(&mut expressions, deserialize_expression(&read_bytes(data, idx, idx + expr_bytes_len)));
            idx = idx + expr_bytes_len;

            i = i + 1;
        };

        expressions
    }

    fun deserialize_commitment_list(bytes: &vector<u8>): vector<Element<G1>> {
        let i = 0;
        let bytes_len = vector::length(bytes);
        let result = vector::empty();
        while (i < bytes_len) {
            vector::push_back(
                &mut result,
                option::destroy_some(deserialize_g1_from_halo2(read_bytes(bytes, i, i + CurvePointLen)))
            );
            i = i + CurvePointLen;
        };
        result
    }
    // --- Protocol Deserialzation end ---


    public fun domain(p: &Protocol): Domain {
        domain::new(p.cs_degree, p.k)
    }

    public fun transcript_repr(self: &Protocol): Element<Fr> {
        self.vk_transcript_repr
    }

    public fun fixed_commitments(self: &Protocol): &vector<Element<G1>> {
        &self.fixed_commitments
    }

    public fun permutation_commitments(self: &Protocol): &vector<Element<G1>> {
        &self.permutation_commitments
    }

    public fun query_instance(protocol: &Protocol): bool {
        protocol.query_instance
    }

    public fun instance_queries(protocol: &Protocol): &vector<ColumnQuery> {
        &protocol.instance_queries
    }

    public fun advice_queries(protocol: &Protocol): &vector<ColumnQuery> {
        &protocol.advice_queries
    }

    public fun fixed_queries(protocol: &Protocol): &vector<ColumnQuery> {
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
    /// TODO(optimize): get_query_index is only called in one place, and we can optimize it for the specific usage.
    public fun get_query_index(protocol: &Protocol, column: &Column, rotation: &I32): u64 {
        let target_queries = if (column::is_fixed(column)) {
            &protocol.fixed_queries
        } else if (column::is_instance(column)) {
            &protocol.instance_queries
        } else if (column::is_advice(column)) {
            &protocol.advice_queries
        } else {
            abort error::invalid_state(QUERY_NOT_FOUND)
        };

        let (find, index) = vector::find(target_queries, |q| {
            let q: &ColumnQuery = q;
            (column_query::column(q) == column) && (column_query::rotation(q) == rotation)
        });
        assert!(find, error::invalid_state(QUERY_NOT_FOUND));
        index
    }

    public fun num_phase(protocol: &Protocol): u8 {
        let max_phase = 0;
        vector::for_each_ref(&protocol.advice_column_phase, |p| if (*p > max_phase) { max_phase = *p });
        vector::for_each_ref(&protocol.challenge_phase, |p| if (*p > max_phase) { max_phase = *p });
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

    #[test_only]
    struct ProtocolDisplay has drop {
        vk_transcript_repr: vector<u8>,
        fixed_commitments: vector<vector<u8>>,
        permutation_commitments: vector<vector<u8>>,
        query_instance: bool,
        // for ipa, true; for kzg, false
        k: u8,
        /// it's `advice_queries.count_by(|q| q.column).max`
        max_num_query_of_advice_column: u32,

        /// it's constraint_system's degree()
        cs_degree: u32,

        num_fixed_columns: u64,
        num_instance_columns: u64,

        advice_column_phase: vector<u8>,
        challenge_phase: vector<u8>,

        advice_queries: vector<ColumnQuery>,
        instance_queries: vector<ColumnQuery>,
        fixed_queries: vector<ColumnQuery>,

        permutation_columns: vector<Column>,
        gates: vector<vector<String>>,
        lookups: vector<LookupDisplay>,
    }

    #[test_only]
    struct LookupDisplay has drop {
        input_expressions: vector<vector<String>>,
        table_expressions: vector<vector<String>>,
    }

    #[test_only]
    public fun format(self: &Protocol): String {
        let display = ProtocolDisplay {
            vk_transcript_repr: serialize_fr(&self.vk_transcript_repr),
            fixed_commitments: map_ref(&self.fixed_commitments, |g| serialize_g1_uncompressed(g)),
            permutation_commitments: map_ref(&self.permutation_commitments, |g| serialize_g1_uncompressed(g)),
            query_instance: self.query_instance,
            k: self.k,
            max_num_query_of_advice_column: self.max_num_query_of_advice_column,
            cs_degree: self.cs_degree,
            num_fixed_columns: self.num_fixed_columns,
            num_instance_columns: self.num_instance_columns,
            advice_column_phase: self.advice_column_phase,
            challenge_phase: self.challenge_phase,
            advice_queries: self.advice_queries,
            instance_queries: self.instance_queries,
            fixed_queries: self.fixed_queries,
            permutation_columns: self.permutation_columns,
            gates: map_ref(&self.gates, |g| multivariate_poly::format(expression::poly(g))),
            lookups: map_ref(&self.lookups, |l| {
                let l: &Lookup = l;
                LookupDisplay {
                    input_expressions: map_ref(
                        &l.input_expressions,
                        |g| multivariate_poly::format(expression::poly(g))
                    ),
                    table_expressions: map_ref(&l.table_expressions, |g| multivariate_poly::format(expression::poly(g)))
                }
            })
        };
        string_utils::debug_string(&display)
    }


    #[test(s = @std)]
    fun test_serialize(s: &signer) {
        enable_cryptography_algebra_natives(s);
        let protocol = from_bytes(
            vector[
                x"e1b7a56758703487bc373d94283e5a82cb60ccb6c89b55f95c59bfad9de1961c",
                x"0000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000008032bfee27b8b44c67b4e94b573c0efff410a61e573fc0efc90aafafc260e1905132bfee27b8b44c67b4e94b573c0efff410a61e573fc0efc90aafafc260e1905132bfee27b8b44c67b4e94b573c0efff410a61e573fc0efc90aafafc260e19051b9aed5c1116492424abdca68fb84fb42a5f5dc5424c911e89fc05e785046dc4d",
                x"49dec335e762fbbdaaefd2fd222d90c0e3debcff45ed97a434ac431d125d8415cbce8d505c3a6fc016e29b97d88a191324050debe6485e6c3781fd9aeced8f2cc4df2c2bcc96cc6e5e11d0c8c383761addd98e22add6b8a168bd41ade081b44b",
                x"00",
                x"10",
                x"01000000",
                x"04000000",
                x"0600000000000000",
                x"0000000000000000",
                x"0000000000",
                x""
            ],
            vector[
                x"00010000000100000000",
                x"00020000000100000000",
                x"00030000000100000000",
                x"00040000000101000000",
                x"00000000000001000000"
            ],
            vector[],
            vector[
                x"ff050000000100000000",
                x"ff000000000100000000",
                x"ff020000000100000000",
                x"ff030000000100000000",
                x"ff040000000100000000",
                x"ff010000000100000000"
            ],
            vector[
                x"0001000000",
                x"0002000000",
                x"0003000000"
            ],
            vector[
                x"05000000000000f093f5e1439170b97948e833285d588181b64550b829a031e1724e643002000000020000000100000009000000010000000100000000000000000000000000000000000000000000000000000000000000020000000100000001000000080000000100000001000000000000000000000000000000000000000000000000000000000000000200000000000000010000000700000001000000010000000000000000000000000000000000000000000000000000000000000003000000030000000100000004000000010000000600000001000000010000000000000000000000000000000000000000000000000000000000000003000000000000000100000001000000010000000a00000001000000"
            ],
            vector[
                x"0100000030000000010000000100000000000000000000000000000000000000000000000000000000000000010000000000000001000000"
            ],
            vector[
                x"0100000030000000010000000100000000000000000000000000000000000000000000000000000000000000010000000500000001000000"
            ],
        );

        assert!(protocol.k == 0x10, 1);
        assert!(protocol.num_fixed_columns == 0x06, 1);

        let advice_query_len = vector::length(&protocol.advice_queries);
        assert!(advice_query_len == 5, 1);

        let advice_query = vector::borrow(&protocol.advice_queries, 3);
        assert!(column::column_type(column_query::column(advice_query)) == 0, 1);
        assert!(column::column_index(column_query::column(advice_query)) == 4, 1);
        assert!(!i32::is_neg(column_query::rotation(advice_query)), 1);
        assert!(i32::abs(column_query::rotation(advice_query)) == 1, 1);

        let permutation_column = vector::borrow(&protocol.permutation_columns, 2);
        assert!(column::column_type(permutation_column) == 0, 1);
        assert!(column::column_index(permutation_column) == 3, 1);

        let gate_repr = vector::map_ref(&protocol.gates, |gate| {
            let g: &Expression = gate;
            multivariate_poly::format(expression::poly(g))
        });
        let expected_gate_repr = vector[
            vector[
                string::utf8(b"0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000 * x_2 * x_9"),
                string::utf8(b"0x0000000000000000000000000000000000000000000000000000000000000001 * x_1 * x_8"),
                string::utf8(b"0x0000000000000000000000000000000000000000000000000000000000000001 * x_0 * x_7"),
                string::utf8(b"0x0000000000000000000000000000000000000000000000000000000000000001 * x_3 * x_4 * x_6"),
                string::utf8(b"0x0000000000000000000000000000000000000000000000000000000000000001 * x_0 * x_1 * x_10")
            ]
        ];
        assert!(gate_repr == expected_gate_repr, 100);
        assert!(vector::length(&protocol.lookups) == 1, 101);

        let lookup = vector::borrow<Lookup>(&protocol.lookups, 0);
        let lookup_input_repr = vector::map_ref(&lookup.input_expressions, |expr| {
            let g: &Expression = expr;
            multivariate_poly::format(expression::poly(g))
        });
        let lookup_table_repr = vector::map_ref(&lookup.table_expressions, |expr| {
            let g: &Expression = expr;
            multivariate_poly::format(expression::poly(g))
        });
        assert!(
            lookup_input_repr == vector[vector[string::utf8(
                b"0x0000000000000000000000000000000000000000000000000000000000000001 * x_0"
            )]],
            102
        );
        assert!(
            lookup_table_repr == vector[vector[string::utf8(
                b"0x0000000000000000000000000000000000000000000000000000000000000001 * x_5"
            )]],
            103
        );
    }
}

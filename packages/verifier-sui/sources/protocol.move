// Copyright (c) zkMove Authors

module halo2_verifier::protocol {
    use sui::bn254;
    use sui::group_ops::Element;
    use halo2_common::bn254_utils::{deserialize_fr, deserialize_g1, serialize_fr, serialize_g1};
    use halo2_common::column::{Self, Column};
    use halo2_common::column_query::{Self, ColumnQuery};
    use halo2_common::domain::{Self, Domain};
    use halo2_common::i32::{Self, I32};

    const CURVE_POINT_LEN: u64 = 32;
    const QUERY_NOT_FOUND: u64 = 1;
    const E_INVALID_BCS_LENGTH: u64 = 100;
    const E_INVALID_BOOL: u64 = 101;
    const E_INVALID_READ_RANGE: u64 = 102;

    public struct Protocol has store, drop {
        vk_transcript_repr: vector<u8>,
        fixed_commitments: vector<vector<u8>>,
        permutation_commitments: vector<vector<u8>>,
        k: u8,
        max_num_query_of_advice_column: u32,
        cs_degree: u32,
        num_fixed_columns: u64,
        num_instance_columns: u64,
        advice_column_phase: vector<u8>,
        challenge_phase: vector<u8>,
        use_u8_fields: u8,
        use_u8_queries: u8,
        advice_queries: vector<ColumnQuery>,
        instance_queries: vector<ColumnQuery>,
        fixed_queries: vector<ColumnQuery>,
        permutation_columns: vector<Column>,
        fields_pool: vector<vector<u8>>,
        gates: vector<vector<u8>>,
        lookups: vector<Lookup>,
        shuffles: vector<Shuffle>,
    }

    public struct Lookup has store, drop {
        input_expressions: vector<u8>,
        table_expressions: vector<u8>,
    }

    public struct Shuffle has store, drop {
        input_expressions: vector<u8>,
        shuffle_expressions: vector<u8>,
    }

    public fun from_bytes(
        mut general_info: vector<vector<u8>>,
        advice_queries: vector<vector<u8>>,
        instance_queries: vector<vector<u8>>,
        fixed_queries: vector<vector<u8>>,
        permutation_columns: vector<vector<u8>>,
        fields_pool: vector<vector<u8>>,
        gates: vector<vector<u8>>,
        lookups_input_exprs: vector<vector<u8>>,
        lookups_table_exprs: vector<vector<u8>>,
        shuffles_input_exprs: vector<vector<u8>>,
        shuffles_exprs: vector<vector<u8>>,
    ): Protocol {
        let use_u8_fields = to_u8(vector::pop_back(&mut general_info));
        let use_u8_queries = to_u8(vector::pop_back(&mut general_info));
        let challenge_phase = vector::pop_back(&mut general_info);
        let advice_column_phase = vector::pop_back(&mut general_info);
        let num_instance_columns = to_u64(vector::pop_back(&mut general_info));
        let num_fixed_columns = to_u64(vector::pop_back(&mut general_info));
        let cs_degree = to_u32(vector::pop_back(&mut general_info));
        let max_num_query_of_advice_column = to_u32(vector::pop_back(&mut general_info));
        let k = to_u8(vector::pop_back(&mut general_info));
        let permutation_commitments = deserialize_commitment_list(&vector::pop_back(&mut general_info));
        let fixed_commitments = deserialize_commitment_list(&vector::pop_back(&mut general_info));
        let vk_repr = option::destroy_some(deserialize_fr(&vector::pop_back(&mut general_info)));

        Protocol {
            vk_transcript_repr: serialize_fr(&vk_repr),
            fixed_commitments: serialize_commitments(&fixed_commitments),
            permutation_commitments: serialize_commitments(&permutation_commitments),
            k,
            max_num_query_of_advice_column,
            cs_degree,
            num_fixed_columns,
            num_instance_columns,
            advice_column_phase,
            challenge_phase,
            use_u8_fields,
            use_u8_queries,
            advice_queries: deserialize_column_queries(&advice_queries),
            instance_queries: deserialize_column_queries(&instance_queries),
            fixed_queries: deserialize_column_queries(&fixed_queries),
            permutation_columns: deserialize_columns(&permutation_columns),
            fields_pool,
            gates,
            lookups: zip_lookups(lookups_input_exprs, lookups_table_exprs),
            shuffles: zip_shuffles(shuffles_input_exprs, shuffles_exprs),
        }
    }

    public fun domain(p: &Protocol): Domain {
        domain::new(p.cs_degree, p.k)
    }

    public fun vk_transcript_repr(self: &Protocol): &vector<u8> { &self.vk_transcript_repr }
    public fun fixed_commitments(self: &Protocol): &vector<vector<u8>> { &self.fixed_commitments }
    public fun permutation_commitments(self: &Protocol): &vector<vector<u8>> { &self.permutation_commitments }
    public fun instance_queries(protocol: &Protocol): &vector<ColumnQuery> { &protocol.instance_queries }
    public fun advice_queries(protocol: &Protocol): &vector<ColumnQuery> { &protocol.advice_queries }
    public fun fixed_queries(protocol: &Protocol): &vector<ColumnQuery> { &protocol.fixed_queries }
    public fun lookups(protocol: &Protocol): &vector<Lookup> { &protocol.lookups }
    public fun shuffles(protocol: &Protocol): &vector<Shuffle> { &protocol.shuffles }
    public fun gates(protocol: &Protocol): &vector<vector<u8>> { &protocol.gates }
    public fun fields_pool(protocol: &Protocol): &vector<vector<u8>> { &protocol.fields_pool }
    public fun input_exprs(self: &Lookup): &vector<u8> { &self.input_expressions }
    public fun table_exprs(self: &Lookup): &vector<u8> { &self.table_expressions }
    public fun shuffle_input_exprs(self: &Shuffle): &vector<u8> { &self.input_expressions }
    public fun shuffle_exprs(self: &Shuffle): &vector<u8> { &self.shuffle_expressions }

    public fun blinding_factors(protocol: &Protocol): u64 {
        let factors = max_u64((protocol.max_num_query_of_advice_column as u64), 1);
        let factors = max_u64(3, factors);
        let factors = factors + 1;
        factors + 1
    }

    public fun permutation_columns(protocol: &Protocol): &vector<Column> { &protocol.permutation_columns }

    public fun get_query_index(protocol: &Protocol, column: &Column, rotation: &I32): u64 {
        let target_queries = if (column::is_fixed(column)) {
            &protocol.fixed_queries
        } else if (column::is_instance(column)) {
            &protocol.instance_queries
        } else if (column::is_advice(column)) {
            &protocol.advice_queries
        } else {
            abort QUERY_NOT_FOUND
        };

        let mut i = 0;
        while (i < target_queries.length()) {
            let q = &target_queries[i];
            if (column_query::column(q) == column && column_query::rotation(q) == rotation) {
                return i
            };
            i = i + 1;
        };
        abort QUERY_NOT_FOUND
    }

    public fun num_phase(protocol: &Protocol): u8 {
        let mut max_phase = 0;
        let mut i = 0;
        while (i < protocol.advice_column_phase.length()) {
            if (protocol.advice_column_phase[i] > max_phase) {
                max_phase = protocol.advice_column_phase[i];
            };
            i = i + 1;
        };
        let mut i = 0;
        while (i < protocol.challenge_phase.length()) {
            if (protocol.challenge_phase[i] > max_phase) {
                max_phase = protocol.challenge_phase[i];
            };
            i = i + 1;
        };
        max_phase + 1
    }

    public fun num_challenges(protocol: &Protocol): u64 { protocol.challenge_phase.length() }
    public fun num_instance_columns(protocol: &Protocol): u64 { protocol.num_instance_columns }
    public fun num_advice_columns(protocol: &Protocol): u64 { protocol.advice_column_phase.length() }
    public fun advice_column_phase(protocol: &Protocol): &vector<u8> { &protocol.advice_column_phase }
    public fun challenge_phase(protocol: &Protocol): &vector<u8> { &protocol.challenge_phase }
    public fun use_u8_fields(protocol: &Protocol): u8 { protocol.use_u8_fields }
    public fun use_u8_queries(protocol: &Protocol): u8 { protocol.use_u8_queries }
    public fun num_lookup(protocol: &Protocol): u64 { protocol.lookups.length() }
    public fun num_shuffle(protocol: &Protocol): u64 { protocol.shuffles.length() }
    public fun permutation_chunk_size(protocol: &Protocol): u32 { protocol.cs_degree - 2 }

    public fun num_permutation_z(protocol: &Protocol): u64 {
        let chunk_size = permutation_chunk_size(protocol) as u64;
        let permutation_columns_len = protocol.permutation_columns.length();
        let chunk = permutation_columns_len / chunk_size;
        if (permutation_columns_len % chunk_size != 0) { chunk + 1 } else { chunk }
    }

    fun deserialize_column_queries(bytes: &vector<vector<u8>>): vector<ColumnQuery> {
        let mut result = vector[];
        let mut i = 0;
        while (i < bytes.length()) {
            vector::push_back(&mut result, deserialize_column_query(&bytes[i]));
            i = i + 1;
        };
        result
    }

    fun deserialize_columns(bytes: &vector<vector<u8>>): vector<Column> {
        let mut result = vector[];
        let mut i = 0;
        while (i < bytes.length()) {
            vector::push_back(&mut result, deserialize_column(&bytes[i]));
            i = i + 1;
        };
        result
    }

    fun deserialize_column_query(q: &vector<u8>): ColumnQuery {
        let column_type = to_u8(read_bytes(q, 0, 1));
        let index = to_u32(read_bytes(q, 1, 5));
        let next = to_bool(read_bytes(q, 5, 6));
        let rotation = to_u32(read_bytes(q, 6, 10));
        column_query::new(column::new(index, column_type), i32::new(next, rotation))
    }

    fun deserialize_column(q: &vector<u8>): Column {
        let column_type = to_u8(read_bytes(q, 0, 1));
        let index = to_u32(read_bytes(q, 1, 5));
        column::new(index, column_type)
    }

    fun deserialize_commitment_list(bytes: &vector<u8>): vector<Element<bn254::G1>> {
        let mut i = 0;
        let mut result = vector[];
        while (i < bytes.length()) {
            vector::push_back(
                &mut result,
                option::destroy_some(deserialize_g1(&read_bytes(bytes, i, i + CURVE_POINT_LEN))),
            );
            i = i + CURVE_POINT_LEN;
        };
        result
    }

    fun serialize_commitments(commitments: &vector<Element<bn254::G1>>): vector<vector<u8>> {
        let mut result = vector[];
        let mut i = 0;
        while (i < commitments.length()) {
            vector::push_back(&mut result, serialize_g1(&commitments[i]));
            i = i + 1;
        };
        result
    }

    fun zip_lookups(input_exprs: vector<vector<u8>>, table_exprs: vector<vector<u8>>): vector<Lookup> {
        let len = input_exprs.length();
        assert!(len == table_exprs.length(), E_INVALID_BCS_LENGTH);
        let mut result = vector[];
        let mut i = 0;
        while (i < len) {
            vector::push_back(&mut result, Lookup {
                input_expressions: input_exprs[i],
                table_expressions: table_exprs[i],
            });
            i = i + 1;
        };
        result
    }

    fun zip_shuffles(input_exprs: vector<vector<u8>>, shuffle_exprs: vector<vector<u8>>): vector<Shuffle> {
        let len = input_exprs.length();
        assert!(len == shuffle_exprs.length(), E_INVALID_BCS_LENGTH);
        let mut result = vector[];
        let mut i = 0;
        while (i < len) {
            vector::push_back(&mut result, Shuffle {
                input_expressions: input_exprs[i],
                shuffle_expressions: shuffle_exprs[i],
            });
            i = i + 1;
        };
        result
    }

    fun read_bytes(source_bytes: &vector<u8>, start_idx: u64, end_idx: u64): vector<u8> {
        assert!(start_idx <= end_idx && end_idx <= source_bytes.length(), E_INVALID_READ_RANGE);
        let mut bytes = vector[];
        let mut i = start_idx;
        while (i < end_idx) {
            vector::push_back(&mut bytes, source_bytes[i]);
            i = i + 1;
        };
        bytes
    }

    fun to_u8(bytes: vector<u8>): u8 {
        assert!(bytes.length() == 1, E_INVALID_BCS_LENGTH);
        bytes[0]
    }

    fun to_bool(bytes: vector<u8>): bool {
        let value = to_u8(bytes);
        assert!(value <= 1, E_INVALID_BOOL);
        value == 1
    }

    fun to_u32(bytes: vector<u8>): u32 {
        assert!(bytes.length() == 4, E_INVALID_BCS_LENGTH);
        (bytes[0] as u32)
            | ((bytes[1] as u32) << 8)
            | ((bytes[2] as u32) << 16)
            | ((bytes[3] as u32) << 24)
    }

    fun to_u64(bytes: vector<u8>): u64 {
        assert!(bytes.length() == 8, E_INVALID_BCS_LENGTH);
        (bytes[0] as u64)
            | ((bytes[1] as u64) << 8)
            | ((bytes[2] as u64) << 16)
            | ((bytes[3] as u64) << 24)
            | ((bytes[4] as u64) << 32)
            | ((bytes[5] as u64) << 40)
            | ((bytes[6] as u64) << 48)
            | ((bytes[7] as u64) << 56)
    }

    fun max_u64(a: u64, b: u64): u64 {
        if (a > b) { a } else { b }
    }
}

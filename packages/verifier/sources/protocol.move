module halo2_verifier::protocol {
    use std::bn254_algebra::G1;
    use std::error;
    use std::option;
    use std::vector::{Self, map_ref};

    use aptos_std::crypto_algebra::Element;
    use aptos_std::from_bcs;
    use aptos_std::math64::max;

    use halo2_common::bn254_utils::{deserialize_g1, deserialize_fr, serialize_fr, serialize_g1};
    use halo2_common::column::{Self, Column};
    use halo2_common::column_query::{Self, ColumnQuery};
    use halo2_common::domain::{Self, Domain};
    use halo2_common::i32::{Self, I32};

    const CurvePointLen: u64 = 32;


    const QUERY_NOT_FOUND: u64 = 1;

    struct Protocol has key, store, drop {
        // Fr in bytes
        vk_transcript_repr: vector<u8>,
        // G1 in arkworks compressed
        fixed_commitments: vector<vector<u8>>,
        // G1 in arkworks compressed
        permutation_commitments: vector<vector<u8>>,
        // query_instance: bool, // for ipa, true; for kzg, false
        k: u8,
        /// it's `advice_queries.count_by(|q| q.column).max`
        max_num_query_of_advice_column: u32,

        /// it's constraint_system's degree()
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
        // list of Fr in bytes
        fields_pool: vector<vector<u8>>,
        gates: vector<vector<u8>>,
        lookups: vector<Lookup>,
        shuffles: vector<Shuffle>,
    }

    struct Lookup has store, drop {
        input_expressions: vector<u8>,
        table_expressions: vector<u8>,
    }
    struct Shuffle has store, drop {
        input_expressions: vector<u8>,
        shuffle_expressions: vector<u8>,
    }

    // --- Protocol Deserialzation start ---

    /// deserialize from a list of vector<vector<u8>> into Protocol.
    /// it corresponds to the serialization in the rust code of shape-generator.
    public fun from_bytes(
        general_info: vector<vector<u8>>,
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
        let use_u8_fields = from_bcs::to_u8(vector::pop_back(&mut general_info));
        let use_u8_queries = from_bcs::to_u8(vector::pop_back(&mut general_info));
        let challenge_phase = vector::pop_back(&mut general_info);
        let advice_column_phase = vector::pop_back(&mut general_info);
        let num_instance_columns = from_bcs::to_u64(vector::pop_back(&mut general_info));
        let num_fixed_columns = from_bcs::to_u64(vector::pop_back(&mut general_info));
        let cs_degree = from_bcs::to_u32(vector::pop_back(&mut general_info));
        let max_num_query_of_advice_column = from_bcs::to_u32(vector::pop_back(&mut general_info));
        let k = from_bcs::to_u8(vector::pop_back(&mut general_info));

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
        // let fields_pool = vector::map_ref(&fields_pool, |e| option::destroy_some(deserialize_fr(e)));

        let lookups = vector::empty();
        vector::zip(lookups_input_exprs, lookups_table_exprs, |p, q| vector::push_back(&mut lookups, Lookup {
            input_expressions: p,
            table_expressions: q,
        }));

        let shuffles = vector::empty();
        vector::zip(shuffles_input_exprs, shuffles_exprs, |p, q| vector::push_back(&mut shuffles, Shuffle {
            input_expressions: p,
            shuffle_expressions: q,
        }));

        let protocol = Protocol {
            vk_transcript_repr: serialize_fr(&vk_repr),
            fixed_commitments: map_ref(&fixed_commitments, |c| serialize_g1(c)),
            permutation_commitments: map_ref(&permutation_commitments, |c| serialize_g1(c)),
            k,
            max_num_query_of_advice_column,
            cs_degree,
            num_fixed_columns,
            num_instance_columns,
            advice_column_phase,
            challenge_phase,
            use_u8_fields,
            use_u8_queries,
            advice_queries,
            instance_queries,
            fixed_queries,
            permutation_columns,
            fields_pool,
            gates,
            lookups,
            shuffles,
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

    fun deserialize_commitment_list(bytes: &vector<u8>): vector<Element<G1>> {
        let i = 0;
        let bytes_len = vector::length(bytes);
        let result = vector::empty();
        while (i < bytes_len) {
            vector::push_back(
                &mut result,
                option::destroy_some(deserialize_g1(&read_bytes(bytes, i, i + CurvePointLen)))
            );
            i = i + CurvePointLen;
        };
        result
    }
    // --- Protocol Deserialzation end ---


    public fun domain(p: &Protocol): Domain {
        domain::new(p.cs_degree, p.k)
    }

    public fun vk_transcript_repr(self: &Protocol): &vector<u8> {
        &self.vk_transcript_repr
    }

    public fun fixed_commitments(self: &Protocol): &vector<vector<u8>> {
        &self.fixed_commitments
    }

    public fun permutation_commitments(self: &Protocol): &vector<vector<u8>> {
        &self.permutation_commitments
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

    public fun shuffles(protocol: &Protocol): &vector<Shuffle> {
        &protocol.shuffles
    }

    public fun gates(protocol: &Protocol): &vector<vector<u8>> {
        &protocol.gates
    }

    public fun fields_pool(protocol: &Protocol): &vector<vector<u8>> {
        &protocol.fields_pool
    }

    public fun input_exprs(self: &Lookup): &vector<u8> {
        &self.input_expressions
    }

    public fun table_exprs(self: &Lookup): &vector<u8> {
        &self.table_expressions
    }

    public fun shuffle_input_exprs(self: &Shuffle): &vector<u8> {
        &self.input_expressions
    }

    public fun shuffle_exprs(self: &Shuffle): &vector<u8> {
        &self.shuffle_expressions
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

    public fun use_u8_fields(protocol: &Protocol): u8 {
        protocol.use_u8_fields
    }

    public fun use_u8_queries(protocol: &Protocol): u8 {
        protocol.use_u8_queries
    }

    public fun num_lookup(protocol: &Protocol): u64 {
        vector::length(&protocol.lookups)
    }

    public fun num_shuffle(protocol: &Protocol): u64 {
        vector::length(&protocol.shuffles)
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
}
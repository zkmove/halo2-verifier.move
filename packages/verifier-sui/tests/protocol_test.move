// Copyright (c) zkMove Authors

#[test_only]
module halo2_verifier::protocol_test {
    use sui::bn254;
    use halo2_common::bn254_utils::{serialize_fr, serialize_g1};
    use halo2_common::column;
    use halo2_common::i32;
    use halo2_verifier::protocol;

    fun bcs_u8(value: u8): vector<u8> { vector[value] }
    fun bcs_bool(value: bool): vector<u8> { vector[if (value) { 1 } else { 0 }] }

    fun bcs_u32(value: u32): vector<u8> {
        vector[
            ((value >> 0) & 0xFF as u8),
            ((value >> 8) & 0xFF as u8),
            ((value >> 16) & 0xFF as u8),
            ((value >> 24) & 0xFF as u8),
        ]
    }

    fun bcs_u64(value: u64): vector<u8> {
        vector[
            ((value >> 0) & 0xFF as u8),
            ((value >> 8) & 0xFF as u8),
            ((value >> 16) & 0xFF as u8),
            ((value >> 24) & 0xFF as u8),
            ((value >> 32) & 0xFF as u8),
            ((value >> 40) & 0xFF as u8),
            ((value >> 48) & 0xFF as u8),
            ((value >> 56) & 0xFF as u8),
        ]
    }

    fun column_bytes(column_type: u8, index: u32): vector<u8> {
        let mut bytes = vector[column_type];
        vector::append(&mut bytes, bcs_u32(index));
        bytes
    }

    fun query_bytes(column_type: u8, index: u32, positive_rotation: bool, rotation: u32): vector<u8> {
        let mut bytes = column_bytes(column_type, index);
        vector::append(&mut bytes, bcs_bool(positive_rotation));
        vector::append(&mut bytes, bcs_u32(rotation));
        bytes
    }

    fun commitment_list(points: vector<vector<u8>>): vector<u8> {
        let mut bytes = vector[];
        let mut i = 0;
        while (i < points.length()) {
            vector::append(&mut bytes, points[i]);
            i = i + 1;
        };
        bytes
    }

    fun sample_protocol(): protocol::Protocol {
        let g = bn254::g1_generator();
        let two_g = bn254::g1_mul(&bn254::scalar_from_u64(2), &g);
        let vk_repr = serialize_fr(&bn254::scalar_from_u64(42));
        let fixed_commitments = commitment_list(vector[serialize_g1(&g), serialize_g1(&two_g)]);
        let permutation_commitments = commitment_list(vector[serialize_g1(&two_g)]);

        let general_info = vector[
            vk_repr,
            fixed_commitments,
            permutation_commitments,
            bcs_u8(4),                  // k
            bcs_u32(2),                 // max_num_query_of_advice_column
            bcs_u32(5),                 // cs_degree
            bcs_u64(2),                 // num_fixed_columns
            bcs_u64(1),                 // num_instance_columns
            vector[0, 1, 2],            // advice_column_phase
            vector[0, 2],               // challenge_phase
            bcs_u8(0),                  // use_u8_queries
            bcs_u8(0),                  // use_u8_fields
        ];

        protocol::from_bytes(
            general_info,
            vector[query_bytes(1, 0, true, 0), query_bytes(1, 1, false, 2)],
            vector[query_bytes(3, 0, true, 1)],
            vector[query_bytes(2, 1, true, 0)],
            vector[column_bytes(1, 0), column_bytes(1, 1), column_bytes(2, 0), column_bytes(3, 0)],
            vector[serialize_fr(&bn254::scalar_from_u64(7))],
            vector[vector[0x00, 0x00]],
            vector[vector[0x01]],
            vector[vector[0x02]],
            vector[vector[0x03]],
            vector[vector[0x04]],
        )
    }

    #[test]
    fun test_from_bytes_and_accessors() {
        let p = sample_protocol();

        assert!(protocol::vk_transcript_repr(&p) == serialize_fr(&bn254::scalar_from_u64(42)), 1000);
        assert!(protocol::fixed_commitments(&p).length() == 2, 1001);
        assert!(protocol::permutation_commitments(&p).length() == 1, 1002);
        assert!(protocol::advice_queries(&p).length() == 2, 1003);
        assert!(protocol::instance_queries(&p).length() == 1, 1004);
        assert!(protocol::fixed_queries(&p).length() == 1, 1005);
        assert!(protocol::permutation_columns(&p).length() == 4, 1006);
        assert!(protocol::fields_pool(&p).length() == 1, 1007);
        assert!(protocol::gates(&p).length() == 1, 1008);
        assert!(protocol::num_lookup(&p) == 1, 1009);
        assert!(protocol::num_shuffle(&p) == 1, 1010);
        assert!(protocol::num_challenges(&p) == 2, 1011);
        assert!(protocol::num_instance_columns(&p) == 1, 1012);
        assert!(protocol::num_advice_columns(&p) == 3, 1013);
        assert!(protocol::use_u8_fields(&p) == 0, 1014);
        assert!(protocol::use_u8_queries(&p) == 0, 1015);
    }

    #[test]
    fun test_derived_values_and_query_lookup() {
        let p = sample_protocol();
        let d = protocol::domain(&p);
        assert!(halo2_common::domain::k(&d) == 4, 2000);
        assert!(halo2_common::domain::n(&d) == 16, 2001);
        assert!(protocol::blinding_factors(&p) == 5, 2002);
        assert!(protocol::permutation_chunk_size(&p) == 3, 2003);
        assert!(protocol::num_permutation_z(&p) == 2, 2004);
        assert!(protocol::num_phase(&p) == 3, 2005);

        let fixed_col = column::new(1, 2);
        assert!(protocol::get_query_index(&p, &fixed_col, &i32::from(0)) == 0, 2006);

        let advice_col = column::new(1, 1);
        assert!(protocol::get_query_index(&p, &advice_col, &i32::neg_from(2)) == 1, 2007);
    }

    #[test]
    fun test_lookup_and_shuffle_accessors() {
        let p = sample_protocol();
        let lookup = &protocol::lookups(&p)[0];
        assert!(protocol::input_exprs(lookup) == &vector[0x01], 3000);
        assert!(protocol::table_exprs(lookup) == &vector[0x02], 3001);

        let shuffle = &protocol::shuffles(&p)[0];
        assert!(protocol::shuffle_input_exprs(shuffle) == &vector[0x03], 3002);
        assert!(protocol::shuffle_exprs(shuffle) == &vector[0x04], 3003);
    }

    #[test, expected_failure]
    fun test_truncated_query_aborts() {
        let g = bn254::g1_generator();
        let general_info = vector[
            serialize_fr(&bn254::scalar_from_u64(42)),
            commitment_list(vector[serialize_g1(&g)]),
            commitment_list(vector[]),
            bcs_u8(4), bcs_u32(1), bcs_u32(5), bcs_u64(1), bcs_u64(0), vector[0], vector[], bcs_u8(0), bcs_u8(0),
        ];
        let _ = protocol::from_bytes(
            general_info,
            vector[vector[1, 0, 0]],
            vector[], vector[], vector[], vector[], vector[], vector[], vector[], vector[], vector[],
        );
    }

    #[test, expected_failure]
    fun test_lookup_zip_mismatch_aborts() {
        let g = bn254::g1_generator();
        let general_info = vector[
            serialize_fr(&bn254::scalar_from_u64(42)),
            commitment_list(vector[serialize_g1(&g)]),
            commitment_list(vector[]),
            bcs_u8(4), bcs_u32(1), bcs_u32(5), bcs_u64(1), bcs_u64(0), vector[0], vector[], bcs_u8(0), bcs_u8(0),
        ];
        let _ = protocol::from_bytes(
            general_info,
            vector[], vector[], vector[], vector[], vector[], vector[], vector[vector[1]], vector[], vector[], vector[],
        );
    }
}

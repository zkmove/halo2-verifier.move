// Copyright (c) zkMove Authors

#[test_only]
module halo2_verifier::lookup_test {
    use sui::bn254;
    use sui::group_ops;
    use halo2_common::bn254_utils::{serialize_fr, serialize_g1};
    use halo2_common::domain;
    use halo2_common::query;
    use halo2_verifier::lookup;
    use halo2_verifier::protocol;
    use halo2_verifier::transcript;

    fun scalar(value: u64): group_ops::Element<bn254::Scalar> {
        bn254::scalar_from_u64(value)
    }

    fun bcs_u8(value: u8): vector<u8> { vector[value] }
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

    fun sample_protocol(): protocol::Protocol {
        protocol::from_bytes(
            vector[
                serialize_fr(&scalar(42)),
                vector[], vector[], bcs_u8(4), bcs_u32(1), bcs_u32(3),
                bcs_u64(0), bcs_u64(0), vector[], vector[], bcs_u8(0), bcs_u8(0),
            ],
            vector[], vector[], vector[], vector[], vector[], vector[],
            vector[vector[0x00, 0x00]],
            vector[vector[0x00, 0x01]],
            vector[], vector[],
        )
    }

    fun proof_for_lookup(
        input_commitment: &group_ops::Element<bn254::G1>,
        table_commitment: &group_ops::Element<bn254::G1>,
        product_commitment: &group_ops::Element<bn254::G1>,
    ): vector<u8> {
        let mut proof = serialize_g1(input_commitment);
        vector::append(&mut proof, serialize_g1(table_commitment));
        vector::append(&mut proof, serialize_g1(product_commitment));
        vector::append(&mut proof, serialize_fr(&scalar(5)));
        vector::append(&mut proof, serialize_fr(&scalar(7)));
        vector::append(&mut proof, serialize_fr(&scalar(11)));
        vector::append(&mut proof, serialize_fr(&scalar(13)));
        vector::append(&mut proof, serialize_fr(&scalar(17)));
        proof
    }

    #[test]
    fun test_read_evaluate_and_queries() {
        let g = bn254::g1_generator();
        let input_commitment = g;
        let table_commitment = bn254::g1_mul(&scalar(2), &g);
        let product_commitment = bn254::g1_mul(&scalar(3), &g);
        let mut transcript = transcript::new(proof_for_lookup(&input_commitment, &table_commitment, &product_commitment));

        let permuted = lookup::read_permuted_commitments(&mut transcript);
        let commited = lookup::read_product_commitment(permuted, &mut transcript);
        let evaluated = lookup::evaluate(&commited, &mut transcript);
        assert!(transcript::proof_remaining_len(&transcript) == 0, 1000);

        let protocol = sample_protocol();
        let d = protocol::domain(&protocol);
        let x = scalar(19);
        let mut queries = vector[];
        lookup::queries(&vector[evaluated], &mut queries, &protocol, &d, &x);

        assert!(queries.length() == 5, 1001);
        assert!(group_ops::equal(query::point(&queries[0]), &x));
        assert!(group_ops::equal(query::eval(&queries[0]), &scalar(5)));
        assert!(group_ops::equal(query::point(&queries[1]), &x));
        assert!(group_ops::equal(query::eval(&queries[1]), &scalar(11)));
        assert!(group_ops::equal(query::point(&queries[2]), &x));
        assert!(group_ops::equal(query::eval(&queries[2]), &scalar(17)));
        assert!(group_ops::equal(query::point(&queries[3]), &domain::rotate_omega(&d, &x, &halo2_common::i32::neg_from(1))));
        assert!(group_ops::equal(query::eval(&queries[3]), &scalar(13)));
        assert!(group_ops::equal(query::point(&queries[4]), &domain::rotate_omega(&d, &x, &halo2_common::i32::from(1))));
        assert!(group_ops::equal(query::eval(&queries[4]), &scalar(7)));
    }

    #[test]
    fun test_expression_single_lookup() {
        let g = bn254::g1_generator();
        let input_commitment = g;
        let table_commitment = bn254::g1_mul(&scalar(2), &g);
        let product_commitment = bn254::g1_mul(&scalar(3), &g);
        let mut transcript = transcript::new(proof_for_lookup(&input_commitment, &table_commitment, &product_commitment));

        let permuted = lookup::read_permuted_commitments(&mut transcript);
        let commited = lookup::read_product_commitment(permuted, &mut transcript);
        let evaluated = lookup::evaluate(&commited, &mut transcript);
        let protocol = sample_protocol();
        let lookup_meta = &protocol::lookups(&protocol)[0];
        let coeff_pool = vector[scalar(2), scalar(3)];
        let empty = vector[];
        let mut results = vector[];

        lookup::expression(
            &evaluated,
            lookup_meta,
            0,
            0,
            &coeff_pool,
            &empty,
            &empty,
            &empty,
            &empty,
            &scalar(2),
            &scalar(3),
            &scalar(4),
            &scalar(10),
            &scalar(19),
            &scalar(23),
            &mut results,
        );

        assert!(results.length() == 5, 2000);
        assert!(group_ops::equal(&bn254::scalar_add(&results[0], &scalar(8)), &bn254::scalar_zero()), 2001);
        assert!(group_ops::equal(&results[1], &scalar(60)), 2002);
        assert!(group_ops::equal(&bn254::scalar_add(&results[2], &scalar(34020)), &bn254::scalar_zero()), 2003);
        assert!(group_ops::equal(&bn254::scalar_add(&results[3], &scalar(12)), &bn254::scalar_zero()), 2004);
        assert!(group_ops::equal(&bn254::scalar_add(&results[4], &scalar(72)), &bn254::scalar_zero()), 2005);
    }

    #[test, expected_failure]
    fun test_read_permuted_commitments_short_proof_aborts() {
        let mut transcript = transcript::new(vector[1, 2, 3]);
        let _ = lookup::read_permuted_commitments(&mut transcript);
    }
}

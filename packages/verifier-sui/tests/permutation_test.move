// Copyright (c) zkMove Authors

#[test_only]
module halo2_verifier::permutation_test {
    use sui::bn254;
    use sui::group_ops;
    use halo2_common::bn254_utils::{serialize_fr, serialize_g1};
    use halo2_common::domain;
    use halo2_common::msm;
    use halo2_common::query;
    use halo2_verifier::permutation;
    use halo2_verifier::protocol;
    use halo2_verifier::transcript;

    fun scalar(value: u64): group_ops::Element<bn254::Scalar> {
        bn254::scalar_from_u64(value)
    }

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

    fun sample_protocol(): protocol::Protocol {
        protocol::from_bytes(
            vector[
                serialize_fr(&scalar(42)),
                vector[],
                vector[],
                bcs_u8(4),
                bcs_u32(1),
                bcs_u32(3),
                bcs_u64(0),
                bcs_u64(0),
                vector[0],
                vector[],
                bcs_u8(0),
                bcs_u8(0),
            ],
            vector[query_bytes(1, 0, true, 0)],
            vector[],
            vector[],
            vector[column_bytes(1, 0)],
            vector[],
            vector[],
            vector[],
            vector[],
            vector[],
            vector[],
        )
    }

    fun proof_for_one_set(commitment: &group_ops::Element<bn254::G1>): vector<u8> {
        let mut proof = serialize_g1(commitment);
        vector::append(&mut proof, serialize_fr(&scalar(19)));
        vector::append(&mut proof, serialize_fr(&scalar(23)));
        proof
    }

    #[test]
    fun test_read_product_commitments_and_evaluate() {
        let g = bn254::g1_generator();
        let mut transcript = transcript::new(proof_for_one_set(&g));
        let committed = permutation::read_product_commitments(&mut transcript, 1);
        assert!(permutation::permutation_product_commitments(&committed).length() == 1, 1000);
        assert!(group_ops::equal(&permutation::permutation_product_commitments(&committed)[0], &g));

        let evaluated = permutation::evaluate(committed, &mut transcript);
        let p = sample_protocol();
        let d = protocol::domain(&p);
        let x = scalar(5);
        let mut queries = vector[];
        permutation::queries(evaluated, &mut queries, &p, &d, &x);

        assert!(queries.length() == 2, 1001);
        assert!(group_ops::equal(query::point(&queries[0]), &x));
        assert!(group_ops::equal(query::eval(&queries[0]), &scalar(19)));
        assert!(group_ops::equal(query::point(&queries[1]), &domain::rotate_omega(&d, &x, &halo2_common::i32::from(1))));
        assert!(group_ops::equal(query::eval(&queries[1]), &scalar(23)));
    }

    #[test]
    fun test_evalute_common_and_common_queries() {
        let g = bn254::g1_generator();
        let mut transcript = transcript::new(serialize_fr(&scalar(5)));
        let common = permutation::evalute_common(&mut transcript, 1);
        let mut queries = vector[];
        permutation::common_queries(common, &mut queries, vector[g], &scalar(7));

        assert!(queries.length() == 1, 2000);
        assert!(group_ops::equal(query::point(&queries[0]), &scalar(7)));
        assert!(group_ops::equal(query::eval(&queries[0]), &scalar(5)));
        let m = query::multiply(query::commitment(&queries[0]), &scalar(1));
        assert!(group_ops::equal(&msm::eval(&m), &g));
    }

    #[test]
    fun test_expressions_single_set() {
        let g = bn254::g1_generator();
        let mut transcript = transcript::new(proof_for_one_set(&g));
        let committed = permutation::read_product_commitments(&mut transcript, 1);
        let evaluated = permutation::evaluate(committed, &mut transcript);

        let mut common_transcript = transcript::new(serialize_fr(&scalar(5)));
        let common = permutation::evalute_common(&mut common_transcript, 1);
        let protocol = sample_protocol();
        let advice_evals = vector[scalar(7)];
        let empty = vector[];
        let mut results = vector[];

        permutation::expressions(
            &evaluated,
            &protocol,
            &common,
            &advice_evals,
            &empty,
            &empty,
            &scalar(2),
            &scalar(3),
            &scalar(4),
            &scalar(11),
            &scalar(13),
            &scalar(17),
            &mut results,
        );

        assert!(results.length() == 3, 3000);
        assert!(group_ops::equal(&bn254::scalar_add(&results[0], &scalar(36)), &bn254::scalar_zero()), 3001);
        assert!(group_ops::equal(&results[1], &scalar(1026)), 3002);
        assert!(group_ops::equal(&results[2], &scalar(13248)), 3003);
    }

    #[test, expected_failure]
    fun test_read_product_commitments_short_proof_aborts() {
        let mut transcript = transcript::new(vector[1, 2, 3]);
        let _ = permutation::read_product_commitments(&mut transcript, 1);
    }
}

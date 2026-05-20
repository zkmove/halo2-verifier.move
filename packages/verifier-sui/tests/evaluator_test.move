// Copyright (c) zkMove Authors

#[test_only]
module halo2_verifier::evaluator_test {
    use sui::bn254;
    use sui::group_ops;
    use halo2_verifier::evaluator;

    fun scalar(value: u64): group_ops::Element<bn254::Scalar> {
        bn254::scalar_from_u64(value)
    }

    fun empty_scalars(): vector<group_ops::Element<bn254::Scalar>> {
        vector[]
    }

    fun assert_scalar_eq(actual: &group_ops::Element<bn254::Scalar>, expected: u64) {
        assert!(group_ops::equal(actual, &scalar(expected)), expected);
    }

    #[test]
    fun test_evaluate_exprs_with_u8_indexes() {
        let fields_pool = vector[scalar(2), scalar(3)];
        let advice_evals = vector[scalar(7)];
        let fixed_evals = vector[scalar(5)];
        let instance_evals = vector[scalar(11)];
        let challenges = vector[scalar(13)];

        let exprs = vector[
            0x00, 0x00,                   // field[0] = 2
            0x02, 0x00,                   // fixed[0] = 5
            0x03, 0x00,                   // advice[0] = 7
            0x04, 0x00,                   // instance[0] = 11
            0x05, 0x00, 0x00, 0x00, 0x00, // challenge[0] = 13
            0x06, 0x03, 0x00,             // -advice[0]
            0x07, 0x00, 0x00, 0x02, 0x00, // field[0] + fixed[0] = 7
            0x08, 0x00, 0x01, 0x03, 0x00, // field[1] * advice[0] = 21
            0x09, 0x03, 0x00, 0x01,       // advice[0] * field[1] = 21
        ];

        let results = evaluator::evaluate_exprs(
            &exprs,
            0,
            0,
            &fields_pool,
            &advice_evals,
            &fixed_evals,
            &instance_evals,
            &challenges,
        );

        assert!(results.length() == 9, 900);
        assert_scalar_eq(&results[0], 2);
        assert_scalar_eq(&results[1], 5);
        assert_scalar_eq(&results[2], 7);
        assert_scalar_eq(&results[3], 11);
        assert_scalar_eq(&results[4], 13);
        assert!(group_ops::equal(&bn254::scalar_add(&results[5], &scalar(7)), &bn254::scalar_zero()), 901);
        assert_scalar_eq(&results[6], 7);
        assert_scalar_eq(&results[7], 21);
        assert_scalar_eq(&results[8], 21);
    }

    #[test]
    fun test_evaluate_exprs_with_u32_indexes() {
        let fields_pool = vector[scalar(2)];
        let advice_evals = empty_scalars();
        let fixed_evals = vector[scalar(5)];
        let instance_evals = empty_scalars();
        let challenges = empty_scalars();

        let exprs = vector[
            0x07,
            0x00, 0x00, 0x00, 0x00, 0x00, // field[0]
            0x02, 0x00, 0x00, 0x00, 0x00, // fixed[0]
        ];

        let results = evaluator::evaluate_exprs(
            &exprs,
            1,
            1,
            &fields_pool,
            &advice_evals,
            &fixed_evals,
            &instance_evals,
            &challenges,
        );

        assert!(results.length() == 1, 902);
        assert_scalar_eq(&results[0], 7);
    }

    #[test]
    fun test_compress_exprs() {
        let fields_pool = vector[scalar(2), scalar(3), scalar(4)];
        let empty = empty_scalars();
        let exprs = vector[
            0x00, 0x00,
            0x00, 0x01,
            0x00, 0x02,
        ];

        let compressed = evaluator::compress_exprs(
            &exprs,
            0,
            0,
            &fields_pool,
            &empty,
            &empty,
            &empty,
            &empty,
            &scalar(10),
        );

        assert_scalar_eq(&compressed, 234);
    }

    #[test, expected_failure]
    fun test_invalid_node_aborts() {
        let empty = empty_scalars();
        let _ = evaluator::evaluate_exprs(&vector[0xFF], 0, 0, &empty, &empty, &empty, &empty, &empty);
    }

    #[test, expected_failure]
    fun test_truncated_u32_index_aborts() {
        let fields_pool = vector[scalar(2)];
        let empty = empty_scalars();
        let _ = evaluator::evaluate_exprs(&vector[0x00, 0x00, 0x00], 1, 0, &fields_pool, &empty, &empty, &empty, &empty);
    }

    #[test, expected_failure]
    fun test_invalid_field_index_aborts() {
        let fields_pool = vector[scalar(2)];
        let empty = empty_scalars();
        let _ = evaluator::evaluate_exprs(&vector[0x00, 0x01], 0, 0, &fields_pool, &empty, &empty, &empty, &empty);
    }

    #[test, expected_failure]
    fun test_invalid_position_aborts() {
        let fields_pool = vector[scalar(2)];
        let empty = empty_scalars();
        let mut pos = 0;
        let _ = evaluator::evaluate_expression(&vector[], &mut pos, &fields_pool, &empty, &empty, &empty, &empty, true, true);
    }
}

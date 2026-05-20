// Copyright (c) zkMove Authors

#[allow(implicit_const_copy), test_only]
module halo2_common::bn254_test {
    use std::unit_test::assert_eq;
    use sui::bn254;
    use sui::group_ops;
    use sui::random;
    use halo2_common::bn254_serialize;
    use halo2_common::bn254_utils;

    const ORDER_BYTES: vector<u8> =
        x"010000f093f5e1439170b97948e833285d588181b64550b829a031e1724e6430";
    const ORDER_MINUS_ONE_BYTES: vector<u8> =
        x"000000f093f5e1439170b97948e833285d588181b64550b829a031e1724e6430";
    const LONG_SCALAR_BYTES: vector<u8> =
        x"010000f093f5e1439170b97948e833285d588181b64550b829a031e1724e643000";
    const SHORT_SCALAR_BYTES: vector<u8> =
        x"010000f093f5e1439170b97948e833285d588181b64550b829a031e1724e64";

    const G1_GENERATOR_BYTES: vector<u8> =
        x"0100000000000000000000000000000000000000000000000000000000000000";
    const G1_IDENTITY_BYTES: vector<u8> =
        x"0000000000000000000000000000000000000000000000000000000000000040";
    const LONG_G1_BYTES: vector<u8> =
        x"010000000000000000000000000000000000000000000000000000000000000000";
    const SHORT_G1_BYTES: vector<u8> =
        x"01000000000000000000000000000000000000000000000000000000000000";

    const G2_GENERATOR_BYTES: vector<u8> =
        x"edf692d95cbdde46ddda5ef7d422436779445c5e66006a42761e1f12efde0018c212f3aeb785e49712e7a9353349aaf1255dfb31b7bf60723a480d9293938e19";
    const G2_IDENTITY_BYTES: vector<u8> =
        x"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000040";
    const LONG_G2_BYTES: vector<u8> =
        x"edf692d95cbdde46ddda5ef7d422436779445c5e66006a42761e1f12efde0018c212f3aeb785e49712e7a9353349aaf1255dfb31b7bf60723a480d9293938e1900";
    const SHORT_G2_BYTES: vector<u8> =
        x"edf692d95cbdde46ddda5ef7d422436779445c5e66006a42761e1f12efde0018c212f3aeb785e49712e7a9353349aaf1255dfb31b7bf60723a480d9293938e";

    #[test]
    fun test_scalar_ops() {
        let zero = bn254::scalar_from_u64(0);
        let one = bn254::scalar_from_u64(1);
        assert!(group_ops::equal(&zero, &bn254::scalar_zero()));
        assert!(group_ops::equal(&one, &bn254::scalar_one()));
        assert!(!group_ops::equal(&zero, &bn254::scalar_one()));

        let two = bn254::scalar_add(&one, &one);
        let four = bn254::scalar_add(&two, &two);
        assert!(group_ops::equal(&four, &bn254::scalar_from_u64(4)));

        let eight = bn254::scalar_mul(&four, &two);
        assert!(group_ops::equal(&eight, &bn254::scalar_from_u64(8)));
        assert!(group_ops::equal(&bn254::scalar_mul(&zero, &eight), &zero));
        assert!(group_ops::equal(&bn254::scalar_mul(&eight, &one), &eight));

        let six = bn254::scalar_sub(&eight, &two);
        assert!(group_ops::equal(&six, &bn254::scalar_from_u64(6)));

        let minus_six = bn254::scalar_sub(&two, &eight);
        let three = bn254::scalar_add(&minus_six, &bn254::scalar_from_u64(9));
        assert!(group_ops::equal(&three, &bn254::scalar_from_u64(3)));

        let three = bn254::scalar_div(&two, &six);
        assert!(group_ops::equal(&three, &bn254::scalar_from_u64(3)));

        let minus_three = bn254::scalar_neg(&three);
        assert!(group_ops::equal(&bn254::scalar_add(&minus_three, &six), &bn254::scalar_from_u64(3)));
        assert!(group_ops::equal(&bn254::scalar_neg(&zero), &zero));

        let inv_three = bn254::scalar_inv(&three);
        assert!(group_ops::equal(&bn254::scalar_mul(&six, &inv_three), &bn254::scalar_from_u64(2)));

        let order_minus_one = bn254::scalar_from_bytes(&ORDER_MINUS_ONE_BYTES);
        let _ = bn254::scalar_add(&order_minus_one, &order_minus_one);
        let _ = bn254::scalar_mul(&order_minus_one, &order_minus_one);
    }

    #[test]
    fun test_scalar_more_ops() {
        let mut gen = random::new_generator_for_testing();
        let x = gen.generate_u32() as u64 % 1_000_000 + 1;
        let x_scalar = bn254::scalar_from_u64(x);
        let y = gen.generate_u32() as u64 % 1_000_000;
        let y_scalar = bn254::scalar_from_u64(y);

        assert!(group_ops::equal(&bn254::scalar_from_u64(x + y), &bn254::scalar_add(&x_scalar, &y_scalar)));

        let z_scalar = bn254::scalar_sub(&x_scalar, &y_scalar);
        assert!(group_ops::equal(&bn254::scalar_from_u64(x), &bn254::scalar_add(&z_scalar, &y_scalar)));

        assert!(group_ops::equal(&bn254::scalar_from_u64(x * y), &bn254::scalar_mul(&x_scalar, &y_scalar)));

        let z_scalar = bn254::scalar_div(&x_scalar, &y_scalar);
        assert!(group_ops::equal(&bn254::scalar_from_u64(y), &bn254::scalar_mul(&z_scalar, &x_scalar)));

        let z_scalar = bn254::scalar_neg(&x_scalar);
        assert!(group_ops::equal(&bn254::scalar_zero(), &bn254::scalar_add(&x_scalar, &z_scalar)));

        let z_scalar = bn254::scalar_inv(&x_scalar);
        assert!(group_ops::equal(&bn254::scalar_one(), &bn254::scalar_mul(&x_scalar, &z_scalar)));

        let mut i = 0u64;
        let mut z = bn254::scalar_add(&x_scalar, &y_scalar);
        while (i < 20) {
            let mut new_z = bn254::scalar_mul(&z, &x_scalar);
            new_z = bn254::scalar_add(&new_z, &y_scalar);
            let mut rev = bn254::scalar_sub(&new_z, &y_scalar);
            rev = bn254::scalar_div(&x_scalar, &rev);
            assert!(group_ops::equal(&z, &rev));

            let rev_as_bytes = *group_ops::bytes(&rev);
            let rev_scalar2 = bn254::scalar_from_bytes(&rev_as_bytes);
            assert!(group_ops::equal(&rev_scalar2, &rev));
            z = new_z;
            i = i + 1;
        };
    }

    #[test]
    fun test_scalar_to_bytes_regression() {
        let zero_bytes = *group_ops::bytes(&bn254::scalar_from_u64(0));
        assert_eq!(x"0000000000000000000000000000000000000000000000000000000000000000", zero_bytes);

        let eight_bytes = *group_ops::bytes(&bn254::scalar_from_u64(8));
        assert_eq!(x"0800000000000000000000000000000000000000000000000000000000000000", eight_bytes);

        let minus_one = bn254::scalar_sub(&bn254::scalar_zero(), &bn254::scalar_from_u64(1));
        assert_eq!(ORDER_MINUS_ONE_BYTES, *group_ops::bytes(&minus_one));

        let minus_eight = bn254::scalar_sub(&bn254::scalar_zero(), &bn254::scalar_from_u64(8));
        assert_eq!(
            x"f9ffffef93f5e1439170b97948e833285d588181b64550b829a031e1724e6430",
            *group_ops::bytes(&minus_eight),
        );
    }

    #[test]
    fun test_valid_scalar_from_bytes() {
        let eight = bn254::scalar_from_u64(8);
        let eight_from_bytes = bn254::scalar_from_bytes(group_ops::bytes(&eight));
        assert!(group_ops::equal(&eight, &eight_from_bytes));

        let zero = bn254::scalar_zero();
        let zero_from_bytes = bn254::scalar_from_bytes(group_ops::bytes(&zero));
        assert!(group_ops::equal(&zero, &zero_from_bytes));
    }

    #[test, expected_failure(abort_code = group_ops::EInvalidInput)]
    fun test_invalid_scalar_order() {
        let _ = bn254::scalar_from_bytes(&ORDER_BYTES);
    }

    #[test, expected_failure(abort_code = group_ops::EInvalidInput)]
    fun test_invalid_scalar_empty() {
        let _ = bn254::scalar_from_bytes(&vector[]);
    }

    #[test, expected_failure(abort_code = group_ops::EInvalidInput)]
    fun test_invalid_scalar_too_short() {
        let _ = bn254::scalar_from_bytes(&SHORT_SCALAR_BYTES);
    }

    #[test, expected_failure(abort_code = group_ops::EInvalidInput)]
    fun test_invalid_scalar_too_long() {
        let _ = bn254::scalar_from_bytes(&LONG_SCALAR_BYTES);
    }

    #[test, expected_failure(abort_code = group_ops::EInvalidInput)]
    fun test_invalid_scalar_div() {
        let _ = bn254::scalar_div(&bn254::scalar_zero(), &bn254::scalar_from_u64(10));
    }

    #[test, expected_failure(abort_code = group_ops::EInvalidInput)]
    fun test_invalid_scalar_inv() {
        let _ = bn254::scalar_inv(&bn254::scalar_zero());
    }

    #[test]
    fun test_g1_ops() {
        let id = bn254::g1_identity();
        let g = bn254::g1_generator();

        assert!(group_ops::equal(&id, &bn254::g1_sub(&g, &g)));
        assert!(group_ops::equal(&id, &bn254::g1_sub(&id, &id)));
        assert!(group_ops::equal(&g, &bn254::g1_add(&id, &g)));
        assert!(group_ops::equal(&g, &bn254::g1_add(&g, &id)));

        let two_g = bn254::g1_add(&g, &g);
        let four_g = bn254::g1_add(&two_g, &two_g);
        assert!(group_ops::equal(&four_g, &bn254::g1_add(&id, &four_g)));
        assert!(group_ops::equal(&four_g, &bn254::g1_mul(&bn254::scalar_from_u64(4), &g)));
        assert!(group_ops::equal(&id, &bn254::g1_mul(&bn254::scalar_from_u64(0), &g)));
        assert!(group_ops::equal(&two_g, &bn254::g1_sub(&four_g, &two_g)));
        assert!(group_ops::equal(&two_g, &bn254::g1_div(&bn254::scalar_from_u64(2), &four_g)));

        let minus_two_g = bn254::g1_neg(&two_g);
        assert!(group_ops::equal(&two_g, &bn254::g1_add(&minus_two_g, &four_g)));

        let order_minus_one = bn254::scalar_from_bytes(&ORDER_MINUS_ONE_BYTES);
        let _ = bn254::g1_mul(&order_minus_one, &g);
    }

    #[test]
    fun test_g1_to_bytes_regression() {
        assert_eq!(G1_IDENTITY_BYTES, *group_ops::bytes(&bn254::g1_identity()));
        assert_eq!(G1_GENERATOR_BYTES, *group_ops::bytes(&bn254::g1_generator()));
    }

    #[test]
    fun test_valid_g1_from_bytes() {
        let g = bn254::g1_generator();
        assert!(group_ops::equal(&g, &bn254::g1_from_bytes(group_ops::bytes(&g))));

        let id = bn254::g1_identity();
        assert!(group_ops::equal(&id, &bn254::g1_from_bytes(group_ops::bytes(&id))));
    }

    #[test, expected_failure(abort_code = group_ops::EInvalidInput)]
    fun test_invalid_g1_empty() {
        let _ = bn254::g1_from_bytes(&vector[]);
    }

    #[test, expected_failure(abort_code = group_ops::EInvalidInput)]
    fun test_invalid_g1_too_short() {
        let _ = bn254::g1_from_bytes(&SHORT_G1_BYTES);
    }

    #[test, expected_failure(abort_code = group_ops::EInvalidInput)]
    fun test_invalid_g1_too_long() {
        let _ = bn254::g1_from_bytes(&LONG_G1_BYTES);
    }

    #[test, expected_failure(abort_code = group_ops::EInvalidInput)]
    fun test_invalid_g1_div() {
        let _ = bn254::g1_div(&bn254::scalar_zero(), &bn254::g1_generator());
    }

    #[test]
    fun test_g2_ops() {
        let id = bn254::g2_identity();
        let g = bn254::g2_generator();

        assert!(group_ops::equal(&id, &bn254::g2_sub(&g, &g)));
        assert!(group_ops::equal(&id, &bn254::g2_sub(&id, &id)));
        assert!(group_ops::equal(&g, &bn254::g2_add(&id, &g)));
        assert!(group_ops::equal(&g, &bn254::g2_add(&g, &id)));

        let two_g = bn254::g2_add(&g, &g);
        let four_g = bn254::g2_add(&two_g, &two_g);
        assert!(group_ops::equal(&four_g, &bn254::g2_add(&id, &four_g)));
        assert!(group_ops::equal(&four_g, &bn254::g2_mul(&bn254::scalar_from_u64(4), &g)));
        assert!(group_ops::equal(&id, &bn254::g2_mul(&bn254::scalar_from_u64(0), &g)));
        assert!(group_ops::equal(&two_g, &bn254::g2_sub(&four_g, &two_g)));
        assert!(group_ops::equal(&two_g, &bn254::g2_div(&bn254::scalar_from_u64(2), &four_g)));

        let minus_two_g = bn254::g2_neg(&two_g);
        assert!(group_ops::equal(&two_g, &bn254::g2_add(&minus_two_g, &four_g)));

        let order_minus_one = bn254::scalar_from_bytes(&ORDER_MINUS_ONE_BYTES);
        let _ = bn254::g2_mul(&order_minus_one, &g);
    }

    #[test]
    fun test_g2_to_bytes_regression() {
        assert_eq!(G2_IDENTITY_BYTES, *group_ops::bytes(&bn254::g2_identity()));
        assert_eq!(G2_GENERATOR_BYTES, *group_ops::bytes(&bn254::g2_generator()));
    }

    #[test]
    fun test_valid_g2_from_bytes() {
        let g = bn254::g2_generator();
        assert!(group_ops::equal(&g, &bn254::g2_from_bytes(group_ops::bytes(&g))));

        let id = bn254::g2_identity();
        assert!(group_ops::equal(&id, &bn254::g2_from_bytes(group_ops::bytes(&id))));
    }

    #[test, expected_failure(abort_code = group_ops::EInvalidInput)]
    fun test_invalid_g2_empty() {
        let _ = bn254::g2_from_bytes(&vector[]);
    }

    #[test, expected_failure(abort_code = group_ops::EInvalidInput)]
    fun test_invalid_g2_too_short() {
        let _ = bn254::g2_from_bytes(&SHORT_G2_BYTES);
    }

    #[test, expected_failure(abort_code = group_ops::EInvalidInput)]
    fun test_invalid_g2_too_long() {
        let _ = bn254::g2_from_bytes(&LONG_G2_BYTES);
    }

    #[test, expected_failure(abort_code = group_ops::EInvalidInput)]
    fun test_invalid_g2_div() {
        let _ = bn254::g2_div(&bn254::scalar_zero(), &bn254::g2_generator());
    }

    #[test]
    fun test_gt_ops() {
        let id = bn254::gt_identity();
        let g = bn254::gt_generator();

        assert!(group_ops::equal(&id, &bn254::gt_sub(&g, &g)));
        assert!(group_ops::equal(&id, &bn254::gt_sub(&id, &id)));
        assert!(group_ops::equal(&g, &bn254::gt_add(&id, &g)));
        assert!(group_ops::equal(&g, &bn254::gt_add(&g, &id)));

        let two_g = bn254::gt_add(&g, &g);
        let four_g = bn254::gt_add(&two_g, &two_g);
        assert!(group_ops::equal(&four_g, &bn254::gt_add(&id, &four_g)));
        assert!(group_ops::equal(&four_g, &bn254::gt_mul(&bn254::scalar_from_u64(4), &g)));
        assert!(group_ops::equal(&id, &bn254::gt_mul(&bn254::scalar_from_u64(0), &g)));
        assert!(group_ops::equal(&two_g, &bn254::gt_sub(&four_g, &two_g)));
        assert!(group_ops::equal(&two_g, &bn254::gt_div(&bn254::scalar_from_u64(2), &four_g)));

        let minus_two_g = bn254::gt_neg(&two_g);
        assert!(group_ops::equal(&two_g, &bn254::gt_add(&minus_two_g, &four_g)));

        let order_minus_one = bn254::scalar_from_bytes(&ORDER_MINUS_ONE_BYTES);
        let _ = bn254::gt_mul(&order_minus_one, &g);
    }

    #[test]
    fun test_gt_to_bytes_regression() {
        let bytes = *group_ops::bytes(&bn254::gt_identity());
        assert_eq!(384, bytes.length());
        assert_eq!(1, bytes[0]);

        let mut i = 1;
        while (i < bytes.length()) {
            assert_eq!(0, bytes[i]);
            i = i + 1;
        };
    }

    #[test]
    fun test_valid_gt_from_bytes() {
        let id = bn254::gt_identity();
        assert!(group_ops::equal(&id, &bn254::gt_from_bytes(group_ops::bytes(&id))));

        let g = bn254::gt_generator();
        assert!(group_ops::equal(&g, &bn254::gt_from_bytes(group_ops::bytes(&g))));
    }

    #[test, expected_failure(abort_code = group_ops::EInvalidInput)]
    fun test_invalid_gt_empty() {
        let _ = bn254::gt_from_bytes(&vector[]);
    }

    #[test, expected_failure(abort_code = group_ops::EInvalidInput)]
    fun test_invalid_gt_too_short() {
        let mut bytes = *group_ops::bytes(&bn254::gt_identity());
        bytes.pop_back();
        let _ = bn254::gt_from_bytes(&bytes);
    }

    #[test, expected_failure(abort_code = group_ops::EInvalidInput)]
    fun test_invalid_gt_too_long() {
        let mut bytes = *group_ops::bytes(&bn254::gt_identity());
        bytes.push_back(0);
        let _ = bn254::gt_from_bytes(&bytes);
    }

    #[test, expected_failure(abort_code = group_ops::EInvalidInput)]
    fun test_invalid_gt_div() {
        let _ = bn254::gt_div(&bn254::scalar_zero(), &bn254::gt_generator());
    }

    #[test]
    fun test_msm_g1() {
        let g = bn254::g1_generator();
        let two_g = bn254::g1_mul(&bn254::scalar_from_u64(2), &g);
        let expected = bn254::g1_mul(&bn254::scalar_from_u64(8), &g);
        let result = bn254::g1_multi_scalar_multiplication(
            &vector[bn254::scalar_from_u64(2), bn254::scalar_from_u64(3)],
            &vector[g, two_g],
        );
        assert!(group_ops::equal(&result, &expected));
    }

    #[test]
    fun test_msm_g1_edge_cases() {
        let zero = bn254::scalar_zero();
        let one = bn254::scalar_one();
        let g = bn254::g1_generator();
        let id = bn254::g1_identity();
        let g_r = bn254::g1_mul(&bn254::scalar_from_u64(12345), &g);

        assert!(group_ops::equal(&bn254::g1_multi_scalar_multiplication(&vector[zero], &vector[g]), &id));
        assert!(group_ops::equal(&bn254::g1_multi_scalar_multiplication(&vector[one], &vector[g]), &g));
        assert!(group_ops::equal(&bn254::g1_multi_scalar_multiplication(&vector[one, one], &vector[g, id]), &g));
        assert!(group_ops::equal(&bn254::g1_multi_scalar_multiplication(&vector[zero, one], &vector[g, id]), &id));
        assert!(group_ops::equal(&bn254::g1_multi_scalar_multiplication(&vector[one, one], &vector[g_r, id]), &g_r));
    }

    #[test, expected_failure(abort_code = group_ops::EInvalidInput)]
    fun test_empty_g1_msm() {
        let scalars: vector<group_ops::Element<bn254::Scalar>> = vector[];
        let elements: vector<group_ops::Element<bn254::G1>> = vector[];
        let _ = bn254::g1_multi_scalar_multiplication(&scalars, &elements);
    }

    #[test, expected_failure(abort_code = group_ops::EInvalidInput)]
    fun test_diff_length_g1_msm() {
        let _ = bn254::g1_multi_scalar_multiplication(
            &vector[bn254::scalar_zero(), bn254::scalar_one()],
            &vector[bn254::g1_generator()],
        );
    }

    #[test, expected_failure(abort_code = group_ops::EInputTooLong)]
    fun test_msm_g1_too_long() {
        let mut i = 0;
        let mut scalars: vector<group_ops::Element<bn254::Scalar>> = vector[];
        let mut elements: vector<group_ops::Element<bn254::G1>> = vector[];
        while (i < 33) {
            scalars.push_back(bn254::scalar_from_u64(i + 1));
            elements.push_back(bn254::g1_generator());
            i = i + 1;
        };
        let _ = bn254::g1_multi_scalar_multiplication(&scalars, &elements);
    }

    #[test]
    fun test_msm_g2() {
        let g = bn254::g2_generator();
        let two_g = bn254::g2_mul(&bn254::scalar_from_u64(2), &g);
        let expected = bn254::g2_mul(&bn254::scalar_from_u64(8), &g);
        let result = bn254::g2_multi_scalar_multiplication(
            &vector[bn254::scalar_from_u64(2), bn254::scalar_from_u64(3)],
            &vector[g, two_g],
        );
        assert!(group_ops::equal(&result, &expected));
    }

    #[test]
    fun test_msm_g2_edge_cases() {
        let zero = bn254::scalar_zero();
        let one = bn254::scalar_one();
        let g = bn254::g2_generator();
        let id = bn254::g2_identity();
        let g_r = bn254::g2_mul(&bn254::scalar_from_u64(12345), &g);

        assert!(group_ops::equal(&bn254::g2_multi_scalar_multiplication(&vector[zero], &vector[g]), &id));
        assert!(group_ops::equal(&bn254::g2_multi_scalar_multiplication(&vector[one], &vector[g]), &g));
        assert!(group_ops::equal(&bn254::g2_multi_scalar_multiplication(&vector[one, one], &vector[g, id]), &g));
        assert!(group_ops::equal(&bn254::g2_multi_scalar_multiplication(&vector[zero, one], &vector[g, id]), &id));
        assert!(group_ops::equal(&bn254::g2_multi_scalar_multiplication(&vector[one, one], &vector[g_r, id]), &g_r));
    }

    #[test, expected_failure(abort_code = group_ops::EInvalidInput)]
    fun test_empty_g2_msm() {
        let scalars: vector<group_ops::Element<bn254::Scalar>> = vector[];
        let elements: vector<group_ops::Element<bn254::G2>> = vector[];
        let _ = bn254::g2_multi_scalar_multiplication(&scalars, &elements);
    }

    #[test, expected_failure(abort_code = group_ops::EInvalidInput)]
    fun test_diff_length_g2_msm() {
        let _ = bn254::g2_multi_scalar_multiplication(
            &vector[bn254::scalar_zero(), bn254::scalar_one()],
            &vector[bn254::g2_generator()],
        );
    }

    #[test, expected_failure(abort_code = group_ops::EInputTooLong)]
    fun test_msm_g2_too_long() {
        let mut i = 0;
        let mut scalars: vector<group_ops::Element<bn254::Scalar>> = vector[];
        let mut elements: vector<group_ops::Element<bn254::G2>> = vector[];
        while (i < 33) {
            scalars.push_back(bn254::scalar_from_u64(i + 1));
            elements.push_back(bn254::g2_generator());
            i = i + 1;
        };
        let _ = bn254::g2_multi_scalar_multiplication(&scalars, &elements);
    }

    #[test]
    fun test_pairing() {
        let g1 = bn254::g1_generator();
        let g2 = bn254::g2_generator();
        let gt = bn254::gt_generator();
        assert_eq!(bn254::pairing(&g1, &g2), gt);

        let g1_3 = bn254::g1_mul(&bn254::scalar_from_u64(3), &g1);
        let g2_5 = bn254::g2_mul(&bn254::scalar_from_u64(5), &g2);
        let gt_15 = bn254::gt_mul(&bn254::scalar_from_u64(15), &gt);
        assert_eq!(bn254::pairing(&g1_3, &g2_5), gt_15);
        assert_eq!(bn254::pairing(&bn254::g1_identity(), &bn254::g2_identity()), bn254::gt_identity());
        assert_eq!(bn254::pairing(&bn254::g1_generator(), &bn254::g2_identity()), bn254::gt_identity());
        assert_eq!(bn254::pairing(&bn254::g1_identity(), &bn254::g2_generator()), bn254::gt_identity());
    }

    #[test]
    fun test_bn254_utils_scalar_bytes() {
        assert_eq!(x"0000000000000000000000000000000000000000000000000000000000000000", bn254_utils::scalar_zero_bytes());
        assert_eq!(x"0100000000000000000000000000000000000000000000000000000000000000", bn254_utils::scalar_one_bytes());
    }

    #[test]
    fun test_bn254_utils_fr_roundtrip() {
        let scalar = bn254_utils::fr_from_u128(18446744073709551615u128);
        assert!(group_ops::equal(&scalar, &bn254::scalar_from_u64(18446744073709551615u64)));

        let bytes = bn254_utils::serialize_fr(&scalar);
        let deserialized = option::destroy_some(bn254_utils::deserialize_fr(&bytes));
        assert!(group_ops::equal(&scalar, &deserialized));
    }

    #[test]
    fun test_bn254_utils_rejects_invalid_fr() {
        assert!(option::is_none(&bn254_utils::deserialize_fr(&ORDER_BYTES)));
        assert!(option::is_none(&bn254_utils::deserialize_fr(&SHORT_SCALAR_BYTES)));
    }

    #[test]
    fun test_bn254_utils_from_u512_le() {
        let a = vector[
            37u8, 210, 18, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let result = bn254_utils::fr_from_u512_le(&a, &a);
        assert_eq!(
            x"7041af4f6757e4eeb972641893ed9c8c7293d18118f87392c803b0ede9d38606",
            bn254_utils::serialize_fr(&result),
        );
    }

    #[test]
    fun test_bn254_utils_pow_root_and_delta() {
        let three = bn254::scalar_from_u64(3);
        assert!(group_ops::equal(&bn254_utils::pow_u32(&three, 0), &bn254::scalar_one()));
        assert!(group_ops::equal(&bn254_utils::pow_u32(&three, 5), &bn254::scalar_from_u64(243)));

        let root = bn254_utils::root_of_unity(28);
        assert_eq!(x"9c7cc360d91e4fd3c82993d36dcf1532741fd33da95e8698b7186d16f5b9dd03", bn254_utils::serialize_fr(&root));

        let delta = bn254_utils::delta_of_fr();
        assert_eq!(x"a2e933e5bb560e87253f965e8e895f5b716ec8d4aa26ec64caf0c6226e6b2209", bn254_utils::serialize_fr(&delta));
    }

    #[test]
    fun test_bn254_utils_g1_g2_roundtrip_and_uncompressed() {
        let g1 = bn254::g1_generator();
        let g1_bytes = bn254_utils::serialize_g1(&g1);
        let g1_roundtrip = option::destroy_some(bn254_utils::deserialize_g1(&g1_bytes));
        assert!(group_ops::equal(&g1, &g1_roundtrip));
        assert_eq!(64, bn254_utils::serialize_g1_uncompressed(&g1).length());

        let g2 = bn254::g2_generator();
        let g2_bytes = bn254_utils::serialize_g2(&g2);
        let g2_roundtrip = option::destroy_some(bn254_utils::deserialize_g2(&g2_bytes));
        assert!(group_ops::equal(&g2, &g2_roundtrip));
    }

    #[test]
    fun test_bn254_serialize_zero_and_one() {
        assert_eq!(x"0000000000000000000000000000000000000000000000000000000000000000", bn254_serialize::zero());
        assert_eq!(x"0100000000000000000000000000000000000000000000000000000000000000", bn254_serialize::one());
    }

    #[test]
    fun test_bn254_serialize_u128_values() {
        assert_eq!(bn254_serialize::zero(), bn254_serialize::u128_to_bn254_le_bytes(0));
        assert_eq!(bn254_serialize::one(), bn254_serialize::u128_to_bn254_le_bytes(1));
        assert_eq!(
            x"efbeadde00000000000000000000000000000000000000000000000000000000",
            bn254_serialize::u128_to_bn254_le_bytes(0xDEADBEEFu128),
        );

        let max = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFu128;
        assert_eq!(
            x"ffffffffffffffffffffffffffffffff00000000000000000000000000000000",
            bn254_serialize::u128_to_bn254_le_bytes(max),
        );
    }

    #[test]
    fun test_bn254_serialize_u256_reduction() {
        let modulus: u256 = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
        assert_eq!(bn254_serialize::zero(), bn254_serialize::u256_to_bn254_le_bytes(modulus));
        assert_eq!(bn254_serialize::one(), bn254_serialize::u256_to_bn254_le_bytes(modulus + 1));
    }

    #[test]
    fun test_bn254_serialize_outputs_are_deserializable() {
        assert!(option::is_some(&bn254_utils::deserialize_fr(&bn254_serialize::u128_to_bn254_le_bytes(0xDEADBEEFCAFEBABEu128))));
        assert!(option::is_some(&bn254_utils::deserialize_fr(&bn254_serialize::u256_to_bn254_le_bytes(0xABCDEF1234567890u256))));
    }
}

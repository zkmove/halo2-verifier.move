// Copyright (c) zkMove Authors

#[test_only]
module halo2_common::params_msm_test {
    use sui::bn254;
    use sui::group_ops;
    use halo2_common::msm;
    use halo2_common::params;

    const LONG_MSM_INPUT_SIZE: u64 = 128;

    #[test]
    fun test_params_getters() {
        let g1 = bn254::g1_generator();
        let g2 = bn254::g2_generator();
        let s_g2 = bn254::g2_mul(&bn254::scalar_from_u64(7), &g2);
        let params = params::new(g1, g2, s_g2);

        assert!(group_ops::equal(params::g(&params), &g1));
        assert!(group_ops::equal(params::g2(&params), &g2));
        assert!(group_ops::equal(params::s_g2(&params), &s_g2));
    }

    #[test]
    fun test_empty_msm_eq_and_scale_noop() {
        let mut a = msm::empty_msm();
        let b = msm::empty_msm();
        msm::scale(&mut a, &bn254::scalar_from_u64(9));
        assert!(msm::eq(&a, &b));
    }

    #[test]
    fun test_eval_empty_msm_returns_identity() {
        let empty = msm::empty_msm();
        assert!(group_ops::equal(&msm::eval(&empty), &bn254::g1_identity()));
    }

    #[test]
    fun test_eval_msm_with_32_terms() {
        let value = repeated_generator_msm(32);
        assert!(group_ops::equal(&msm::eval(&value), &expected_generator_multiple(32)));
    }

    #[test]
    fun test_eval_msm_repeated_bases_long_input() {
        let value = repeated_generator_msm(LONG_MSM_INPUT_SIZE);
        assert!(group_ops::equal(&msm::eval(&value), &expected_generator_multiple(LONG_MSM_INPUT_SIZE)));
    }

    #[test]
    fun test_eval_msm_distinct_bases_long_input() {
        let value = distinct_generator_msm(LONG_MSM_INPUT_SIZE);
        assert!(group_ops::equal(&msm::eval(&value), &expected_generator_multiple(LONG_MSM_INPUT_SIZE)));
    }

    #[test]
    fun test_msm_append_and_eval() {
        let g = bn254::g1_generator();
        let two_g = bn254::g1_mul(&bn254::scalar_from_u64(2), &g);
        let expected = bn254::g1_mul(&bn254::scalar_from_u64(8), &g);

        let mut value = msm::empty_msm();
        msm::append_term(&mut value, bn254::scalar_from_u64(2), g);
        msm::append_term(&mut value, bn254::scalar_from_u64(3), two_g);

        assert!(group_ops::equal(&msm::eval(&value), &expected));
    }

    #[test]
    fun test_msm_scale() {
        let g = bn254::g1_generator();
        let expected = bn254::g1_mul(&bn254::scalar_from_u64(8), &g);

        let mut value = msm::empty_msm();
        msm::append_term(&mut value, bn254::scalar_from_u64(2), g);
        msm::scale(&mut value, &bn254::scalar_from_u64(4));

        assert!(group_ops::equal(&msm::eval(&value), &expected));
    }

    #[test]
    fun test_msm_add_msm() {
        let g = bn254::g1_generator();
        let two_g = bn254::g1_mul(&bn254::scalar_from_u64(2), &g);
        let expected = bn254::g1_mul(&bn254::scalar_from_u64(8), &g);

        let mut left = msm::empty_msm();
        msm::append_term(&mut left, bn254::scalar_from_u64(2), g);

        let mut right = msm::empty_msm();
        msm::append_term(&mut right, bn254::scalar_from_u64(3), two_g);

        msm::add_msm(&mut left, &right);
        assert!(group_ops::equal(&msm::eval(&left), &expected));
    }

    #[test]
    fun test_msm_eq() {
        let g = bn254::g1_generator();
        let two_g = bn254::g1_mul(&bn254::scalar_from_u64(2), &g);

        let mut a = msm::empty_msm();
        msm::append_term(&mut a, bn254::scalar_from_u64(2), g);

        let mut b = msm::empty_msm();
        msm::append_term(&mut b, bn254::scalar_from_u64(2), g);

        let mut c = msm::empty_msm();
        msm::append_term(&mut c, bn254::scalar_from_u64(2), two_g);

        assert!(msm::eq(&a, &b));
        assert!(!msm::eq(&a, &c));
    }

    fun repeated_generator_msm(count: u64): msm::MSM {
        let g = bn254::g1_generator();
        let mut value = msm::empty_msm();
        let mut i = 0;
        while (i < count) {
            msm::append_term(&mut value, bn254::scalar_from_u64(i + 1), g);
            i = i + 1;
        };
        value
    }

    fun distinct_generator_msm(count: u64): msm::MSM {
        let g = bn254::g1_generator();
        let one = bn254::scalar_one();
        let mut value = msm::empty_msm();
        let mut i = 0;
        while (i < count) {
            msm::append_term(&mut value, one, bn254::g1_mul(&bn254::scalar_from_u64(i + 1), &g));
            i = i + 1;
        };
        value
    }

    fun expected_generator_multiple(count: u64): group_ops::Element<bn254::G1> {
        bn254::g1_mul(&bn254::scalar_from_u64(arithmetic_sum(count)), &bn254::g1_generator())
    }

    fun arithmetic_sum(count: u64): u64 {
        count * (count + 1) / 2
    }
}

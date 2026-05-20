// Copyright (c) zkMove Authors

#[test_only]
module halo2_common::domain_test {
    use std::unit_test::assert_eq;
    use sui::bn254;
    use sui::group_ops;
    use halo2_common::bn254_utils::{pow_u32, root_of_unity};
    use halo2_common::domain;
    use halo2_common::i32;

    #[test]
    fun test_domain_getters_and_quotient_degree() {
        let d = domain::new(4, 3);
        assert_eq!(3, domain::k(&d));
        assert_eq!(8, domain::n(&d));
        assert_eq!(3, domain::quotient_poly_degree(&d));
    }

    #[test]
    fun test_rotate_omega_zero_positive_and_negative() {
        let d = domain::new(3, 3);
        let x = bn254::scalar_from_u64(7);
        let one = bn254::scalar_one();
        let omega = root_of_unity(3);

        assert!(group_ops::equal(&domain::rotate_omega(&d, &x, &i32::from(0)), &x));

        let rotated = domain::rotate_omega(&d, &x, &i32::from(2));
        let expected = bn254::scalar_mul(&x, &pow_u32(&omega, 2));
        assert!(group_ops::equal(&rotated, &expected));

        let omega_squared = domain::rotate_omega(&d, &one, &i32::from(2));
        let omega_inv_squared = domain::rotate_omega(&d, &one, &i32::neg_from(2));
        assert!(group_ops::equal(&bn254::scalar_mul(&omega_squared, &omega_inv_squared), &one));
    }

    #[test]
    fun test_l_i_range_full_domain_sums_to_one() {
        let d = domain::new(3, 3);
        let x = bn254::scalar_from_u64(3);
        let xn = pow_u32(&x, domain::n(&d));
        let values = domain::l_i_range(&d, &x, &xn, i32::from(0), i32::from(domain::n(&d)));

        assert_eq!(8, values.length());

        let mut sum = bn254::scalar_zero();
        let mut i = 0;
        while (i < values.length()) {
            sum = bn254::scalar_add(&sum, &values[i]);
            i = i + 1;
        };
        assert!(group_ops::equal(&sum, &bn254::scalar_one()));
    }

    #[test]
    fun test_l_i_range_subrange_length() {
        let d = domain::new(5, 3);
        let x = bn254::scalar_from_u64(5);
        let xn = pow_u32(&x, domain::n(&d));
        let values = domain::l_i_range(&d, &x, &xn, i32::from(2), i32::from(5));
        assert_eq!(3, values.length());
    }
}

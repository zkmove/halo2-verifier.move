// Copyright (c) zkMove Authors

#[test_only]
module halo2_common::pure_common_test {
    use std::unit_test::assert_eq;
    use halo2_common::column;
    use halo2_common::column_query;
    use halo2_common::i32;
    use halo2_common::vec_utils;

    #[test]
    fun test_i32_constructors_and_sign() {
        let zero = i32::zero();
        assert!(i32::is_zero(&zero));
        assert!(!i32::is_neg(&zero));
        assert_eq!(0, i32::as_u32(&zero));

        let positive = i32::from(42);
        assert!(!i32::is_zero(&positive));
        assert!(!i32::is_neg(&positive));
        assert_eq!(42, i32::as_u32(&positive));
        assert_eq!(42, i32::abs(&positive));

        let negative = i32::neg_from(42);
        assert!(i32::is_neg(&negative));
        assert_eq!(42, i32::abs(&negative));
        assert_eq!(42, i32::as_u32(&i32::neg(&negative)));

        let positive_from_new = i32::new(true, 7);
        let negative_from_new = i32::new(false, 7);
        assert_eq!(7, i32::as_u32(&positive_from_new));
        assert!(i32::is_neg(&negative_from_new));
        assert_eq!(7, i32::abs(&negative_from_new));
    }

    #[test]
    fun test_i32_compare() {
        let neg_three = i32::neg_from(3);
        let two = i32::from(2);
        let five = i32::from(5);

        assert_eq!(0, i32::compare(&two, &two));
        assert_eq!(1, i32::compare(&neg_three, &two));
        assert_eq!(2, i32::compare(&five, &two));
        assert_eq!(2, i32::compare(&two, &neg_three));
    }

    #[test]
    fun test_i32_arithmetic() {
        let seven = i32::from(7);
        let three = i32::from(3);
        let neg_three = i32::neg_from(3);
        let neg_seven = i32::neg_from(7);

        assert_eq!(10, i32::as_u32(&i32::add(&seven, &three)));
        assert_eq!(4, i32::as_u32(&i32::add(&seven, &neg_three)));

        let neg_four = i32::add(&neg_seven, &three);
        assert!(i32::is_neg(&neg_four));
        assert_eq!(4, i32::abs(&neg_four));

        assert_eq!(4, i32::as_u32(&i32::sub(&seven, &three)));
        assert_eq!(10, i32::as_u32(&i32::sub(&seven, &neg_three)));

        let neg_ten = i32::sub(&neg_seven, &three);
        assert!(i32::is_neg(&neg_ten));
        assert_eq!(10, i32::abs(&neg_ten));

        assert_eq!(21, i32::as_u32(&i32::mul(&seven, &three)));
        let neg_twenty_one = i32::mul(&seven, &neg_three);
        assert!(i32::is_neg(&neg_twenty_one));
        assert_eq!(21, i32::abs(&neg_twenty_one));

        assert_eq!(2, i32::as_u32(&i32::div(&seven, &three)));
        let neg_two = i32::div(&neg_seven, &three);
        assert!(i32::is_neg(&neg_two));
        assert_eq!(2, i32::abs(&neg_two));
    }

    #[test, expected_failure]
    fun test_i32_from_overflow_aborts() {
        let _ = i32::from(2147483648u32);
    }

    #[test, expected_failure]
    fun test_i32_as_u32_negative_aborts() {
        let _ = i32::as_u32(&i32::neg_from(1));
    }

    #[test]
    fun test_vec_utils_repeat() {
        let values = vec_utils::repeat(9u8, 4);
        assert_eq!(4, values.length());
        assert_eq!(9, values[0]);
        assert_eq!(9, values[3]);

        let one = vec_utils::repeat(123u64, 1);
        assert_eq!(1, one.length());
        assert_eq!(123, one[0]);
    }

    #[test, expected_failure]
    fun test_vec_utils_repeat_zero_aborts() {
        let _ = vec_utils::repeat(0u8, 0);
    }

    #[test]
    fun test_column_helpers() {
        let advice = column::new(0, 1);
        let fixed = column::new(3, 2);
        let instance = column::new(5, 3);

        assert!(column::is_advice(&advice));
        assert!(!column::is_fixed(&advice));
        assert!(column::is_fixed(&fixed));
        assert!(column::is_instance(&instance));
        assert_eq!(3, column::column_index(&fixed));
        assert_eq!(2, column::column_type(&fixed));
    }

    #[test]
    fun test_column_query_helpers() {
        let col = column::new(11, 3);
        let rotation = i32::neg_from(2);
        let query = column_query::new(col, rotation);

        let query_col = column_query::column(&query);
        let query_rotation = column_query::rotation(&query);

        assert_eq!(11, column::column_index(query_col));
        assert_eq!(3, column::column_type(query_col));
        assert!(i32::is_neg(query_rotation));
        assert_eq!(2, i32::abs(query_rotation));
    }
}

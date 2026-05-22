// Copyright (c) zkMove Authors

#[test_only]
module halo2_common::public_inputs_test {
    use std::unit_test::assert_eq;
    use halo2_common::bn254_utils::{fr_from_u128, serialize_fr};
    use halo2_common::public_inputs;

    fun expected_fr_bytes_from_u64(value: u64): vector<u8> {
        serialize_fr(&fr_from_u128((value as u128)))
    }

    fun expected_fr_bytes_from_bool(value: bool): vector<u8> {
        expected_fr_bytes_from_u64(if (value) { 1 } else { 0 })
    }

    fun u256_to_lo_hi(value: u256): (u128, u128) {
        let lo_mask = (1u256 << 128) - 1;
        (((value & lo_mask) as u128), ((value >> 128) as u128))
    }

    fun slice_vector(src: &vector<u8>, start: u64, end: u64): vector<u8> {
        let mut result = vector[];
        let mut i = start;
        while (i < end) {
            vector::push_back(&mut result, src[i]);
            i = i + 1;
        };
        result
    }

    #[test]
    fun test_default_and_empty_row_count() {
        let default_pi = public_inputs::default(public_inputs::get_vm_public_inputs_column_count());
        assert_eq!(1, public_inputs::row_count(&default_pi));

        let empty_pi = public_inputs::empty(public_inputs::get_vm_public_inputs_column_count());
        assert_eq!(0, public_inputs::row_count(&empty_pi));

        let no_columns = public_inputs::empty(0);
        assert_eq!(0, public_inputs::row_count(&no_columns));
    }

    #[test]
    fun test_specific_values_are_column_major_encoded() {
        let mut pi = public_inputs::empty(public_inputs::get_vm_public_inputs_column_count());

        public_inputs::push_bool(&mut pi, true);
        public_inputs::push_u8(&mut pi, 255);
        public_inputs::push_u64(&mut pi, 123456789);
        public_inputs::push_u128(&mut pi, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFu128);
        public_inputs::push_u256(&mut pi, 0x1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEFu256);
        public_inputs::push_u256(&mut pi, 1u256 << 255);
        public_inputs::push_bool(&mut pi, false);

        let bytes = public_inputs::to_bytes_flat(&pi);
        let num_rows = 7;
        assert_eq!(num_rows * 4 * 32, bytes.length());

        let col_lo = 2;
        let col_hi = 3;
        let col_lo_base = col_lo * (num_rows * 32);
        let col_hi_base = col_hi * (num_rows * 32);

        let offset = col_lo_base;
        assert!(slice_vector(&bytes, offset, offset + 32) == expected_fr_bytes_from_bool(true), 1001);

        let offset = col_lo_base + 1 * 32;
        assert!(slice_vector(&bytes, offset, offset + 32) == expected_fr_bytes_from_u64(255), 1002);

        let offset = col_lo_base + 2 * 32;
        assert!(slice_vector(&bytes, offset, offset + 32) == expected_fr_bytes_from_u64(123456789), 1003);

        let offset_lo = col_lo_base + 3 * 32;
        assert!(slice_vector(&bytes, offset_lo, offset_lo + 32) == serialize_fr(&fr_from_u128(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFu128)), 1004);

        let offset_hi = col_hi_base + 3 * 32;
        assert!(slice_vector(&bytes, offset_hi, offset_hi + 32) == expected_fr_bytes_from_u64(0), 1005);

        let large_u256 = 0x1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEFu256;
        let (lo, hi) = u256_to_lo_hi(large_u256);
        let offset_lo = col_lo_base + 4 * 32;
        assert!(slice_vector(&bytes, offset_lo, offset_lo + 32) == serialize_fr(&fr_from_u128(lo)), 1006);

        let offset_hi = col_hi_base + 4 * 32;
        assert!(slice_vector(&bytes, offset_hi, offset_hi + 32) == serialize_fr(&fr_from_u128(hi)), 1007);

        let offset_lo = col_lo_base + 5 * 32;
        assert!(slice_vector(&bytes, offset_lo, offset_lo + 32) == expected_fr_bytes_from_u64(0), 1008);

        let offset_hi = col_hi_base + 5 * 32;
        assert!(slice_vector(&bytes, offset_hi, offset_hi + 32) == serialize_fr(&fr_from_u128(1u128 << 127)), 1009);

        let offset = col_lo_base + 6 * 32;
        assert!(slice_vector(&bytes, offset, offset + 32) == expected_fr_bytes_from_bool(false), 1010);

        let mut row = 0;
        while (row < num_rows) {
            let offset = row * 32;
            assert!(slice_vector(&bytes, offset, offset + 32) == expected_fr_bytes_from_u64(0), 1011 + row);
            row = row + 1;
        };

        let col_header_base = num_rows * 32;
        let mut row = 0;
        while (row < num_rows) {
            let offset = col_header_base + row * 32;
            assert!(slice_vector(&bytes, offset, offset + 32) == expected_fr_bytes_from_u64(0), 1020 + row);
            row = row + 1;
        };
    }

    #[test]
    fun test_from_bytes_roundtrip_and_bcs() {
        let mut pi = public_inputs::empty(public_inputs::get_vm_public_inputs_column_count());
        public_inputs::push_bool(&mut pi, true);
        public_inputs::push_u16(&mut pi, 65535);
        public_inputs::push_u32(&mut pi, 123456789);
        public_inputs::push_u256(&mut pi, 1u256 << 255);

        let bytes = public_inputs::to_bytes(&pi);
        let reconstructed = public_inputs::from_bytes(&bytes);
        assert_eq!(public_inputs::row_count(&pi), public_inputs::row_count(&reconstructed));
        assert!(bytes == public_inputs::to_bytes(&reconstructed), 2001);

        let bcs_bytes = public_inputs::to_bcs_bytes(&pi);
        assert!(bcs_bytes.length() > 0, 2002);
    }

    #[test]
    fun test_columns_returns_column_major_data() {
        let mut pi = public_inputs::empty(public_inputs::get_vm_public_inputs_column_count());
        public_inputs::push_u8(&mut pi, 9);
        public_inputs::push_u8(&mut pi, 10);

        let columns = public_inputs::columns(&pi);
        assert_eq!(4, columns.length());
        assert_eq!(2, columns[0].length());
        assert_eq!(2, columns[2].length());
    }

    #[test, expected_failure]
    fun test_push_with_invalid_column_count_aborts() {
        let mut pi = public_inputs::empty(3);
        public_inputs::push_u8(&mut pi, 1);
    }

    #[test, expected_failure]
    fun test_push_vector_aborts() {
        let mut pi = public_inputs::empty(public_inputs::get_vm_public_inputs_column_count());
        public_inputs::push_vector(&mut pi, vector[1u8, 2, 3]);
    }
}

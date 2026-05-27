#[test_only]
module verifier_api::serialized_public_inputs_tests;

use verifier_api::serialized_public_inputs;

fun slice_vector(src: &vector<u8>, start: u64, end: u64): vector<u8> {
    let mut result = vector[];
    let mut i = start;
    while (i < end) {
        result.push_back(src[i]);
        i = i + 1;
    };
    result
}

fun u256_to_lo_hi(value: u256): (u128, u128) {
    let lo_mask: u256 = (1u256 << 128) - 1;
    let lo = ((value & lo_mask) as u128);
    let hi = ((value >> 128) as u128);
    (lo, hi)
}

#[test]
fun test_specific_values_are_column_major_encoded() {
    let mut pi = serialized_public_inputs::empty(
        serialized_public_inputs::get_vm_public_inputs_column_count(),
    );

    serialized_public_inputs::push_bool(&mut pi, true);
    serialized_public_inputs::push_u8(&mut pi, 255u8);
    serialized_public_inputs::push_u64(&mut pi, 123456789u64);
    serialized_public_inputs::push_u128(&mut pi, 0xffffffffffffffffffffffffffffffffu128);
    serialized_public_inputs::push_u256(
        &mut pi,
        0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdefu256,
    );
    serialized_public_inputs::push_u256(&mut pi, 1u256 << 255);
    serialized_public_inputs::push_bool(&mut pi, false);

    let bytes = serialized_public_inputs::to_bytes_flat(&pi);
    let num_rows = 7;
    assert!(bytes.length() == num_rows * 4 * 32, 1000);

    let col_lo_base = 2 * (num_rows * 32);
    let col_hi_base = 3 * (num_rows * 32);

    let actual = slice_vector(&bytes, col_lo_base, col_lo_base + 32);
    assert!(actual == serialized_public_inputs::u128_to_bn254_le_bytes(1), 1001);

    let actual = slice_vector(&bytes, col_lo_base + 32, col_lo_base + 64);
    assert!(actual == serialized_public_inputs::u128_to_bn254_le_bytes(255), 1002);

    let actual = slice_vector(&bytes, col_lo_base + 2 * 32, col_lo_base + 3 * 32);
    assert!(actual == serialized_public_inputs::u128_to_bn254_le_bytes(123456789), 1003);

    let actual_lo = slice_vector(&bytes, col_lo_base + 3 * 32, col_lo_base + 4 * 32);
    assert!(
        actual_lo == serialized_public_inputs::u128_to_bn254_le_bytes(0xffffffffffffffffffffffffffffffffu128),
        1004,
    );
    let actual_hi = slice_vector(&bytes, col_hi_base + 3 * 32, col_hi_base + 4 * 32);
    assert!(actual_hi == serialized_public_inputs::zero_scalar_bytes(), 1005);

    let large = 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdefu256;
    let (lo, hi) = u256_to_lo_hi(large);
    let actual_lo = slice_vector(&bytes, col_lo_base + 4 * 32, col_lo_base + 5 * 32);
    let actual_hi = slice_vector(&bytes, col_hi_base + 4 * 32, col_hi_base + 5 * 32);
    assert!(actual_lo == serialized_public_inputs::u128_to_bn254_le_bytes(lo), 1006);
    assert!(actual_hi == serialized_public_inputs::u128_to_bn254_le_bytes(hi), 1007);

    let actual_lo = slice_vector(&bytes, col_lo_base + 5 * 32, col_lo_base + 6 * 32);
    let actual_hi = slice_vector(&bytes, col_hi_base + 5 * 32, col_hi_base + 6 * 32);
    assert!(actual_lo == serialized_public_inputs::zero_scalar_bytes(), 1008);
    assert!(actual_hi == serialized_public_inputs::u128_to_bn254_le_bytes(1u128 << 127), 1009);

    let actual = slice_vector(&bytes, col_lo_base + 6 * 32, col_lo_base + 7 * 32);
    assert!(actual == serialized_public_inputs::zero_scalar_bytes(), 1010);

    let mut row = 0;
    while (row < num_rows) {
        let offset = row * 32;
        let actual = slice_vector(&bytes, offset, offset + 32);
        assert!(actual == serialized_public_inputs::zero_scalar_bytes(), 1011 + row);
        row = row + 1;
    };

    let col1_base = num_rows * 32;
    let mut row = 0;
    while (row < num_rows) {
        let offset = col1_base + row * 32;
        let actual = slice_vector(&bytes, offset, offset + 32);
        assert!(actual == serialized_public_inputs::zero_scalar_bytes(), 1020 + row);
        row = row + 1;
    };
}

#[test]
fun test_roundtrip_from_bytes_and_bcs() {
    let mut pi = serialized_public_inputs::empty(
        serialized_public_inputs::get_vm_public_inputs_column_count(),
    );

    serialized_public_inputs::push_bool(&mut pi, true);
    serialized_public_inputs::push_u8(&mut pi, 255u8);
    serialized_public_inputs::push_u64(&mut pi, 123456789u64);
    serialized_public_inputs::push_u128(&mut pi, 0xffffffffffffffffffffffffffffffffu128);

    let original_bytes = serialized_public_inputs::to_bytes(&pi);
    let pi2 = serialized_public_inputs::from_bytes(copy original_bytes);
    let pi3 = serialized_public_inputs::from_bytes_ref(&original_bytes);

    assert!(serialized_public_inputs::row_count(&pi) == serialized_public_inputs::row_count(&pi2), 2000);
    assert!(serialized_public_inputs::to_bytes(&pi) == serialized_public_inputs::to_bytes(&pi2), 2001);
    assert!(serialized_public_inputs::to_bytes(&pi2) == serialized_public_inputs::to_bytes(&pi3), 2002);
    assert!(serialized_public_inputs::to_bcs_bytes(&pi) == std::bcs::to_bytes(&original_bytes), 2003);
}

#[test]
fun test_default_empty_and_validate() {
    let pi = serialized_public_inputs::default(
        serialized_public_inputs::get_vm_public_inputs_column_count(),
    );
    assert!(serialized_public_inputs::num_columns(&pi) == 4, 3000);
    assert!(serialized_public_inputs::row_count(&pi) == 1, 3001);
    assert!(serialized_public_inputs::validate(&pi), 3002);

    let cols = serialized_public_inputs::columns(&pi);
    let mut col = 0;
    while (col < cols.length()) {
        assert!(cols[col][0] == serialized_public_inputs::zero_scalar_bytes(), 3003 + col);
        col = col + 1;
    };

    let empty = serialized_public_inputs::empty(
        serialized_public_inputs::get_vm_public_inputs_column_count(),
    );
    assert!(serialized_public_inputs::row_count(&empty) == 0, 3010);
    assert!(serialized_public_inputs::validate(&empty), 3011);

    let malformed = serialized_public_inputs::from_bytes(vector[vector[vector[1, 2, 3]]]);
    assert!(!serialized_public_inputs::validate(&malformed), 3012);
}

#[test]
fun test_pack_sub_index() {
    let packed = serialized_public_inputs::pack_sub_index(&vector[1, 2, 3]);
    assert!(packed.length() == 32, 4000);
    assert!(packed[0] == 1, 4001);
    assert!(packed[1] == 0, 4002);
    assert!(packed[2] == 2, 4003);
    assert!(packed[3] == 0, 4004);
    assert!(packed[4] == 3, 4005);
    assert!(packed[5] == 0, 4006);
}

#[test]
#[expected_failure(abort_code = 1000)]
fun test_push_with_invalid_column_count_aborts() {
    let mut pi = serialized_public_inputs::empty(1);
    serialized_public_inputs::push_u64(&mut pi, 42)
}

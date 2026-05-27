/// Module for managing public inputs
module halo2_common::serialized_public_inputs {
    use std::bcs;
    use std::vector;
    use halo2_common::bn254_serialize;

    const E_INVALID_COLUMN_COUNT: u64 = 1000;

    /// Constants for zkmove internal value representation
    const VM_PUBLIC_INPUTS_COLUMN_COUNT: u64 = 4;
    const LIMB_BITS: u8 = 16;

    /// Struct representing public inputs in bytes
    struct PublicInputs has drop {
        columns: vector<vector<vector<u8>>>,
        num_columns: u64,
    }

    /// Create a default PublicInputs with one dummy row of zeros
    public fun default(num_columns: u64): PublicInputs {
        let zero_bytes = bn254_serialize::zero();
        let columns = vector::empty<vector<vector<u8>>>();
        let i = 0;
        while (i < num_columns) {
            let col = vector::empty<vector<u8>>();
            vector::push_back(&mut col, zero_bytes);
            vector::push_back(&mut columns, col);
            i = i + 1;
        };
        PublicInputs { columns, num_columns }
    }

    /// Create an empty PublicInputs with zero rows
    public fun empty(num_columns: u64): PublicInputs {
        let columns = vector::empty<vector<vector<u8>>>();
        let i = 0;
        while (i < num_columns) {
            vector::push_back(&mut columns, vector::empty<vector<u8>>());
            i = i + 1;
        };
        PublicInputs { columns, num_columns }
    }

    /// Create PublicInputs from serialized bytes
    public fun from_bytes(bytes: vector<vector<vector<u8>>>): PublicInputs {
        let num_columns = vector::length(&bytes);
        PublicInputs { columns: bytes, num_columns }
    }

    /// Create PublicInputs from a reference to serialized bytes
    public fun from_bytes_ref(bytes: &vector<vector<vector<u8>>>): PublicInputs {
        let num_columns = vector::length(bytes);
        PublicInputs { columns: *bytes, num_columns }
    }

    /// Return the raw column-major byte representation of the public inputs
    public fun to_bytes(pi: &PublicInputs): vector<vector<vector<u8>>> {
        pi.columns
    }

    /// Return the public inputs serialized as a flat byte array (column-major order)
    public fun to_bytes_flat(pi: &PublicInputs): vector<u8> {
        let bytes = vector::empty<u8>();
        let num_columns = pi.num_columns;
        let col = 0;
        while (col < num_columns) {
            let column = vector::borrow(&pi.columns, col);
            let row = 0;
            let len = vector::length(column);
            while (row < len) {
                let elem_bytes = *vector::borrow(column, row);
                vector::append(&mut bytes, elem_bytes);
                row = row + 1;
            };
            col = col + 1;
        };
        bytes
    }

    /// Return the public inputs BCS-encoded (column-major order)
    public fun to_bcs_bytes(pi: &PublicInputs): vector<u8> {
        bcs::to_bytes(&pi.columns)
    }

    /// Return the columns of the public inputs
    public fun columns(self: &PublicInputs): vector<vector<vector<u8>>> {
        self.columns
    }

    /// Return the number of rows in the public inputs
    public fun row_count(self: &PublicInputs): u64 {
        if (self.num_columns == 0) {
            0
        } else {
            vector::length(vector::borrow(&self.columns, 0))
        }
    }

    /// Validate that every stored element is exactly 32 bytes (one BN254 scalar field element).
    /// This is a lightweight structural check; it does not verify field membership.
    public fun validate(pi: &PublicInputs): bool {
        let col = 0;
        while (col < pi.num_columns) {
            let column = vector::borrow(&pi.columns, col);
            let row = 0;
            let len = vector::length(column);
            while (row < len) {
                if (vector::length(vector::borrow(column, row)) != 32) {
                    return false
                };
                row = row + 1;
            };
            col = col + 1;
        };
        true
    }

    /// Packs a list of 16-bit limbs into a BN254 scalar field element using base-2^16
    /// positional encoding, and returns the result as 32 little-endian bytes.
    ///
    /// Each limb must be in [0, 0xFFFF]. The maximum number of limbs is 15
    /// (15 × 16 = 240 bits < 254-bit field capacity), so the packed value never
    /// exceeds the field modulus and no reduction is required.
    fun pack_sub_index(limbs: &vector<u64>): vector<u8> {
        assert!(
            vector::length(limbs) <= (255 / (LIMB_BITS as u64)),
            1001
        );

        let value: u256 = 0;
        let multiplier: u256 = 1;
        let base: u256 = 1u256 << LIMB_BITS; // 65536

        let i = 0;
        let len = vector::length(limbs);
        while (i < len) {
            let limb = *vector::borrow(limbs, i);
            assert!(limb <= 0xFFFF, 1002);
            value = value + (limb as u256) * multiplier;
            multiplier = multiplier * base;
            i = i + 1;
        };
        bn254_serialize::u256_to_bn254_le_bytes(value)
    }

    fun push_internal(
        self: &mut PublicInputs,
        sub_index_limbs: vector<u64>,
        header: bool,
        word_lo: u128,
        word_hi: u128,
    ) {
        assert!(self.num_columns == VM_PUBLIC_INPUTS_COLUMN_COUNT, E_INVALID_COLUMN_COUNT);

        let scalars: vector<vector<u8>> = vector[
            pack_sub_index(&sub_index_limbs),
            if (header) { bn254_serialize::one() } else { bn254_serialize::zero() },
            bn254_serialize::u128_to_bn254_le_bytes(word_lo),
            bn254_serialize::u128_to_bn254_le_bytes(word_hi),
        ];

        let i = 0;
        while (i < self.num_columns) {
            let col = vector::borrow_mut(&mut self.columns, i);
            vector::push_back(col, *vector::borrow(&scalars, i));
            i = i + 1;
        }
    }

    /// Push a u8 value as a public input row (VM circuits only)
    public fun push_u8(self: &mut PublicInputs, v: u8) {
        push_internal(self, vector<u64>[0], false, (v as u128), 0);
    }

    /// Push a u16 value as a public input row (VM circuits only)
    public fun push_u16(self: &mut PublicInputs, v: u16) {
        push_internal(self, vector<u64>[0], false, (v as u128), 0);
    }

    /// Push a u32 value as a public input row (VM circuits only)
    public fun push_u32(self: &mut PublicInputs, v: u32) {
        push_internal(self, vector<u64>[0], false, (v as u128), 0);
    }

    /// Push a u64 value as a public input row (VM circuits only)
    public fun push_u64(self: &mut PublicInputs, v: u64) {
        push_internal(self, vector<u64>[0], false, (v as u128), 0);
    }

    /// Push a u128 value as a public input row (VM circuits only)
    public fun push_u128(self: &mut PublicInputs, v: u128) {
        push_internal(self, vector<u64>[0], false, v, 0);
    }

    /// Split a u256 into its low and high 128-bit halves (little-endian)
    fun u256_to_lo_hi(v: u256): (u128, u128) {
        let lo_mask: u256 = (1u256 << 128) - 1;
        let lo = ((v & lo_mask) as u128);
        let hi = ((v >> 128) as u128);
        (lo, hi)
    }

    /// Push a u256 value as a public input row (VM circuits only).
    /// The value is split into low and high 128-bit halves stored in separate columns.
    public fun push_u256(self: &mut PublicInputs, v: u256) {
        let (lo, hi) = u256_to_lo_hi(v);
        push_internal(self, vector<u64>[0], false, lo, hi);
    }

    /// Push a bool value as a public input row (VM circuits only)
    public fun push_bool(self: &mut PublicInputs, v: bool) {
        let val: u128 = if (v) { 1 } else { 0 };
        push_internal(self, vector<u64>[0], false, val, 0);
    }

    /// Return the number of columns used by the VM public input layout
    public fun get_vm_public_inputs_column_count(): u64 {
        VM_PUBLIC_INPUTS_COLUMN_COUNT
    }
}

#[test_only]
module halo2_common::serialized_public_inputs_tests {
    use std::vector;
    use halo2_common::serialized_public_inputs;
    use halo2_common::serialized_public_inputs::get_vm_public_inputs_column_count;
    use halo2_common::bn254_serialize;

    fun u256_to_lo_hi(v: u256): (u128, u128) {
        let lo_mask: u256 = (1u256 << 128) - 1;
        let lo = ((v & lo_mask) as u128);
        let hi = ((v >> 128) as u128);
        (lo, hi)
    }

    fun slice_vector(src: &vector<u8>, start: u64, end: u64): vector<u8> {
        let result = vector::empty<u8>();
        let i = start;
        while (i < end) {
            vector::push_back(&mut result, *vector::borrow(src, i));
            i = i + 1;
        };
        result
    }

    #[test]
    fun test_specific_values_correctly_encoded() {
        let pi = serialized_public_inputs::empty(get_vm_public_inputs_column_count());

        serialized_public_inputs::push_bool(&mut pi, true);        // row 0
        serialized_public_inputs::push_u8(&mut pi, 255u8);         // row 1
        serialized_public_inputs::push_u64(&mut pi, 123456789u64); // row 2
        serialized_public_inputs::push_u128(&mut pi, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFu128); // row 3
        serialized_public_inputs::push_u256(&mut pi, 0x1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEFu256); // row 4
        serialized_public_inputs::push_u256(&mut pi, (1u256 << 255)); // row 5
        serialized_public_inputs::push_bool(&mut pi, false);       // row 6

        let bytes = serialized_public_inputs::to_bytes_flat(&pi);
        let num_rows = 7;
        // 7 rows × 4 columns × 32 bytes per element
        assert!(vector::length(&bytes) == num_rows * 4 * 32, 1000);

        // Flat layout is column-major:
        //   col0_row0..col0_row6 | col1_row0..col1_row6 | col2_row0..col2_row6 | col3_row0..col3_row6

        let col_lo_base = 2 * (num_rows * 32); // word_lo is column 2
        let col_hi_base = 3 * (num_rows * 32); // word_hi is column 3

        // row 0: bool true → lo = 1, hi = 0
        let actual = slice_vector(&bytes, col_lo_base, col_lo_base + 32);
        assert!(actual == bn254_serialize::u128_to_bn254_le_bytes(1), 1001);

        // row 1: u8 255 → lo = 255, hi = 0
        let actual = slice_vector(&bytes, col_lo_base + 32, col_lo_base + 64);
        assert!(actual == bn254_serialize::u128_to_bn254_le_bytes(255), 1002);

        // row 2: u64 123456789 → lo = 123456789, hi = 0
        let actual = slice_vector(&bytes, col_lo_base + 2 * 32, col_lo_base + 3 * 32);
        assert!(actual == bn254_serialize::u128_to_bn254_le_bytes(123456789), 1003);

        // row 3: u128::MAX → lo = u128::MAX, hi = 0
        let actual_lo = slice_vector(&bytes, col_lo_base + 3 * 32, col_lo_base + 4 * 32);
        assert!(actual_lo == bn254_serialize::u128_to_bn254_le_bytes(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFu128), 1004);
        let actual_hi = slice_vector(&bytes, col_hi_base + 3 * 32, col_hi_base + 4 * 32);
        assert!(actual_hi == bn254_serialize::zero(), 1005);

        // row 4: large u256 split into lo / hi
        let large = 0x1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEFu256;
        let (lo, hi) = u256_to_lo_hi(large);
        let actual_lo = slice_vector(&bytes, col_lo_base + 4 * 32, col_lo_base + 5 * 32);
        let actual_hi = slice_vector(&bytes, col_hi_base + 4 * 32, col_hi_base + 5 * 32);
        assert!(actual_lo == bn254_serialize::u128_to_bn254_le_bytes(lo), 1006);
        assert!(actual_hi == bn254_serialize::u128_to_bn254_le_bytes(hi), 1007);

        // row 5: 2^255 → lo = 0, hi = 1 << 127
        let actual_lo = slice_vector(&bytes, col_lo_base + 5 * 32, col_lo_base + 6 * 32);
        let actual_hi = slice_vector(&bytes, col_hi_base + 5 * 32, col_hi_base + 6 * 32);
        assert!(actual_lo == bn254_serialize::zero(), 1008);
        assert!(actual_hi == bn254_serialize::u128_to_bn254_le_bytes(1u128 << 127), 1009);

        // row 6: bool false → lo = 0, hi = 0
        let actual = slice_vector(&bytes, col_lo_base + 6 * 32, col_lo_base + 7 * 32);
        assert!(actual == bn254_serialize::zero(), 1010);

        // column 0 (sub_index): all zero
        let row = 0;
        while (row < num_rows) {
            let offset = row * 32;
            let actual = slice_vector(&bytes, offset, offset + 32);
            assert!(actual == bn254_serialize::zero(), 1011 + row);
            row = row + 1;
        };

        // column 1 (header): all zero (header=false for all push_* helpers)
        let col1_base = num_rows * 32;
        let row = 0;
        while (row < num_rows) {
            let offset = col1_base + row * 32;
            let actual = slice_vector(&bytes, offset, offset + 32);
            assert!(actual == bn254_serialize::zero(), 1020 + row);
            row = row + 1;
        };
    }

    #[test]
    fun test_roundtrip_from_bytes() {
        let pi = serialized_public_inputs::empty(get_vm_public_inputs_column_count());

        serialized_public_inputs::push_bool(&mut pi, true);
        serialized_public_inputs::push_u8(&mut pi, 255u8);
        serialized_public_inputs::push_u64(&mut pi, 123456789u64);
        serialized_public_inputs::push_u128(&mut pi, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFu128);
        serialized_public_inputs::push_u256(&mut pi, 0x1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEFu256);
        serialized_public_inputs::push_u256(&mut pi, (1u256 << 255));
        serialized_public_inputs::push_bool(&mut pi, false);

        let original_bytes = serialized_public_inputs::to_bytes(&pi);
        let pi2 = serialized_public_inputs::from_bytes(original_bytes);

        assert!(serialized_public_inputs::row_count(&pi) == serialized_public_inputs::row_count(&pi2), 1000);
        assert!(serialized_public_inputs::to_bytes(&pi) == serialized_public_inputs::to_bytes(&pi2), 1001);
    }

    #[test]
    fun test_default_has_dummy_row() {
        let pi = serialized_public_inputs::default(get_vm_public_inputs_column_count());
        assert!(serialized_public_inputs::row_count(&pi) == 1, 2000);

        // Every element in the single dummy row must be the zero field element
        let cols = serialized_public_inputs::columns(&pi);
        let col = 0;
        while (col < vector::length(&cols)) {
            let column = vector::borrow(&cols, col);
            assert!(*vector::borrow(column, 0) == bn254_serialize::zero(), 2001 + col);
            col = col + 1;
        };
    }

    #[test]
    fun test_empty_has_zero_rows() {
        let pi = serialized_public_inputs::empty(get_vm_public_inputs_column_count());
        assert!(serialized_public_inputs::row_count(&pi) == 0, 3000);
    }

    #[test]
    fun test_validate_well_formed() {
        let pi = serialized_public_inputs::empty(get_vm_public_inputs_column_count());
        serialized_public_inputs::push_u64(&mut pi, 42u64);
        assert!(serialized_public_inputs::validate(&pi), 4000);
    }
}
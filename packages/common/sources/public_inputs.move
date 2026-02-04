/// Module for managing public inputs
module halo2_common::public_inputs {
    use std::vector;
    use std::option;
    use aptos_std::crypto_algebra::{Self, Element};
    use aptos_std::bn254_algebra::Fr;
    use halo2_common::bn254_utils::{fr_from_u128, deserialize_fr, serialize_fr};

    const E_INVALID_COLUMN_COUNT: u64 = 1000;

    /// constants for zkmove internal value representation
    const VM_PUBLIC_INPUTS_COLUMN_COUNT: u64 = 4;
    const SUB_INDEX_LIMBS: u64 = 8;
    const LIMB_BITS: u8 = 16;

    /// Struct representing public inputs
    struct PublicInputs<phantom F> has drop {
        columns: vector<vector<Element<F>>>,
        num_columns: u64,
    }

    /// Create a default PublicInputs with one dummy row of zeros
    public fun default<F>(num_columns: u64): PublicInputs<F> {
        let columns = vector::empty<vector<Element<F>>>();
        let i = 0;
        while (i < num_columns) {
            let col = vector::empty<Element<F>>();
            vector::push_back(&mut col, crypto_algebra::zero<F>());
            vector::push_back(&mut columns, col);
            i = i + 1;
        };
        PublicInputs { columns, num_columns }
    }

    /// Create an empty PublicInputs with zero rows
    public fun empty<F>(num_columns: u64): PublicInputs<F> {
        let columns = vector::empty<vector<Element<F>>>();
        let i = 0;
        while (i < num_columns) {
            vector::push_back(&mut columns, vector::empty<Element<F>>());
            i = i + 1;
        };
        PublicInputs { columns, num_columns }
    }

    /// Create PublicInputs from serialized bytes
    public fun from_bytes(bytes: &vector<vector<vector<u8>>>): PublicInputs<Fr> {
        let num_columns = vector::length(bytes);
        let columns = vector::map_ref(bytes, |column| {
            vector::map_ref<vector<u8>, Element<Fr>>(column, |instance| {
                option::destroy_some(deserialize_fr(instance))
            })
        });
        PublicInputs { columns, num_columns }
    }

    /// Serialize PublicInputs to bytes
    public fun to_bytes(pi: &PublicInputs<Fr>): vector<vector<vector<u8>>> {
        let num_columns = pi.num_columns;
        let bytes = vector::empty<vector<vector<u8>>>();
        let col = 0;
        while (col < num_columns) {
            let column = vector::borrow(&pi.columns, col);
            let col_bytes = vector::map_ref<Element<Fr>, vector<u8>>(column, |elem| {
                serialize_fr(elem)
            });
            vector::push_back(&mut bytes, col_bytes);
            col = col + 1;
        };
        bytes
    }

    /// Create PublicInputs from flat serialized bytes
    public fun to_bytes_flat(pi: &PublicInputs<Fr>): vector<u8> {
        let bytes = vector::empty<u8>();
        let col = 0;
        while (col < VM_PUBLIC_INPUTS_COLUMN_COUNT) {
            let column = vector::borrow(&pi.columns, col);
            let row = 0;
            let len = vector::length(column);
            while (row < len) {
                let elem = vector::borrow(column, row);
                let elem_bytes = serialize_fr(elem);
                vector::append(&mut bytes, elem_bytes);
                row = row + 1;
            };
            col = col + 1;
        };
        bytes
    }

    /// Get the columns of public inputs
    public fun columns<F>(self: &PublicInputs<F>): vector<vector<Element<F>>> {
        self.columns
    }

    /// Get the number of rows of public inputs
    public fun row_count<F>(self: &PublicInputs<F>): u64 {
        if (self.num_columns == 0) {
            0
        } else {
            vector::length(vector::borrow(&self.columns, 0))
        }
    }

    fun pack_sub_index<F>(limbs: &vector<u64>): Element<F> {
        assert!(
            vector::length(limbs) <= (255 / (LIMB_BITS as u64)),
            1001
        );

        let value = crypto_algebra::zero<F>();
        let multiplier = crypto_algebra::one<F>();
        let base = crypto_algebra::from_u64<F>(1u64 << LIMB_BITS);

        let i = 0;
        let len = vector::length(limbs);
        while (i < len) {
            let limb = *vector::borrow(limbs, i);
            assert!(limb <= 0xFFFF, 1002);

            let term = crypto_algebra::mul<F>(
                &crypto_algebra::from_u64<F>(limb),
                &multiplier
            );
            value = crypto_algebra::add<F>(&value, &term);
            multiplier = crypto_algebra::mul<F>(&multiplier, &base);
            i = i + 1;
        };
        value
    }

    fun push_internal<F>(
        self: &mut PublicInputs<F>,
        sub_index_limbs: vector<u64>,
        header: bool,
        word_lo: u128,
        word_hi: u128,
    ) {
        assert!(self.num_columns == VM_PUBLIC_INPUTS_COLUMN_COUNT, E_INVALID_COLUMN_COUNT);

        let sub_index_elem = pack_sub_index<F>(&sub_index_limbs);
        let header_elem = if (header) {
            crypto_algebra::from_u64<F>(1)
        } else {
            crypto_algebra::zero<F>()
        };
        let lo_elem = fr_from_u128<F>(word_lo);
        let hi_elem = fr_from_u128<F>(word_hi);

        let scalars: vector<Element<F>> = vector[
            sub_index_elem,
            header_elem,
            lo_elem,
            hi_elem,
        ];

        let i = 0;
        while (i < self.num_columns) {
            let col = vector::borrow_mut(&mut self.columns, i);
            vector::push_back(col, *vector::borrow(&scalars, i));
            i = i + 1;
        }
    }

    /// Push u8 value as public input, only used for vm circuits
    public fun push_u8<F>(self: &mut PublicInputs<F>, v: u8) {
        push_internal(self, vector<u64>[0], false, (v as u128), 0);
    }

    /// Push u16 value as public input, only used for vm circuits
    public fun push_u16<F>(self: &mut PublicInputs<F>, v: u16) {
        push_internal(self, vector<u64>[0], false, (v as u128), 0);
    }

    /// Push u32 value as public input, only used for vm circuits
    public fun push_u32<F>(self: &mut PublicInputs<F>, v: u32) {
        push_internal(self, vector<u64>[0], false, (v as u128), 0);
    }

    /// Push u64 value as public input, only used for vm circuits
    public fun push_u64<F>(self: &mut PublicInputs<F>, v: u64) {
        push_internal(self, vector<u64>[0], false, (v as u128), 0);
    }

    /// Push u128 value as public input, only used for vm circuits
    public fun push_u128<F>(self: &mut PublicInputs<F>, v: u128) {
        push_internal(self, vector<u64>[0], false, v, 0);
    }

    fun u256_to_lo_hi(v: u256): (u128, u128) {
        // Low 128 bits: mask with 2^128 - 1
        let lo_mask: u256 = (1u256 << 128) - 1;
        let lo = ((v & lo_mask) as u128);

        // High 128 bits: shift right 128 bits
        let hi = ((v >> 128) as u128);

        (lo, hi)
    }

    /// Push u256 value as public input, only used for vm circuits
    public fun push_u256<F>(self: &mut PublicInputs<F>, v: u256) {
        let (lo, hi) = u256_to_lo_hi(v);
        push_internal(self, vector<u64>[0], false, lo, hi);
    }

    /// Push bool value as public input, only used for vm circuits
    public fun push_bool<F>(self: &mut PublicInputs<F>, v: bool) {
        let val = if (v) { 1u128 } else { 0u128 };
        push_internal(self, vector<u64>[0], false, val, 0);
    }

    /// Push a vector of values as public inputs, only used for vm circuits
    public fun push_vector<F, T>(self: &mut PublicInputs<F>, _v: vector<T>) {
        // TODO: implement based on T type
        abort 1000;
    }

    /// Helper to get the constant from outside the module
    public fun get_vm_public_inputs_column_count(): u64 {
        VM_PUBLIC_INPUTS_COLUMN_COUNT
    }
}

#[test_only]
module halo2_common::public_inputs_tests {
    use std::vector;
    use halo2_common::public_inputs;
    use halo2_common::public_inputs::get_vm_public_inputs_column_count;
    use aptos_std::bn254_algebra::Fr;
    use halo2_common::bn254_utils::{fr_from_u128, serialize_fr};

    fun u256_to_lo_hi(v: u256): (u128, u128) {
        // Low 128 bits: mask with 2^128 - 1
        let lo_mask: u256 = (1u256 << 128) - 1;
        let lo = ((v & lo_mask) as u128);

        // High 128 bits: shift right 128 bits
        let hi = ((v >> 128) as u128);

        (lo, hi)
    }

    fun expected_fr_bytes_from_u64(value: u64): vector<u8> {
        let elem = fr_from_u128((value as u128));
        serialize_fr(&elem)
    }

    fun expected_fr_bytes_from_bool(v: bool): vector<u8> {
        let value = if (v) { 1u64 } else { 0u64 };
        expected_fr_bytes_from_u64(value)
    }

    fun slice_vector(src: &vector<u8>, start: u64, end: u64): vector<u8> {
        let result = vector::empty<u8>();
        let i = start;
        while (i < end) {
            let byte = *vector::borrow(src, i);
            vector::push_back(&mut result, byte);
            i = i + 1;
        };
        result
    }

    #[test]
    fun test_specific_values_correctly_encoded() {
        // Initialize with standard 4 columns
        let pi = public_inputs::empty<Fr>(get_vm_public_inputs_column_count());

        public_inputs::push_bool(&mut pi, true);        // row 0
        public_inputs::push_u8(&mut pi, 255u8);         // row 1
        public_inputs::push_u64(&mut pi, 123456789u64); // row 2
        public_inputs::push_u128(&mut pi, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFu128); // row 3
        public_inputs::push_u256(&mut pi, 0x1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEFu256); // row 4
        public_inputs::push_u256(&mut pi, (1u256 << 255)); // row 5
        public_inputs::push_bool(&mut pi, false);       // row 6

        let bytes = public_inputs::to_bytes_flat(&pi);
        let num_rows = 7;
        assert!(vector::length(&bytes) == num_rows * 4 * 32, 1000);  // 7 rows × 4 cols × 32 bytes

        // after serialization, the layout in bytes is column-major:
        // col0_row0 ... col0_row6, col1_row0 ... col1_row6,
        // col2_row0 ... col2_row6, col3_row0 ... col3_row6

        // word_lo column (col 2)
        let col_lo = 2;
        let col_lo_base = col_lo * (num_rows * 32);

        // word_hi column (col 3)
        let col_hi = 3;
        let col_hi_base = col_hi * (num_rows * 32);

        // row 0: true
        let offset = col_lo_base + 0 * 32;
        let actual = slice_vector(&bytes, offset, offset + 32);
        let expected = expected_fr_bytes_from_bool(true);
        assert!(actual == expected, 1001);

        // row 1: 255
        let offset = col_lo_base + 1 * 32;
        let actual = slice_vector(&bytes, offset, offset + 32);
        let expected = expected_fr_bytes_from_u64(255);
        assert!(actual == expected, 1002);

        // row 2: 123456789
        let offset = col_lo_base + 2 * 32;
        let actual = slice_vector(&bytes, offset, offset + 32);
        let expected = expected_fr_bytes_from_u64(123456789);
        assert!(actual == expected, 1003);

        // row 3: lo = u128::MAX, hi = 0
        let offset_lo = col_lo_base + 3 * 32;
        let actual_lo = slice_vector(&bytes, offset_lo, offset_lo + 32);
        let expected_lo = serialize_fr(&fr_from_u128(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFu128));
        assert!(actual_lo == expected_lo, 1004);

        let offset_hi = col_hi_base + 3 * 32;
        let actual_hi = slice_vector(&bytes, offset_hi, offset_hi + 32);
        let expected_hi = expected_fr_bytes_from_u64(0);
        assert!(actual_hi == expected_hi, 1005);

        // row 4: large u256
        let large_u256 = 0x1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEFu256;
        let (lo, hi) = u256_to_lo_hi(large_u256);
        let expected_lo = serialize_fr(&fr_from_u128(lo));
        let expected_hi = serialize_fr(&fr_from_u128(hi));

        let offset_lo = col_lo_base + 4 * 32;
        let actual_lo = slice_vector(&bytes, offset_lo, offset_lo + 32);
        assert!(actual_lo == expected_lo, 1006);

        let offset_hi = col_hi_base + 4 * 32;
        let actual_hi = slice_vector(&bytes, offset_hi, offset_hi + 32);
        assert!(actual_hi == expected_hi, 1007);

        // row 5: 2^255, lo = 0, hi = 1 << 127
        let offset_lo = col_lo_base + 5 * 32;
        let actual_lo = slice_vector(&bytes, offset_lo, offset_lo + 32);
        let expected_lo = expected_fr_bytes_from_u64(0);
        assert!(actual_lo == expected_lo, 1008);

        let offset_hi = col_hi_base + 5 * 32;
        let actual_hi = slice_vector(&bytes, offset_hi, offset_hi + 32);
        let expected_hi = serialize_fr(&fr_from_u128(1u128 << 127));
        assert!(actual_hi == expected_hi, 1009);

        // row 6: false
        let offset = col_lo_base + 6 * 32;
        let actual = slice_vector(&bytes, offset, offset + 32);
        let expected = expected_fr_bytes_from_bool(false);
        assert!(actual == expected, 1010);

        // column 0 (sub_index) all 0
        let col = 0;
        let col_offset_base = col * (num_rows * 32);
        let row = 0;
        while (row < num_rows) {
            let offset = col_offset_base + row * 32;
            let actual = slice_vector(&bytes, offset, offset + 32);
            let expected = expected_fr_bytes_from_u64(0);
            assert!(actual == expected, 1011 + row);
            row = row + 1;
        };

        // column 1 (header) all 0
        let col = 1;
        let col_offset_base = col * (num_rows * 32);
        let row = 0;
        while (row < num_rows) {
            let offset = col_offset_base + row * 32;
            let actual = slice_vector(&bytes, offset, offset + 32);
            let expected = expected_fr_bytes_from_u64(0);
            assert!(actual == expected, 1020 + row);
            row = row + 1;
        };
    }

    #[test]
    fun test_to_types_and_from_bytes() {
        // Initialize with standard 4 columns
        let pi = public_inputs::empty<Fr>(get_vm_public_inputs_column_count());

        public_inputs::push_bool(&mut pi, true);        // row 0
        public_inputs::push_u8(&mut pi, 255u8);         // row 1
        public_inputs::push_u64(&mut pi, 123456789u64); // row 2
        public_inputs::push_u128(&mut pi, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFu128); // row 3
        public_inputs::push_u256(
            &mut pi,
            0x1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEFu256
        ); // row 4
        public_inputs::push_u256(&mut pi, (1u256 << 255)); // row 5
        public_inputs::push_bool(&mut pi, false);       // row 6

        let bytes_original = public_inputs::to_bytes(&pi);
        let pi_reconstructed = public_inputs::from_bytes(&bytes_original);

        assert!(public_inputs::row_count(&pi) == public_inputs::row_count(&pi_reconstructed), 1000);

        let bytes_reconstructed = public_inputs::to_bytes(&pi_reconstructed);
        assert!(bytes_original == bytes_reconstructed, 1001);
    }

    #[test]
    fun test_default_has_dummy_row() {
        let pi = public_inputs::default<Fr>(get_vm_public_inputs_column_count());
        let rows = public_inputs::row_count(&pi);
        assert!(rows == 1, 2000);
    }

    #[test]
    fun test_empty_has_zero_rows() {
        let pi = public_inputs::empty<Fr>(get_vm_public_inputs_column_count());
        let rows = public_inputs::row_count(&pi);
        assert!(rows == 0, 3000);
    }
}
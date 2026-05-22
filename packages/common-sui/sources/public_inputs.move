// Copyright (c) zkMove Authors

/// Utilities for managing BN254 public inputs.
module halo2_common::public_inputs {
    use sui::bcs;
    use sui::bn254;
    use sui::group_ops::Element;
    use halo2_common::bn254_utils::{deserialize_fr, fr_from_u128, serialize_fr};

    const E_INVALID_COLUMN_COUNT: u64 = 1000;
    const E_TOO_MANY_SUB_INDEX_LIMBS: u64 = 1001;
    const E_INVALID_SUB_INDEX_LIMB: u64 = 1002;
    const E_PUSH_VECTOR_UNSUPPORTED: u64 = 1003;

    /// Number of public input columns used by zkMove VM circuits.
    const VM_PUBLIC_INPUTS_COLUMN_COUNT: u64 = 4;
    const LIMB_BITS: u8 = 16;

    /// Public inputs stored as BN254 scalar field elements in column-major form.
    public struct PublicInputs has drop {
        columns: vector<vector<Element<bn254::Scalar>>>,
        num_columns: u64,
    }

    /// Creates public inputs with one dummy zero row in each column.
    public fun default(num_columns: u64): PublicInputs {
        let mut columns = vector[];
        let mut i = 0;
        while (i < num_columns) {
            let mut col = vector[];
            vector::push_back(&mut col, bn254::scalar_zero());
            vector::push_back(&mut columns, col);
            i = i + 1;
        };
        PublicInputs { columns, num_columns }
    }

    /// Creates public inputs with zero rows.
    public fun empty(num_columns: u64): PublicInputs {
        let mut columns = vector[];
        let mut i = 0;
        while (i < num_columns) {
            vector::push_back(&mut columns, vector[]);
            i = i + 1;
        };
        PublicInputs { columns, num_columns }
    }

    /// Creates public inputs from serialized BN254 scalar bytes.
    public fun from_bytes(bytes: &vector<vector<vector<u8>>>): PublicInputs {
        let num_columns = bytes.length();
        let mut columns = vector[];
        let mut col = 0;
        while (col < num_columns) {
            let column_bytes = &bytes[col];
            let mut column = vector[];
            let mut row = 0;
            while (row < column_bytes.length()) {
                let instance = &column_bytes[row];
                vector::push_back(&mut column, option::destroy_some(deserialize_fr(instance)));
                row = row + 1;
            };
            vector::push_back(&mut columns, column);
            col = col + 1;
        };
        PublicInputs { columns, num_columns }
    }

    /// Serializes public inputs to BN254 scalar bytes in column-major form.
    public fun to_bytes(pi: &PublicInputs): vector<vector<vector<u8>>> {
        let mut bytes = vector[];
        let mut col = 0;
        while (col < pi.num_columns) {
            let column = &pi.columns[col];
            let mut col_bytes = vector[];
            let mut row = 0;
            while (row < column.length()) {
                vector::push_back(&mut col_bytes, serialize_fr(&column[row]));
                row = row + 1;
            };
            vector::push_back(&mut bytes, col_bytes);
            col = col + 1;
        };
        bytes
    }

    /// Serializes public inputs to flat BN254 scalar bytes in column-major form.
    public fun to_bytes_flat(pi: &PublicInputs): vector<u8> {
        let mut bytes = vector[];
        let mut col = 0;
        while (col < pi.num_columns) {
            let column = &pi.columns[col];
            let mut row = 0;
            while (row < column.length()) {
                let elem_bytes = serialize_fr(&column[row]);
                vector::append(&mut bytes, elem_bytes);
                row = row + 1;
            };
            col = col + 1;
        };
        bytes
    }

    /// Serializes public inputs to BCS bytes in column-major form.
    public fun to_bcs_bytes(pi: &PublicInputs): vector<u8> {
        bcs::to_bytes(&to_bytes(pi))
    }

    /// Returns public input columns.
    public fun columns(self: &PublicInputs): vector<vector<Element<bn254::Scalar>>> {
        self.columns
    }

    /// Returns the number of rows in public inputs.
    public fun row_count(self: &PublicInputs): u64 {
        if (self.num_columns == 0) {
            0
        } else {
            self.columns[0].length()
        }
    }

    fun pack_sub_index(limbs: &vector<u64>): Element<bn254::Scalar> {
        assert!(limbs.length() <= (255 / (LIMB_BITS as u64)), E_TOO_MANY_SUB_INDEX_LIMBS);

        let mut value = bn254::scalar_zero();
        let mut multiplier = bn254::scalar_one();
        let base = bn254::scalar_from_u64(1u64 << LIMB_BITS);

        let mut i = 0;
        while (i < limbs.length()) {
            let limb = limbs[i];
            assert!(limb <= 0xFFFF, E_INVALID_SUB_INDEX_LIMB);

            let term = bn254::scalar_mul(&bn254::scalar_from_u64(limb), &multiplier);
            value = bn254::scalar_add(&value, &term);
            multiplier = bn254::scalar_mul(&multiplier, &base);
            i = i + 1;
        };
        value
    }

    fun push_internal(
        self: &mut PublicInputs,
        sub_index_limbs: vector<u64>,
        header: bool,
        word_lo: u128,
        word_hi: u128,
    ) {
        assert!(self.num_columns == VM_PUBLIC_INPUTS_COLUMN_COUNT, E_INVALID_COLUMN_COUNT);

        let sub_index_elem = pack_sub_index(&sub_index_limbs);
        let header_elem = if (header) { bn254::scalar_one() } else { bn254::scalar_zero() };
        let lo_elem = fr_from_u128(word_lo);
        let hi_elem = fr_from_u128(word_hi);

        let scalars = vector[sub_index_elem, header_elem, lo_elem, hi_elem];
        let mut i = 0;
        while (i < self.num_columns) {
            vector::push_back(&mut self.columns[i], scalars[i]);
            i = i + 1;
        }
    }

    /// Pushes a `u8` value as a VM public input.
    public fun push_u8(self: &mut PublicInputs, v: u8) {
        push_internal(self, vector[0], false, (v as u128), 0);
    }

    /// Pushes a `u16` value as a VM public input.
    public fun push_u16(self: &mut PublicInputs, v: u16) {
        push_internal(self, vector[0], false, (v as u128), 0);
    }

    /// Pushes a `u32` value as a VM public input.
    public fun push_u32(self: &mut PublicInputs, v: u32) {
        push_internal(self, vector[0], false, (v as u128), 0);
    }

    /// Pushes a `u64` value as a VM public input.
    public fun push_u64(self: &mut PublicInputs, v: u64) {
        push_internal(self, vector[0], false, (v as u128), 0);
    }

    /// Pushes a `u128` value as a VM public input.
    public fun push_u128(self: &mut PublicInputs, v: u128) {
        push_internal(self, vector[0], false, v, 0);
    }

    /// Pushes a `u256` value as a VM public input.
    public fun push_u256(self: &mut PublicInputs, v: u256) {
        let (lo, hi) = u256_to_lo_hi(v);
        push_internal(self, vector[0], false, lo, hi);
    }

    /// Pushes a bool value as a VM public input.
    public fun push_bool(self: &mut PublicInputs, v: bool) {
        let val = if (v) { 1u128 } else { 0u128 };
        push_internal(self, vector[0], false, val, 0);
    }

    /// Vector public inputs are not supported yet.
    public fun push_vector<T>(_self: &mut PublicInputs, _v: vector<T>) {
        abort E_PUSH_VECTOR_UNSUPPORTED
    }

    /// Returns the VM public input column count.
    public fun get_vm_public_inputs_column_count(): u64 {
        VM_PUBLIC_INPUTS_COLUMN_COUNT
    }

    fun u256_to_lo_hi(v: u256): (u128, u128) {
        let lo_mask = (1u256 << 128) - 1;
        let lo = ((v & lo_mask) as u128);
        let hi = ((v >> 128) as u128);
        (lo, hi)
    }
}

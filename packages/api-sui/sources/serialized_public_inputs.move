module verifier_api::serialized_public_inputs;

use std::bcs;

const EInvalidColumnCount: u64 = 1000;
const ETooManySubIndexLimbs: u64 = 1001;
const EInvalidSubIndexLimb: u64 = 1002;

const VM_PUBLIC_INPUTS_COLUMN_COUNT: u64 = 4;
const LIMB_BITS: u8 = 16;
const SCALAR_BYTES: u64 = 32;

/// Public inputs encoded as column-major BN254 scalar bytes.
public struct PublicInputs has drop {
    columns: vector<vector<vector<u8>>>,
    num_columns: u64,
}

/// Create public inputs with one dummy row of zero scalars.
public fun default(num_columns: u64): PublicInputs {
    let zero = zero_scalar_bytes();
    let mut columns = vector[];
    let mut i = 0;
    while (i < num_columns) {
        let mut col = vector[];
        col.push_back(copy zero);
        columns.push_back(col);
        i = i + 1;
    };
    PublicInputs { columns, num_columns }
}

/// Create public inputs with zero rows.
public fun empty(num_columns: u64): PublicInputs {
    let mut columns = vector[];
    let mut i = 0;
    while (i < num_columns) {
        columns.push_back(vector[]);
        i = i + 1;
    };
    PublicInputs { columns, num_columns }
}

/// Create public inputs from column-major serialized scalar bytes.
public fun from_bytes(bytes: vector<vector<vector<u8>>>): PublicInputs {
    let num_columns = bytes.length();
    PublicInputs { columns: bytes, num_columns }
}

/// Create public inputs from a reference to column-major serialized scalar bytes.
public fun from_bytes_ref(bytes: &vector<vector<vector<u8>>>): PublicInputs {
    let num_columns = bytes.length();
    PublicInputs { columns: *bytes, num_columns }
}

/// Return the raw column-major byte representation.
public fun to_bytes(public_inputs: &PublicInputs): vector<vector<vector<u8>>> {
    public_inputs.columns
}

/// Return public inputs as a flat byte array in column-major order.
public fun to_bytes_flat(public_inputs: &PublicInputs): vector<u8> {
    let mut bytes = vector[];
    let mut col = 0;
    while (col < public_inputs.num_columns) {
        let column = &public_inputs.columns[col];
        let mut row = 0;
        while (row < column.length()) {
            bytes.append(*&column[row]);
            row = row + 1;
        };
        col = col + 1;
    };
    bytes
}

/// Return the public inputs BCS-encoded in column-major order.
public fun to_bcs_bytes(public_inputs: &PublicInputs): vector<u8> {
    bcs::to_bytes(&public_inputs.columns)
}

/// Return the columns of the public inputs.
public fun columns(public_inputs: &PublicInputs): vector<vector<vector<u8>>> {
    public_inputs.columns
}

/// Return the configured number of columns.
public fun num_columns(public_inputs: &PublicInputs): u64 {
    public_inputs.num_columns
}

/// Return the number of rows in the public inputs.
public fun row_count(public_inputs: &PublicInputs): u64 {
    if (public_inputs.num_columns == 0) {
        0
    } else {
        public_inputs.columns[0].length()
    }
}

/// Validate that every stored element is exactly one 32-byte scalar.
public fun validate(public_inputs: &PublicInputs): bool {
    if (public_inputs.columns.length() != public_inputs.num_columns) {
        return false
    };

    let mut col = 0;
    while (col < public_inputs.num_columns) {
        let column = &public_inputs.columns[col];
        let mut row = 0;
        while (row < column.length()) {
            if (column[row].length() != SCALAR_BYTES) {
                return false
            };
            row = row + 1;
        };
        col = col + 1;
    };
    true
}

/// Return the zero scalar field element as 32 little-endian bytes.
public fun zero_scalar_bytes(): vector<u8> {
    u256_to_bn254_le_bytes(0)
}

/// Return the one scalar field element as 32 little-endian bytes.
public fun one_scalar_bytes(): vector<u8> {
    u256_to_bn254_le_bytes(1)
}

/// Return a u128 as a BN254 scalar encoded in 32 little-endian bytes.
public fun u128_to_bn254_le_bytes(value: u128): vector<u8> {
    let mut bytes = vector[];
    let mut v = value;
    let mut i = 0;
    while (i < 16) {
        bytes.push_back((v & 0xff) as u8);
        v = v >> 8;
        i = i + 1;
    };
    while (i < SCALAR_BYTES) {
        bytes.push_back(0);
        i = i + 1;
    };
    bytes
}

/// Return a u256 as a BN254 scalar encoded in 32 little-endian bytes.
/// Callers must only pass values already known to be below the BN254 scalar modulus.
public fun u256_to_bn254_le_bytes(value: u256): vector<u8> {
    let mut bytes = vector[];
    let mut v = value;
    let mut i = 0;
    while (i < SCALAR_BYTES) {
        bytes.push_back((v & 0xff) as u8);
        v = v >> 8;
        i = i + 1;
    };
    bytes
}

/// Pack 16-bit sub-index limbs into one BN254 scalar encoded as 32 little-endian bytes.
public fun pack_sub_index(limbs: &vector<u64>): vector<u8> {
    assert!(limbs.length() <= (255 / (LIMB_BITS as u64)), ETooManySubIndexLimbs);

    let mut value: u256 = 0;
    let mut multiplier: u256 = 1;
    let base: u256 = 1u256 << LIMB_BITS;

    let mut i = 0;
    while (i < limbs.length()) {
        let limb = limbs[i];
        assert!(limb <= 0xffff, EInvalidSubIndexLimb);
        value = value + (limb as u256) * multiplier;
        multiplier = multiplier * base;
        i = i + 1;
    };
    u256_to_bn254_le_bytes(value)
}

fun push_internal(
    public_inputs: &mut PublicInputs,
    sub_index_limbs: vector<u64>,
    header: bool,
    word_lo: u128,
    word_hi: u128,
) {
    assert!(public_inputs.num_columns == VM_PUBLIC_INPUTS_COLUMN_COUNT, EInvalidColumnCount);

    let scalars = vector[
        pack_sub_index(&sub_index_limbs),
        if (header) { one_scalar_bytes() } else { zero_scalar_bytes() },
        u128_to_bn254_le_bytes(word_lo),
        u128_to_bn254_le_bytes(word_hi),
    ];

    let mut i = 0;
    while (i < public_inputs.num_columns) {
        public_inputs.columns[i].push_back(scalars[i]);
        i = i + 1;
    }
}

/// Push a u8 value as a VM public input row.
public fun push_u8(public_inputs: &mut PublicInputs, value: u8) {
    push_internal(public_inputs, vector[0], false, (value as u128), 0)
}

/// Push a u16 value as a VM public input row.
public fun push_u16(public_inputs: &mut PublicInputs, value: u16) {
    push_internal(public_inputs, vector[0], false, (value as u128), 0)
}

/// Push a u32 value as a VM public input row.
public fun push_u32(public_inputs: &mut PublicInputs, value: u32) {
    push_internal(public_inputs, vector[0], false, (value as u128), 0)
}

/// Push a u64 value as a VM public input row.
public fun push_u64(public_inputs: &mut PublicInputs, value: u64) {
    push_internal(public_inputs, vector[0], false, (value as u128), 0)
}

/// Push a u128 value as a VM public input row.
public fun push_u128(public_inputs: &mut PublicInputs, value: u128) {
    push_internal(public_inputs, vector[0], false, value, 0)
}

fun u256_to_lo_hi(value: u256): (u128, u128) {
    let lo_mask: u256 = (1u256 << 128) - 1;
    let lo = ((value & lo_mask) as u128);
    let hi = ((value >> 128) as u128);
    (lo, hi)
}

/// Push a u256 value as a VM public input row.
public fun push_u256(public_inputs: &mut PublicInputs, value: u256) {
    let (lo, hi) = u256_to_lo_hi(value);
    push_internal(public_inputs, vector[0], false, lo, hi)
}

/// Push a bool value as a VM public input row.
public fun push_bool(public_inputs: &mut PublicInputs, value: bool) {
    let scalar: u128 = if (value) { 1 } else { 0 };
    push_internal(public_inputs, vector[0], false, scalar, 0)
}

/// Return the number of columns used by the VM public input layout.
public fun get_vm_public_inputs_column_count(): u64 {
    VM_PUBLIC_INPUTS_COLUMN_COUNT
}

// Copyright (c) zkMove Authors

module halo2_common::column {
    /// Represents fixed, instance, and advice columns.
    ///
    /// Advice columns use type `1`. Fixed and instance columns use types `2`
    /// and `3`. Advice phases are stored separately in verifier protocol data.
    public struct Column has copy, drop, store {
        index: u32,
        column_type: u8,
    }

    const ADVICE: u8 = 1;
    const FIXED: u8 = 2;
    const INSTANCE: u8 = 3;

    public fun is_fixed(column: &Column): bool {
        column.column_type == FIXED
    }

    public fun is_instance(column: &Column): bool {
        column.column_type == INSTANCE
    }

    public fun is_advice(column: &Column): bool {
        column.column_type == ADVICE
    }

    public fun column_index(column: &Column): u32 {
        column.index
    }

    public fun column_type(column: &Column): u8 {
        column.column_type
    }

    public fun new(index: u32, column_type: u8): Column {
        Column { index, column_type }
    }
}

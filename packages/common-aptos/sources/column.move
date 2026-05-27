module halo2_common::column {
    /// use a u8 to represent fixed, instance, advice columns.
    /// advice columns have a fixed type=1, phases are stored separately in protocol.advice_column_phase.
    /// fixed and instance types are encoded from 2 and 3.
    struct Column has copy, drop, store {
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

    // Remove phase function, as it's no longer accurate.
    // Use protocol.advice_column_phase[column.index] instead for advice columns.

    public fun column_index(column: &Column): u32 {
        column.index
    }

    public fun column_type(column: &Column): u8 {
        column.column_type
    }

    public fun new(index: u32, column_type: u8): Column {
        Column {
            index,
            column_type
        }
    }
}
module halo2_verifier::column {
    /// use a u8 to represent fixed, instance, advice(phased) columns.
    /// advice columns only have 3 phases for now. we expect it shouldn't expand too many.
    /// and we encode fixed, instance type from 255.
    struct Column has copy, drop, store{
        index: u32,
        column_type: u8,
    }

    const FIXED: u8 = 255;
    const INSTANCE: u8 = 244;

    public fun is_fixed(column: &Column): bool {
        column.column_type == FIXED
    }
    public fun is_instance(column: &Column): bool {
        column.column_type == INSTANCE
    }
    public fun is_advice(column: &Column): bool {
        column.column_type < INSTANCE
    }
    public fun phase(column: &Column): u8 {
        column.column_type
    }

    public fun column_index(column: &Column): u32 {
        column.index
    }
}

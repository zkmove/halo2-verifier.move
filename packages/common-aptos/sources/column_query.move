module halo2_common::column_query {
    use halo2_common::column::Column;
    use halo2_common::i32::I32;

    struct ColumnQuery  has store, copy, drop {
        column: Column,
        rotation: I32,
    }

    public fun new(c: Column, rotation: I32): ColumnQuery {
        ColumnQuery {
            column:c,
            rotation
        }
    }

    public fun rotation(self: &ColumnQuery): &I32 {
        &self.rotation
    }
    public fun column(self: &ColumnQuery): &Column {
        &self.column
    }
}

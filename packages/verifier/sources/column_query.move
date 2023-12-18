module halo2_verifier::column_query {
    use halo2_verifier::column::Column;
    use halo2_verifier::i32::I32;

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

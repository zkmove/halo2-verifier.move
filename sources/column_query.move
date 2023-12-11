module halo2_verifier::column_query {
    use halo2_verifier::column::Column;
    use halo2_verifier::rotation::Rotation;

    struct ColumnQuery  has copy, drop {
        column: Column,
        rotation: Rotation,
    }

    public fun new(c: Column, rotation: Rotation): ColumnQuery {
        ColumnQuery {
            column:c,
            rotation
        }
    }

    public fun rotation(self: &ColumnQuery): &Rotation {
        &self.rotation
    }
    public fun column(self: &ColumnQuery): &Column {
        &self.column
    }
}

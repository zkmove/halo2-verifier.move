module halo2_verifier::base {
    const INVALID_BASE_FIELD_ELEMENT: u64 = 101;

    struct Base has copy, drop, store {
        repr: vector<u8>,
    }

    public fun from_repr(repr: vector<u8>): Base {
        assert!(check_encoding(repr), INVALID_BASE_FIELD_ELEMENT);
        Base {repr}
    }

    public fun to_repr(self: &Base): vector<u8> {
        self.repr
    }

    fun check_encoding(repr: vector<u8>): bool {
        abort 100
    }
}

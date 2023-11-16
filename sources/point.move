module halo2_verifier::point {
    use halo2_verifier::base::{Self, Base};
    const INVALID_BASE_FIELD_ELEMENT: u64 = 101;
    const INVALID_CURVE_AFFINE_COORDINATE: u64 = 103;

    struct G1Affine has copy, drop, store {
        x: Base,
        y: Base,
    }

    public fun default(): G1Affine {
        abort 100
    }

    public fun g1_from_xy(x: Base, y: Base): G1Affine {
        G1Affine { x, y }
    }

    public fun new_g1(x: vector<u8>, y: vector<u8>): G1Affine {
        assert!(check_encoding(x), INVALID_BASE_FIELD_ELEMENT);
        assert!(check_encoding(y), INVALID_BASE_FIELD_ELEMENT);
        assert!(check_on_curve(x,y), INVALID_CURVE_AFFINE_COORDINATE);
        G1Affine {
            x: base::from_repr(x),
            y: base::from_repr(y),
        }
    }

    fun check_encoding(repr: vector<u8>): bool {
        abort 100
    }

    fun check_on_curve(x: vector<u8>, y: vector<u8>): bool {
        abort 100
    }
}

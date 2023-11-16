module halo2_verifier::scalar {
    use halo2_verifier::bn254_algebra::{Fr, G1, G2};
    use aptos_std::crypto_algebra::{Self, Element};

    const INVALID_SCALAR_FIELD_ELEMENT: u64 = 102;

    struct Scalar has copy, drop, store {
        repr: vector<u8>,
    }

    public fun from_repr(repr: vector<u8>): Scalar {
        assert!(check_encoding(repr), INVALID_SCALAR_FIELD_ELEMENT);
        Scalar {repr}
    }

    public fun to_repr(self: &Scalar): vector<u8> {
        self.repr
    }

    fun check_encoding(repr: vector<u8>): bool {
        abort 100
    }

    fun from_element(e: Element<Fr>): Scalar {
        abort 100
    }

    public fun one(): Scalar {
        from_element(crypto_algebra::one<Fr>())
    }
    public fun zero(): Scalar {
        from_element(crypto_algebra::zero<Fr>())
    }
    public fun delta(): Scalar {
        abort 100
    }
    public fun invert(x: &Scalar): Scalar {
        abort 100
    }
    public fun square(x: &Scalar): Scalar {
        abort 100
    }
    public fun mul(a: &Scalar, b: &Scalar): Scalar {
        abort 100
    }
    public fun add(a: &Scalar, b: &Scalar): Scalar {
        abort 100
    }
    public fun sub(a: &Scalar, b: &Scalar): Scalar {
        abort 100
    }
    public fun neg(a: &Scalar): Scalar {
        abort 100
    }
    public fun pow(a: &Scalar, p: u64):Scalar {
        abort 100
    }
}

module halo2_verifier::scalar {
    use halo2_verifier::bn254_types::{Fr, FormatFrLsb};
    use aptos_std::crypto_algebra::{Self, Element};

    struct Scalar has copy, drop, store {
        repr: vector<u8>,
    }

    public fun from_repr(repr: vector<u8>): Scalar {
        Scalar {repr}
    }

    public fun to_repr(self: &Scalar): vector<u8> {
        self.repr
    }

    public fun default(): Scalar {
        Scalar {
            repr: vector[0u8,0u8,0u8,0u8,0u8,0u8,0u8,0u8,0u8,0u8,0u8,0u8,0u8,0u8,0u8,0u8,0u8,0u8,0u8,0u8,0u8,0u8,0u8,0u8,0u8,0u8,0u8,0u8,0u8,0u8,0u8,0u8],
        }
    }

    fun from_element(e: &Element<Fr>): Scalar {
        Scalar {
            repr: crypto_algebra::serialize<Fr, FormatFrLsb>(e),
        }
    }

    fun to_element(s: &Scalar): Element<Fr> {
        std::option::extract(&mut crypto_algebra::deserialize<Fr, FormatFrLsb>(&to_repr(s)))
    }

    public fun one(): Scalar {
        from_element(&crypto_algebra::one<Fr>())
    }
    public fun zero(): Scalar {
        from_element(&crypto_algebra::zero<Fr>())
    }
    public fun delta(): Scalar {
        abort 100
    }
    public fun invert(x: &Scalar): Scalar {
        let e = std::option::extract(&mut crypto_algebra::inv<Fr>(&to_element(x)));
        from_element(&e)
    }
    public fun square(x: &Scalar): Scalar {
        from_element(&crypto_algebra::sqr<Fr>(&to_element(x)))
    }
    public fun mul(a: &Scalar, b: &Scalar): Scalar {
        from_element(&crypto_algebra::mul<Fr>(&to_element(a),&to_element(b)))
    }
    public fun add(a: &Scalar, b: &Scalar): Scalar {
        from_element(&crypto_algebra::add<Fr>(&to_element(a),&to_element(b)))
    }
    public fun sub(a: &Scalar, b: &Scalar): Scalar {
        from_element(&crypto_algebra::sub<Fr>(&to_element(a),&to_element(b)))
    }
    public fun neg(a: &Scalar): Scalar {
        from_element(&crypto_algebra::neg<Fr>(&to_element(a)))
    }
    public fun pow(a: &Scalar, p: u64):Scalar {
        abort 100
    }
}

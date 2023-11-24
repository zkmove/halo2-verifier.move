module halo2_verifier::scalar {
    use aptos_std::crypto_algebra::{Self, Element};

    use halo2_verifier::bn254_types::{Fr, FormatFrLsb};

    struct Scalar has copy, drop{ e: Element<Fr> }

    public fun inner(self: &Scalar): &Element<Fr> {
        &self.e
    }
    public fun from_element(e: Element<Fr>): Scalar {
        Scalar {e}
    }

    public fun from_repr(repr: vector<u8>): Scalar {
        let e = std::option::extract(&mut crypto_algebra::deserialize<Fr, FormatFrLsb>(&repr));
        Scalar { e }
    }

    public fun to_repr(self: &Scalar): vector<u8> {
        crypto_algebra::serialize<Fr, FormatFrLsb>(&self.e)
    }

    public fun one(): Scalar {
        Scalar { e: crypto_algebra::one<Fr>() }
    }

    public fun zero(): Scalar {
        Scalar { e: crypto_algebra::zero<Fr>() }
    }

    public fun delta(): Scalar {
        abort 100
    }

    public fun invert(x: &Scalar): Scalar {
        Scalar { e: std::option::extract(&mut crypto_algebra::inv<Fr>(&x.e)) }
    }

    public fun square(x: &Scalar): Scalar {
        Scalar { e: crypto_algebra::sqr<Fr>(&x.e) }
    }

    public fun mul(a: &Scalar, b: &Scalar): Scalar {
        Scalar { e: crypto_algebra::mul<Fr>(&a.e, &b.e) }
    }

    public fun add(a: &Scalar, b: &Scalar): Scalar {
        Scalar { e: crypto_algebra::add<Fr>(&a.e, &b.e) }
    }

    public fun sub(a: &Scalar, b: &Scalar): Scalar {
        Scalar { e: crypto_algebra::sub<Fr>(&a.e, &b.e) }
    }

    public fun neg(a: &Scalar): Scalar {
        Scalar { e: crypto_algebra::neg<Fr>(&a.e) }
    }

    public fun pow<S>(self: &Element<S>, p: u64): Element<S> {
        abort 100
    }
}

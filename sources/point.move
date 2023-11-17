module halo2_verifier::point {
    use halo2_verifier::bn254_types::{G1, Fr, FormatG1Compr};
    use aptos_std::crypto_algebra::{Self, Element};
    use halo2_verifier::scalar::{Self, Scalar};

    struct G1Affine has copy, drop {e: Element<G1>}

    public fun default(): G1Affine {
        abort 100
    }

    public fun from_bytes(compressed: vector<u8>): G1Affine {
        let e = std::option::extract(&mut crypto_algebra::deserialize<G1, FormatG1Compr>(&compressed));
        G1Affine {e}
    }

    public fun to_bytes(self: &G1Affine): vector<u8> {
        crypto_algebra::serialize<G1, FormatG1Compr>(&self.e)
    }

    public fun one(): G1Affine {
        G1Affine { e: crypto_algebra::one<G1>() }
    }
    public fun zero(): G1Affine {
        G1Affine { e: crypto_algebra::zero<G1>() }
    }
    public fun order(): vector<u8> {
        crypto_algebra::order<G1>()
    }
    public fun scalar_mul(point: &G1Affine, scalar: &Scalar): G1Affine {
        G1Affine { e: crypto_algebra::scalar_mul<G1, Fr>(&point.e, &scalar::inner(scalar)) }
    }
    public fun multi_scalar_mul(point: &vector<G1Affine>, scalar: &vector<Scalar>): G1Affine {
        abort 100
    }
    public fun double(a: &G1Affine): G1Affine{
        G1Affine { e: crypto_algebra::double<G1>(&a.e) }
    }
    public fun add(a: &G1Affine, b: &G1Affine): G1Affine {
        G1Affine { e: crypto_algebra::add<G1>(&a.e, &b.e) }
    }
    public fun sub(a: &G1Affine, b: &G1Affine): G1Affine {
        G1Affine { e: crypto_algebra::sub<G1>(&a.e, &b.e) }
    }
    public fun neg(a: &G1Affine): G1Affine {
        G1Affine { e: crypto_algebra::neg<G1>(&a.e) }
    }
}

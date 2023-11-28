module halo2_verifier::arithmetic {
    use aptos_std::crypto_algebra::{Self, Element};

    use halo2_verifier::bn254_types::{Fr, FormatFrLsb};

    public fun default<G>(): Element<G> {
        abort 100
    }

    public fun from_bytes<G, Format>(compressed: vector<u8>): Element<G> {
        let e = std::option::extract(&mut crypto_algebra::deserialize<G, Format>(&compressed));
        e
    }

    public fun to_bytes<G, Format>(e: &Element<G>): vector<u8> {
        crypto_algebra::serialize<G, Format>(e)
    }

    public fun from_repr(repr: vector<u8>): Element<Fr> {
        let e = std::option::extract(&mut crypto_algebra::deserialize<Fr, FormatFrLsb>(&repr));
        e
    }

    public fun to_repr(e: &Element<Fr>): vector<u8> {
        crypto_algebra::serialize<Fr, FormatFrLsb>(e)
    }

    public fun one<G>(): Element<G> {
        crypto_algebra::one<G>()
    }

    public fun zero<G>(): Element<G> {
        crypto_algebra::zero<G>()
    }

    public fun delta<G>(): Element<G> {
        abort 100
    }

    public fun order<G>(): vector<u8> {
        crypto_algebra::order<G>()
    }

    public fun double<G>(a: &Element<G>): Element<G> {
        crypto_algebra::double<G>(a)
    }

    public fun add<G>(a: &Element<G>, b: &Element<G>): Element<G> {
        crypto_algebra::add<G>(a, b)
    }

    public fun sub<G>(a: &Element<G>, b: &Element<G>): Element<G> {
        crypto_algebra::sub<G>(a, b)
    }

    public fun mul<G>(a: &Element<G>, b: &Element<G>): Element<G> {
        crypto_algebra::mul<G>(a, b)
    }

    public fun neg<G>(a: &Element<G>): Element<G> {
        crypto_algebra::neg<G>(a)
    }

    public fun square<G>(a: &Element<G>): Element<G> {
        crypto_algebra::sqr<G>(a)
    }

    public fun pow<G>(_e: &Element<G>, _num: u64): Element<G> {
        abort 100
    }

    public fun invert(x: &Element<Fr>): Element<Fr> {
        std::option::extract(&mut crypto_algebra::inv<Fr>(x))
    }

    public fun scalar_mul<G>(point: &Element<G>, scalar: &Element<Fr>): Element<G> {
        crypto_algebra::scalar_mul<G, Fr>(point, scalar)
    }

    public fun multi_scalar_mul<G>(points: &vector<Element<G>>, scalars: &vector<Element<Fr>>): Element<G> {
        crypto_algebra::multi_scalar_mul<G, Fr>(points, scalars)
    }
}

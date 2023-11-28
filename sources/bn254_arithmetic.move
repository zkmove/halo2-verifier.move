module halo2_verifier::bn254_arithmetic {
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

    public fun delta<G>(): Element<G> {
        abort 100
    }

    public fun pow<G>(_e: &Element<G>, _num: u64): Element<G> {
        abort 100
    }

    public fun invert(x: &Element<Fr>): Element<Fr> {
        std::option::extract(&mut crypto_algebra::inv<Fr>(x))
    }
}

module halo2_verifier::point {
    use halo2_verifier::bn254_types::{G1, FormatG1Compr};
    use aptos_std::crypto_algebra::{Self, Element};

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
}

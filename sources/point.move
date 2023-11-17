module halo2_verifier::point {

    struct G1Affine has copy, drop, store {
        // compressed repr
        repr: vector<u8>,
    }

    public fun default(): G1Affine {
        G1Affine {
            repr: vector[0u8,0u8,0u8,0u8,0u8,0u8,0u8,0u8,0u8,0u8,0u8,0u8,0u8,0u8,0u8,0u8,0u8,0u8,0u8,0u8,0u8,0u8,0u8,0u8,0u8,0u8,0u8,0u8,0u8,0u8,0u8,0u8],
        }
    }

    public fun from_bytes(compressed: vector<u8>): G1Affine {
        G1Affine {
            repr: compressed,
        }
    }

    public fun to_bytes(self: &G1Affine): vector<u8> {
        self.repr
    }
}

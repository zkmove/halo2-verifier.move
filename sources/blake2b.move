module halo2_verifier::blake2b {
    use std::vector;
    use aptos_std::aptos_hash;

    struct Blake2b has copy, drop {
        data: vector<u8>
    }
    public fun new(): Blake2b {
        Blake2b {data: vector::empty()}
    }

    public fun update(self: &mut Blake2b, input: vector<u8>) {
        vector::append(&mut self.data, input)

    }

    public fun finalize(self: &mut Blake2b) : vector<u8> {
        aptos_hash::blake2b_256(self.data)
    }
}

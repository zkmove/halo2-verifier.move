module halo2_common::plain_blake2b {
    use std::vector;
    use aptos_std::aptos_hash;

    struct PlainBlake2b has copy, drop {
        data: vector<u8>
    }
    public fun new(): PlainBlake2b {
        PlainBlake2b {data: vector::empty()}
    }

    public fun update(self: &mut PlainBlake2b, input: vector<u8>) {
        vector::append(&mut self.data, input)

    }

    public fun finalize(self: &mut PlainBlake2b) : vector<u8> {
        aptos_hash::blake2b_256(self.data)
    }
}

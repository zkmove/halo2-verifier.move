module halo2_common::plain_keccak {
    use std::vector;
    use aptos_std::aptos_hash;

    struct PlainKeccak has copy, drop {
        data: vector<u8>
    }
    public fun new(): PlainKeccak {
        PlainKeccak {data: vector::empty()}
    }

    public fun update(self: &mut PlainKeccak, input: vector<u8>) {
        vector::append(&mut self.data, input)

    }

    public fun finalize(self: &mut PlainKeccak) : vector<u8> {
        aptos_hash::keccak256(self.data)
    }
}

// Copyright (c) zkMove Authors

module halo2_common::plain_keccak {
    use sui::hash;

    public struct PlainKeccak has copy, drop {
        data: vector<u8>,
    }

    public fun new(): PlainKeccak {
        PlainKeccak { data: vector[] }
    }

    public fun update(self: &mut PlainKeccak, input: vector<u8>) {
        vector::append(&mut self.data, input)
    }

    public fun finalize(self: &mut PlainKeccak): vector<u8> {
        hash::keccak256(&self.data)
    }
}

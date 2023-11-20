module halo2_verifier::keccak256 {
    use std::vector;
    use aptos_std::aptos_hash::keccak256;
    
    struct Keccak256 has copy, drop {
        repr: vector<u8>
    }

    public fun new(): Keccak256 {
        // Todo.
        Keccak256{repr: vector::empty()}
    }

    public fun update(self: &mut Keccak256, data: vector<u8>) {
        // Todo.
        let v = vector::empty();
        vector::append(&mut v, self.repr);
        vector::append(&mut v, data);
        self.repr = keccak256(v);
    }
    public fun finalize(self: &Keccak256): vector<u8> {
        // Todo.
        self.repr
    }
}
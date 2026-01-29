module verifier_api::vk_store {
    use std::signer;
    use std::error;
    use std::vector;
    use std::bcs;

    const E_NOT_FOUND: u64 = 1;
    const E_EMPTY_VK: u64 = 2;
    const E_EMPTY_CIRCUIT: u64 = 3;


    struct SerializedVK has key {
        vk_bytes: vector<u8>,
    }

    struct SerializedCircuitInfo has key {
        circuit_info_bytes: vector<u8>,
    }

    public entry fun publish_serialized_vk(
        owner: &signer,
        vk_bytes: vector<u8>,
    ) {
        assert!(!vector::is_empty(&vk_bytes), error::invalid_argument(E_EMPTY_VK));

        let addr = signer::address_of(owner);

        if (exists<SerializedVK>(addr)) {
            let res = borrow_global_mut<SerializedVK>(addr);
            res.vk_bytes = vk_bytes;
        } else {
            move_to(owner, SerializedVK { vk_bytes });
        }
    }

    public fun get_serialized_vk(addr: address): vector<u8> acquires SerializedVK {
        assert!(exists<SerializedVK>(addr), error::not_found(E_NOT_FOUND));
        *&borrow_global<SerializedVK>(addr).vk_bytes
    }

    public entry fun publish_serialized_circuit(
        owner: &signer,
        circuit_info_bytes: vector<u8>,
    ) {
        assert!(!vector::is_empty(&circuit_info_bytes), error::invalid_argument(E_EMPTY_CIRCUIT));
        let circuit_info = bcs::to_bytes(&circuit_info_bytes);

        let addr = signer::address_of(owner);

        if (exists<SerializedCircuitInfo>(addr)) {
            let res = borrow_global_mut<SerializedCircuitInfo>(addr);
            res.circuit_info_bytes = circuit_info;
        } else {
            move_to(owner, SerializedCircuitInfo { circuit_info_bytes });
        }
    }

    public fun get_serialized_circuit(addr: address): vector<u8> acquires SerializedCircuitInfo {
        assert!(exists<SerializedCircuitInfo>(addr), error::not_found(E_NOT_FOUND));
        *&borrow_global<SerializedCircuitInfo>(addr).circuit_info_bytes
    }
}
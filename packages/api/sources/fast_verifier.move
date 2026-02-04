module verifier_api::fast_verifier {
    use std::error;
    use std::option::Option;
    use std::signer;
    use std::vector;
    use std::bcs;
    use std::proofs::verify_proof;

    use verifier_api::param_store::get_serialized_params;

    const E_NOT_FOUND: u64 = 1;
    const E_EMPTY_VK: u64 = 2;
    const E_EMPTY_CIRCUIT: u64 = 3;
    const E_VERIFY_PROOF: u64 = 4;
    

    /// Struct to hold serialized verification key
    struct SerializedVK has key {
        vk_bytes: vector<u8>,
    }

    /// Struct to hold serialized circuit information, used by the native verifier
    struct SerializedCircuit has key {
        circuit_bytes: vector<u8>,
    }

    /// Publishes or updates the serialized verification key for the signer's address
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

    /// Retrieves the serialized verification key for a given address
    public fun get_serialized_vk(addr: address): vector<u8> acquires SerializedVK {
        assert!(exists<SerializedVK>(addr), error::not_found(E_NOT_FOUND));
        *&borrow_global<SerializedVK>(addr).vk_bytes
    }

    /// Publishes or updates the serialized circuit information for the signer's address
    public entry fun publish_serialized_circuit(
        owner: &signer,
        circuit_bytes: vector<u8>,
    ) {
        assert!(!vector::is_empty(&circuit_bytes), error::invalid_argument(E_EMPTY_CIRCUIT));
        let circuit_info = bcs::to_bytes(&circuit_bytes);

        let addr = signer::address_of(owner);

        if (exists<SerializedCircuit>(addr)) {
            let res = borrow_global_mut<SerializedCircuit>(addr);
            res.circuit_bytes = circuit_info;
        } else {
            move_to(owner, SerializedCircuit { circuit_bytes });
        }
    }

    /// Retrieves the serialized circuit information for a given address
    public fun get_serialized_circuit(addr: address): vector<u8> acquires SerializedCircuit {
        assert!(exists<SerializedCircuit>(addr), error::not_found(E_NOT_FOUND));
        *&borrow_global<SerializedCircuit>(addr).circuit_bytes
    }

    /// Verify proof with the native verifier, aborts on failure
    /// `param_address`: address where the params are published
    /// `vk_address`: address where the verification key is published
    /// `public_inputs`: public inputs as vector of bytes
    /// `proof`: proof as vector of bytes
    /// `kzg_variant`: 0 for gwc, 1 for shplonk
    /// `k`: parameter to downsize params, None to use the full params
    public entry fun verify(
        param_address: address,
        vk_address: address,
        public_inputs: vector<u8>,
        proof: vector<u8>,
        kzg_variant: u8,
        k: Option<u32>,
    ) {
        let params = get_serialized_params(param_address);
        let vk_bytes = get_serialized_vk(vk_address);
        let circuit_info = get_serialized_circuit(vk_address);

        assert!(verify_proof(params,  vk_bytes, circuit_info, public_inputs, proof, kzg_variant, k), error::aborted(E_VERIFY_PROOF));
    }

    #[test_only]
    public fun mock_verify(
        _param_address: address,
        _vk_address: address,
        _instances: vector<vector<vector<u8>>>,
        _proof: vector<u8>,
        _kzg_variant: u8,
    ) {
        // do nothing
    }
}

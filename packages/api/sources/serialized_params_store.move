module verifier_api::serialized_params_store {
    use std::error;
    use std::signer;
    use std::vector;

    const E_EMPTY_PARAMS: u64 = 1;
    const E_PARAMS_NOT_FOUND: u64 = 2;

    /// Store the serialized KZG params
    struct SerializedParams has key {
        params_bytes: vector<u8>,
    }

    /// Publish the serialized params bytes for the signer
    public entry fun publish_serialized_params(
        owner: &signer,
        params_bytes: vector<u8>,
    ) {
        assert!(!vector::is_empty(&params_bytes), error::invalid_argument(E_EMPTY_PARAMS));

        let addr = signer::address_of(owner);

        if (exists<SerializedParams>(addr)) {
            let res = borrow_global_mut<SerializedParams>(addr);
            res.params_bytes = params_bytes;
        } else {
            move_to(owner, SerializedParams { params_bytes });
        }
    }

    /// Retrieves the serialized params bytes for a given address
    public fun get_serialized_params(addr: address): vector<u8> acquires SerializedParams {
        assert!(exists<SerializedParams>(addr), error::not_found(E_PARAMS_NOT_FOUND));
        *&borrow_global<SerializedParams>(addr).params_bytes
    }
}

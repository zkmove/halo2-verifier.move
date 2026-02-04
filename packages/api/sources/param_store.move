module verifier_api::param_store {
    use std::option;
    use std::error;
    use std::signer;
    use std::vector;

    use halo2_common::bn254_utils;
    use halo2_common::params::{Self, Params};

    const INVALID_CURVE_ENCODING: u64 = 1;
    const E_EMPTY_PARAMS: u64 = 2;
    const E_PARAMS_NOT_FOUND: u64 = 3;

    /// params in stored form.
    /// because element cannot be stored, we have to serialize the elements to bytes to store them.
    /// Note: the serializaton should follow to arkworks serialzation.
    /// see this issue for more detail: https://github.com/privacy-scaling-explorations/halo2curves/issues/109
    struct StoredParams has key, store {
        g1: vector<u8>,
        g2: vector<u8>,
        s_g2: vector<u8>,
    }

    /// Store the serialized KZG params
    struct SerializedParams has key {
        params_bytes: vector<u8>,
    }

    /// the serializaton of curve point should follow to arkworks serialzation.
    /// see this issue for more detail: https://github.com/privacy-scaling-explorations/halo2curves/issues/109
    public entry fun create(sender: &signer, g1: vector<u8>, g2: vector<u8>, s_g2: vector<u8>) {
        assert!(option::is_some(&bn254_utils::deserialize_g1(&g1)), error::invalid_argument(INVALID_CURVE_ENCODING));
        assert!(option::is_some(&bn254_utils::deserialize_g2(&g2)), error::invalid_argument(INVALID_CURVE_ENCODING));
        assert!(option::is_some(&bn254_utils::deserialize_g2(&s_g2)), error::invalid_argument(INVALID_CURVE_ENCODING));

        move_to(sender, StoredParams {
            g1, g2, s_g2
        });
    }

    public fun get_params(addr: address): Params acquires StoredParams {
        to_params(borrow_global<StoredParams>(addr))
    }

    /// destory a params
    public fun destroy(params: StoredParams) {
        let StoredParams {g1: _, g2:_,s_g2:_} = params;
    }

    /// deserialize the stored param into `Params`
    public fun to_params(params: &StoredParams): Params {
        params::new(
            option::destroy_some(bn254_utils::deserialize_g1(&params.g1)),
            option::destroy_some(bn254_utils::deserialize_g2(&params.g2)),
            option::destroy_some(bn254_utils::deserialize_g2(&params.s_g2)),
        )
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

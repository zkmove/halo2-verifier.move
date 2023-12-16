module verifier_api::param_store {

    use halo2_verifier::params::Params;
    use std::option;
    use halo2_verifier::params;
    use halo2_verifier::bn254_utils;
    use std::error;


    const INVALID_CURVE_ENCODING: u64 = 1;
    /// params in stored form.
    /// because element cannot be stored, we have to serialize the elements to bytes to store them.
    /// Note: the serializaton should follow to arkworks serialzation.
    /// see this issue for more detail: https://github.com/privacy-scaling-explorations/halo2curves/issues/109
    struct StoredParams has key, store {
        g1: vector<u8>,
        g2: vector<u8>,
        s_g2: vector<u8>,
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

}

module verifier_api::verifier_api {
    use halo2_verifier::halo2_verifier::verify_single;
    use halo2_verifier::protocol::{Self, Protocol};

    use verifier_api::param_store::get_params;
    use std::error;

    const VERIFY_PROOF_FAILURE: u64 = 1;

    /// wrapper on protocol
    struct Circuit has key {
        protocol: Protocol,
    }

    /// Publish the circuit under sender account
    public entry fun publish_circuit(
        sender: &signer,
        general_info: vector<vector<u8>>,
        advice_queries: vector<vector<u8>>,
        instance_queries: vector<vector<u8>>,
        fixed_queries: vector<vector<u8>>,
        permutation_columns: vector<vector<u8>>,
        fields_pool: vector<vector<u8>>,
        gates: vector<vector<u8>>,
        lookups_input_exprs: vector<vector<u8>>,
        lookups_table_exprs: vector<vector<u8>>,
        shuffle_input_exprs: vector<vector<u8>>,
        shuffle_exprs: vector<vector<u8>>,
    ) {
        let proto = protocol::from_bytes(
            general_info, advice_queries, instance_queries, fixed_queries, permutation_columns,
            fields_pool, gates, lookups_input_exprs, lookups_table_exprs, shuffle_input_exprs,
            shuffle_exprs
        );
        move_to(sender, Circuit { protocol: proto });
    }

    public entry fun verify_proof_gwc(param_address: address,
                                  circuit_address: address,
                                  instances: vector<vector<vector<u8>>>,
                                  proof: vector<u8>) acquires Circuit {
        assert!(verify(param_address,circuit_address,instances,proof, 1), error::aborted(VERIFY_PROOF_FAILURE));
    }
    public entry fun verify_proof_shplonk(param_address: address,
                                      circuit_address: address,
                                      instances: vector<vector<vector<u8>>>,
                                      proof: vector<u8>) acquires Circuit {
        assert!(verify(param_address,circuit_address,instances,proof, 0), error::aborted(VERIFY_PROOF_FAILURE));
    }

    /// verify proof with given kzg variant, 0: shplonk, 1: gwc
    public entry fun verify_proof(
        param_address: address,
        circuit_address: address,
        instances: vector<vector<vector<u8>>>,
        proof: vector<u8>,
        kzg_variant: u8,
    ) acquires Circuit {
        assert!(verify(param_address,circuit_address,instances,proof, kzg_variant), error::aborted(VERIFY_PROOF_FAILURE));
    }

    /// verify a proof on the circuit in `circuit_address`
    public fun verify(
        param_address: address,
        circuit_address: address,
        instances: vector<vector<vector<u8>>>,
        proof: vector<u8>,
        kzg_variant: u8,
    ): bool acquires Circuit {
        let params = get_params(param_address);
        let circuit = borrow_global<Circuit>(circuit_address);
        let protocol = &circuit.protocol;
        verify_single(&params, protocol, instances, proof, kzg_variant)
    }

    /// destory a circuit
    public fun destroy(circuit: Circuit) {
        let Circuit { protocol: _ } = circuit;
    }
}

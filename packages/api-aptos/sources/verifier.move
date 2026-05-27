module verifier_api::verifier {
    use std::error;
    use aptos_std::bn254_algebra::Fr;

    use verifier_api::params_store::get_params;
    use halo2_common::public_inputs::PublicInputs;
    use halo2_verifier::halo2_verifier::{verify_single, verify_single_proof};
    use halo2_verifier::protocol::{Self, Protocol};
    
    const E_VERIFY_PROOF: u64 = 4;

    /// Struct to hold circuit information
    struct Circuit has key {
        protocol: Protocol,
    }

    /// Publishes the circuit for the signer's address
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

    /// destory a circuit
    public fun destroy(circuit: Circuit) {
        let Circuit { protocol: _ } = circuit;
    }
    
    /// Verify proof with move verifier, aborts on failure
    ///
    /// `params_address`: address where the params are published
    /// `circuit_address`: address where the circuit is published
    /// `public_inputs`: public inputs as vector of vector of bytes
    /// `proof`: proof as bytes
    /// `kzg_variant`: 0 for gwc, 1 for shplonk
    public entry fun verify(
        params_address: address,
        circuit_address: address,
        public_inputs: vector<vector<vector<u8>>>,
        proof: vector<u8>,
        kzg_variant: u8,
    ) acquires Circuit {
        let params = get_params(params_address);
        let circuit = borrow_global<Circuit>(circuit_address);
        let protocol = &circuit.protocol;
        assert!(verify_single(&params, protocol, public_inputs, proof, kzg_variant), error::aborted(E_VERIFY_PROOF));
    }

    /// Vefify proof with move verifier, different from `verify`,
    /// this function is not entry function, takes `PublicInputs` as input
    /// and returns `bool` instead of aborting on failure
    public fun verify_proof(
        params_address: address,
        circuit_address: address,
        public_inputs: PublicInputs<Fr>,
        proof: vector<u8>,
        kzg_variant: u8,
    ): bool acquires Circuit {
        let params = get_params(params_address);
        let circuit = borrow_global<Circuit>(circuit_address);
        let protocol = &circuit.protocol;
        verify_single_proof(&params, protocol, public_inputs, proof, kzg_variant)
    }

    #[test_only]
    public fun mock_verify_proof(
        _params_address: address,
        _circuit_address: address,
        _public_inputs: PublicInputs<Fr>,
        _proof: vector<u8>,
        _kzg_variant: u8,
    ): bool {
        true
    }
}
